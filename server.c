#include <stdio.h>
#include <string.h>
#include <unistd.h> 
#include <fcntl.h>
#include <arpa/inet.h>
#include <openssl/ssl.h> // does NOT give access to SSL_CONNECTION
#include <openssl/err.h>
#include <openssl/rand.h>
#include "openssl-3.5-source/ssl/ssl_local.h" //gives access to SSL_CONNECTION
#include <pthread.h> 
#include <sys/select.h> 

#define SSL_CONNECTION_FROM_SSL(ssl) ((SSL_CONNECTION *)(ssl)) // for access in client_hello_cb
#define BLOCK_SIZE 32 

int grease_ascii;
const unsigned char *session_data;
int fd;
unsigned char session_id_fixed[BLOCK_SIZE] = {0}; //extract in cb and print in main
unsigned char server_random[BLOCK_SIZE];
int has_custom_random = 0;
pthread_mutex_t random_lock = PTHREAD_MUTEX_INITIALIZER; 

//log fields from clientHello
//and handle server_random reading and insertion
int client_hello_cb(SSL *s, int *al, void *arg) {
    int high_nibble;
    int low_nibble;
    const unsigned char *data;
    size_t len;

    //grease high nibble
    len = SSL_client_hello_get0_ciphers(s, &data);
    if (len > 0 && data != NULL) {
        int first_cipher = (data[0] << 8) | data[1];
        //printf("[+] grease client ciphersuite: %04X\n", first_cipher);
        high_nibble = (first_cipher >> 12) & 0xF;
    }

    //grease low nibble
    if (SSL_client_hello_get0_ext(s, TLSEXT_TYPE_supported_groups, &data, &len)) {
        int first_supported_group = (data[2] << 8) | data[3]; 
        //printf("[+] grease client supported_groups: %04X\n", first_supported_group);
        low_nibble = (first_supported_group >>12) & 0xF;
    }

    grease_ascii = (high_nibble << 4) | low_nibble;
    // printf("[+] grease ascii: %c\n", (char)grease_ascii);
    printf("%c", (char)grease_ascii);

    len = SSL_client_hello_get0_session_id(s, &session_data);
    if (len > 0 && session_data != NULL) {
        memcpy(session_id_fixed, session_data, len);
    }

    /*begin custom server random block*/
    SSL_CONNECTION *conn = SSL_CONNECTION_FROM_SSL(s);
    if (conn == NULL) {
        fprintf(stderr, "[-] failed to extract SSL_CONNECTION from SSL object\n");
        return SSL_CLIENT_HELLO_ERROR;
    }
    unsigned char custom[SSL3_RANDOM_SIZE];

    pthread_mutex_lock(&random_lock);
    if (has_custom_random) {
        memcpy(custom, server_random, BLOCK_SIZE); //use custom
        has_custom_random = 0; //reset to default after use
    } else {
        memset(custom, 0xFD, 16);
        if (RAND_bytes(custom + 16, 16) <= 0){
            fprintf(stderr, "[-] RAND_bytes failed in client_hello_cb\n");
            *al = SSL_AD_INTERNAL_ERROR;
            return SSL_CLIENT_HELLO_ERROR;
        }
    }
    pthread_mutex_unlock(&random_lock);

    if (!SSL_set_server_random(s, custom, SSL3_RANDOM_SIZE)) {
        fprintf(stderr, "[-] SSL_set_server_random failed in client_hello_cb\n");
        *al = SSL_AD_INTERNAL_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }
    /*end custom server random block*/
    return SSL_CLIENT_HELLO_SUCCESS;
}

//read a command to be passed as custom random
void* stdin_random_reader(void* arg){
    unsigned char input[BLOCK_SIZE];
    while (1) {
        fd_set read_fds;
        struct timeval timeout;
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int ret = select(STDIN_FILENO + 1, &read_fds, NULL, NULL, &timeout);
        if(ret > 0 && FD_ISSET(STDIN_FILENO, &read_fds)) {
            char line[100];
            if(fgets(line, sizeof(line), stdin) != NULL) {
                size_t len = strlen(line);
                if(len > 0 && line[len-1] == '\n') {
                    line[len-1] = '\0';
                    len--;
                }

                if(len == 0) {
                    printf("[stdin] empty input ignored\n");
                    continue;
                }

                if(len > BLOCK_SIZE) {
                    printf("[stdin] input too long (%zu bytes), max is 32 bytes\n", len);
                    continue;
                }

                memset(input, 0x00, BLOCK_SIZE);
                memcpy(input, line, len);

                //lock before updating the server_random
                pthread_mutex_lock(&random_lock);
                memcpy(server_random, input, BLOCK_SIZE);
                has_custom_random = 1; // mark custom random now set
                pthread_mutex_unlock(&random_lock);
                printf("[stdin] custom server_random set\n");
            }
        }
    }
    return NULL;
}

int main() {
    int port = 8787;
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_size;
    char buffer[1];

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
    	perror("[-] error creating ssl context\n");
	    ERR_print_errors_fp(stderr);
	    exit(EXIT_FAILURE);
    }
    
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET); //dont use session tickets for sess resumption

    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0 || SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
    	ERR_print_errors_fp(stderr);
	    exit(EXIT_FAILURE);
    }

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("[-] socket error\n");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY; 

    if(bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("[-] bind error\n");
        close(server_sock);
        exit(1);
    }

    if (listen(server_sock, 5) < 0) {
        perror("[-] listening error\n");
        close(server_sock);
        exit(1);
    }

    fd = open("output.file", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("[-] file opening grease error");
        return 1;
    }

    //debug version
    //printf("[+] openSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));

    // for server_random from stdin
    pthread_t stdin_thread;
    pthread_create(&stdin_thread, NULL, stdin_random_reader, NULL);
    printf("[+] enter a < 32 bytes server_random:\n"); //one-time message

    while (1){
    	addr_size = sizeof(client_addr);
    	client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addr_size);
    	if (client_sock < 0) {
        	perror("[-] client accept error\n");
    	}
	
        SSL *ssl = SSL_new(ctx);
        SSL_CTX_set_client_hello_cb(ctx, client_hello_cb, NULL);
        SSL_set_fd(ssl, client_sock);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_sock);
            continue;
        }

        if (write(fd, &grease_ascii, 1) != 1) {
            perror("[-] file writing grease error");
            close(fd);
            return 1;
        }

        //log client_random 
        unsigned char client_random[SSL3_RANDOM_SIZE];
        SSL_get_client_random(ssl, client_random, sizeof(client_random));
        for (int i = 0; i < SSL3_RANDOM_SIZE; i++){
            printf("%c", client_random[i]);
            if (write(fd, &client_random[i], 1) != 1) {
                perror("[-] file writing client_random error");
                close(fd);
                return 1;
            }
        }

        // log session_id
        printf("%.32s", session_id_fixed);

        if (write(fd, &session_id_fixed, 32) != 32) {
            perror("[-] file writing session_id error");
            close(fd);
            return 1;
        } 

        int byteReceived = SSL_read(ssl, buffer, sizeof(buffer));
        if( byteReceived <= 0) {
            int err = SSL_get_error(ssl, byteReceived);
                if (err == SSL_ERROR_ZERO_RETURN) {
                    printf("[-] connection closed by the client\n");
                } else if (err == SSL_ERROR_WANT_READ) {
                    printf("[-] SSL_read is waiting for data\n");
                } else {
                    printf("[-] SSL_read failed with error code: %d\n", err);
                }
                break; 
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sock);
    }
    close(server_sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
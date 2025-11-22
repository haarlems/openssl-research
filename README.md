This is a personal research project, <br> not to be used outside of test environments.
==============================

The `OpenSSL_1_1_1-stable-research-exfil` branch was patched to allow a client to exfil data via GREASE (RFC 8701), random and session_id in clientHello. <br> 
`client.c` added to branch.<br>
The `openssl-3.5-research` branch was patched to allow a server to send commands to a client via random in serverHello. <br> 
`server.c` added to branch.<br>
A client linked with 1.1.1 and a server linked with 3.5 can communicate via the CH-SH.<br>
A low throughput, noisy, conspicuous TLS C2 channel is achieved. <br>
<br>
This was developed for research purposes only.<br>
I do not condone its usage in any environments where you do not have explicit permission to operate.<br>
<br>
Blogpost: to come<br>
<br>
This was presented at DefCamp 2025.<br>
Slides: to come<br>

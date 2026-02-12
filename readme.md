# TLS Subliminal Channels
This is a demonstration of using subliminal channels in EdDSA signatures to covertly exchange data over TLS handshakes. It works by patching the WolfSSL library to override nonce generation in the Ed25519 algorithm, and capturing the CertificateVerify messages exchanged during the TLS handshake. The EdDSA signatures in the CertificateVerify messages contain the subliminal data, which is used for a simple C2 protocol that executes commands on the client and sends the response back to the server.

This project was built on x86-64 linux with gcc, using WolfSSL 5.8.4.

For a full overview of this project, [see the write-up on my website here](https://www.johnmathot.com/posts/Using-Subliminal-Channels-in-TLS-Handshakes/).

# Build Instructions
1. `git clone https://github.com/cattl3ya/tls-subliminal-channel.git`
2. `git clone https://github.com/wolfSSL/wolfssl.git`
3. Copy the files from `./tls-subliminal-channel/wolfssl-5.8.4/` to `./wolfssl-5.8.4/` to overwrite ed25519.c, ed25519.h, tls13.c, and libwolfssl_sources.h
4. Build WolfSSL with the options `./configure --disable-shared --enable-opensslall --enable-ed25519 --enable-certgen --enable-opensslextra --enable-savecert --enable-keylog-export` and build with `make`
5. Either edit the `WOLFSSL_LIB = ./wolfssl-5.8.4/lib/libwolfssl.a` in the makefile to point to the location of your patched WolfSSL library, or copy the patched library into the expected directory with `mkdir ./tls-subliminal-channel/wolfssl-5.8.4/lib && cp ./wolfssl-5.8.4/src/.libs/libwolfssl.a ./tls-subliminal-channel/wolfssl-5.8.4/lib`
6. Run `make certs` to generate the certificates
7. Run `make` to compile the client and server
8. If you want to be able to decrypt the traffic, set `export SSLKEYLOGFILE=./ssl_key_log.txt` in your terminal
9. Start the server and client programs

# Usage
## Server
Run `./https_server` to start the server on localhost:8443. You'll be prompted to pick which subliminal channel you want to use. After choosing, commands are read from stdin, sent to the client, and the response printed to stdout. Ctrl-C quits.
## Client
Run `./https_client` to start the client. After choosing which subliminal channel to use, the client will start sending requests to the server. Commands received from the server are executed with `popen()`. The client will constantly send requests and print output to stdout. The program will stop on a failed connection or you can use Ctrl-C to quit.

# License and Contact
This project contains code from the WolfSSL library, licensed under GPL-3.0.
My code and modifications are released under the same license.

Contact information at https://www.johnmathot.com


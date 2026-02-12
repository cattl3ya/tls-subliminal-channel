# TLS Subliminal Channels
This is a demonstration of using subliminal channels in EdDSA signatures to covertly exchange data over TLS handshakes. It works by patching the WolfSSL library to override nonce generation in the Ed25519 algorithm, and capturing the CertificateVerify messages exchanged during the TLS handshake. The EdDSA signatures in the CertificateVerify messages contain the subliminal data, which is used for a simple C2 protocol that executes commands on the client and sends the response back to the server. For a full overview of this project, go to (link). 

# Build Instructions
1. Copy this repo: `git clone `
2. `git clone https://github.com/wolfSSL/wolfssl.git`
3. Copy the files from `./tls-subliminal-channel/wolfssl-5.8.4` to `./wolfssl-5.8.4` to overwrite ed25519.c, ed25519.h, tls13.c, and libwolfssl_sources.h
4. Build `wolfssl-5.8.4` with the options `./configure --disable-shared --enable-opensslall --enable-ed25519 --enable-certgen --enable-opensslextra --enable-savecert --enable-keylog-export` and `make`
5. Either copy your compiled library into  `cp ./wolfssl-5.8.4/src/.libs/libwolfssl.a ./tls-subliminal-channel/wolfssl-5.8.4/lib` or edit the `WOLFSSL_LIB = ./wolfssl-5.8.4/lib/libwolfssl.a` in the makefile.
6. Run `make certs` to generate the certificates
7. Run `make` to compile the client and server
8. If you want to be able to decrypt the traffic, remember to set `export SSLKEYLOGFILE=./ssl_key_log.txt`
9. Start the server and client programs.

# Usage
## Server
Run `./https_server` to start the server on localhost:8443. You'll be prompted to pick which subliminal channel you want to use. After choosing, commands are read from stdin, sent to the client, and the response printed to stdout. Ctrl-C quits.
## Client
Run `./https_client` to start the client. After choosing which subliminal channel to use, the client will start sending requests to the server. Commands received from the server are executed with `popen()`. The client will constantly send requests and print output to stdout. The program will quit on a failed connection or use Ctrl-C to quit.

# License and Contact
This project contains code from the WolfSSL library, licensed under GPL-3.0
My code and modifications are released under the same license
Contact information at https://www.johnmathot.com


# Subliminal Channels in TLS Handshakes
You can hide data within digital signatures by using something called a *subliminal channel*. The resulting signature will be valid and indistinguishable from a signature that does not contain subliminal data.

This project is a demonstration of using the subliminal channel in EdDSA signatures to secretly exchange data during a TLS 1.3 handshake. Unlike other methods of hiding data within a TLS handshake, it doesn't require altering any messages or values in a way that could be detected. All of the information is contained inside the signature of the `CertificateVerify` message.

It works by patching the WolfSSL library to override nonce generation in the Ed25519 algorithm, and capturing the CertificateVerify messages exchanged during the TLS handshake. The subliminal channel is used for a simple C2 protocol that executes commands on the client and sends the response back to the server.

![](https://www.johnmathot.com/assets/img/broadband_c2.png)

This project was built on x86-64 linux with gcc, using WolfSSL 5.8.4.

For a full overview of this project and the details behind its implementation, [see the write-up on my website here](https://www.johnmathot.com/posts/Using-Subliminal-Channels-in-TLS-Handshakes/).

# Build Instructions
1. `git clone https://github.com/cattl3ya/tls-subliminal-channel.git`
2. Get WolfSSL 5.8.4: `curl -LO https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.8.4-stable.zip` and `unzip v5.8.4-stable.zip`
3. Copy the files from `./tls-subliminal-channel/wolfssl-5.8.4/` to `./wolfssl-5.8.4-stable/` to overwrite ed25519.c, ed25519.h, tls13.c, and libwolfssl_sources.h: `cp -rv ./tls-subliminal-channel/wolfssl-5.8.4/* ./wolfssl-5.8.4-stable`
4. Build WolfSSL: `cd ./wolfssl-5.8.4-stable`, `./autogen.sh`, `./configure --disable-shared --enable-opensslall --enable-ed25519 --enable-certgen --enable-opensslextra --enable-savecert --enable-keylog-export` and build with `make`. DO NOT INSTALL the compiled library, just leave it alone and it will be statically linked when you build the client and server.
5. `cd ../tls-subliminal-channel`
6. Run `make` to compile the client and server
7. Run `make certs` to generate the certificates
8. If you want to be able to decrypt the traffic, set `export SSLKEYLOGFILE=./ssl_key_log.txt` in your terminal
9. Using tmux or another terminal window, start the server first with `./https_server`, and then start the client with `./https_client`

# Usage
## Server
Running `./https_server` will start the server on localhost:8443. You'll be prompted to pick which subliminal channel you want to use: narrowband or broadband. After choosing, commands are read from stdin, sent to the client, and the response printed to stdout. Ctrl-C quits.
## Client
Running `./https_client` will start the client. After choosing which subliminal channel to use, the client will start sending requests to the server. Commands received from the server are executed with `popen()`. The client will constantly send requests and print output to stdout. The program will stop on a failed connection or you can use Ctrl-C to quit.

# License and Contact
This project contains code from the WolfSSL library, licensed under GPL-3.0.
My code and modifications are released under the same license.

Contact information at https://www.johnmathot.com


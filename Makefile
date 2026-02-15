# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -I. -I../wolfssl-5.8.4-stable
WOLFSSL_LIB = ../wolfssl-5.8.4-stable/src/.libs/libwolfssl.a
LDFLAGS = $(WOLFSSL_LIB) -lm -lpthread

# Targets
SERVER = https_server
CLIENT = https_client

# Certificate files
CERT_DIR = certs
CERTS = $(CERT_DIR)/ca-cert.pem $(CERT_DIR)/server-cert.pem $(CERT_DIR)/client-cert.pem

.PHONY: all clean clean-all certs

# Default target
all: $(SERVER) $(CLIENT)

# Build server
$(SERVER): https_server.c
	$(CC) $(CFLAGS) -o $(SERVER) https_server.c $(LDFLAGS)
	@echo "Server built successfully"

# Build client
$(CLIENT): https_client.c
	$(CC) $(CFLAGS) -o $(CLIENT) https_client.c $(LDFLAGS)
	@echo "Client built successfully"

# Generate certificates
certs: generate_certs.sh
	@if [ ! -d "$(CERT_DIR)" ] || [ ! -f "$(CERT_DIR)/ca-cert.pem" ]; then \
		echo "Generating certificates..."; \
		./generate_certs.sh; \
	else \
		echo "Certificates already exist. Use 'make clean-certs' to regenerate."; \
	fi

# Clean build artifacts
clean:
	rm -f $(SERVER) $(CLIENT)
	@echo "Cleaned build artifacts"

# Clean certificates only
clean-certs:
	rm -rf $(CERT_DIR)
	@echo "Cleaned certificates"

# Clean everything
clean-all: clean clean-certs
	@echo "Cleaned all artifacts and certificates"

# Rebuild everything
rebuild: clean-all all certs
	@echo "Complete rebuild finished"

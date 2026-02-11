#!/bin/bash

echo "Generating Ed25519 certificates for mutual TLS..."
echo ""

# Create certs directory if it doesn't exist
mkdir -p certs

# Generate CA (Certificate Authority) private key and certificate
echo "1. Generating CA certificate..."
openssl genpkey -algorithm ED25519 -out certs/ca-key.pem

openssl req -new -x509 -key certs/ca-key.pem -out certs/ca-cert.pem -days 365 \
    -subj "/C=US/ST=State/L=City/O=Test CA/CN=Test CA"

# Generate server private key
echo "2. Generating server certificate..."
openssl genpkey -algorithm ED25519 -out certs/server-key.pem

# Generate server certificate signing request
openssl req -new -key certs/server-key.pem -out certs/server.csr \
    -subj "/C=US/ST=State/L=City/O=Server/CN=localhost"

# Sign server certificate with CA
openssl x509 -req -in certs/server.csr -CA certs/ca-cert.pem -CAkey certs/ca-key.pem \
    -CAcreateserial -out certs/server-cert.pem -days 365

# Generate client private key
echo "3. Generating client certificate..."
openssl genpkey -algorithm ED25519 -out certs/client-key.pem

# Generate client certificate signing request
openssl req -new -key certs/client-key.pem -out certs/client.csr \
    -subj "/C=US/ST=State/L=City/O=Client/CN=client"

# Sign client certificate with CA
openssl x509 -req -in certs/client.csr -CA certs/ca-cert.pem -CAkey certs/ca-key.pem \
    -CAcreateserial -out certs/client-cert.pem -days 365

# Clean up CSR files
rm -f certs/server.csr certs/client.csr

echo ""
echo "Certificate files generated in ./certs/:"
echo "  - ca-cert.pem       (CA certificate)"
echo "  - ca-key.pem        (CA private key)"
echo "  - server-cert.pem   (Server certificate)"
echo "  - server-key.pem    (Server private key)"
echo "  - client-cert.pem   (Client certificate)"
echo "  - client-key.pem    (Client private key)"
echo ""
echo "Verifying certificates..."
openssl x509 -in certs/ca-cert.pem -text -noout | grep "Signature Algorithm" | head -1
openssl x509 -in certs/server-cert.pem -text -noout | grep "Signature Algorithm" | head -1
openssl x509 -in certs/client-cert.pem -text -noout | grep "Signature Algorithm" | head -1
echo ""

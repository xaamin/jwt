!#/bin/bash

openssl genpkey -algorithm RSA -aes-256-cbc -outform PEM -out private.pem -pkeyopt rsa_keygen_bits:2048

private.pem -pkeyopt rsa_keygen_bits:2048

chmod 0400 private.pem

openssl rsa -in private.pem -outform PEM -pubout -out public_key.pem

# Remove password
openssl rsa -in private.pem -out private_new.pem


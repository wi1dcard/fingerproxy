#!/bin/bash -xeuo pipefail

SAN=example.com

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 3650 \
  -nodes -keyout tls.key -out tls.crt -subj "/CN=$SAN" \
  -addext "subjectAltName=DNS:$SAN,DNS:*.$SAN,IP:127.0.0.1"

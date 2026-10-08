#!/bin/sh
# Generates a throwaway self-signed TLS certificate for 127.0.0.1, used
# by the server tests: tls.pem and tls.key.
set -e
cd "$(dirname "$0")"

openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
	-keyout tls.key -out tls.pem -days 3650 -subj "/CN=127.0.0.1" \
	-addext "subjectAltName=IP:127.0.0.1,DNS:localhost" 2>/dev/null

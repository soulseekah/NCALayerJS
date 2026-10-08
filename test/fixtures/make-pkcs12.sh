#!/bin/sh
# Generates PKCS#12 test fixtures with a throwaway P-256 key.
#
# legacy.p12: 3DES key bag and RC2-40 certificate bag, SHA-1 MAC. This is
#             the same layout Kalkan uses for NCA keys.
# modern.p12: PBES2/AES bags and SHA-256 MAC, which we do not support yet.
#
# Expected values: key.pkcs8.der (PrivateKeyInfo) and cert.der.
set -e
cd "$(dirname "$0")"

openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -subj "/CN=NCALayerJS test" -days 3650 -out cert.pem
openssl pkcs8 -topk8 -nocrypt -in key.pem -outform DER -out key.pkcs8.der
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -export -legacy -inkey key.pem -in cert.pem -name "Test Key" \
	-passout pass:test123 -out legacy.p12
openssl pkcs12 -export -inkey key.pem -in cert.pem -name "Test Key" \
	-passout pass:test123 -out modern.p12
rm key.pem cert.pem

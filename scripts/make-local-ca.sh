#!/bin/sh
# Creates the TLS certificate for wss://127.0.0.1:13579.
#
# A throwaway CA is made with name constraints that only allow 127.0.0.1
# and localhost. It issues one server certificate, and then its private
# key is deleted, so it can never sign anything else. Import ca.pem into
# the browser once; rerun this script when the certificate expires.
#
# Usage: scripts/make-local-ca.sh [output dir, default ~/.config/ncalayerjs/tls]
set -eu

OUT="${1:-$HOME/.config/ncalayerjs/tls}"
DAYS=397
umask 077
mkdir -p "$OUT"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/openssl.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no

[dn]
CN = NCALayerJS local CA (127.0.0.1 and localhost only)

[ca_ext]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
nameConstraints = critical,permitted;IP:127.0.0.1/255.255.255.255,permitted;DNS:localhost
subjectKeyIdentifier = hash

[leaf_ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = IP:127.0.0.1,DNS:localhost
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[bad_ext]
basicConstraints = critical,CA:FALSE
subjectAltName = DNS:example.com
EOF

export OPENSSL_CONF="$TMP/openssl.cnf"

# CA, valid as long as the server certificate. Its key stays in $TMP.
openssl req -x509 -new -config "$TMP/openssl.cnf" -extensions ca_ext \
	-newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
	-keyout "$TMP/ca.key" -out "$TMP/ca.pem" -days "$DAYS" 2>/dev/null

# Issues a certificate signed by the CA: issue <name> <ext section> <subject>.
issue() {
	openssl req -new -config "$TMP/openssl.cnf" -subj "$3" \
		-newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
		-keyout "$TMP/$1.key" -out "$TMP/$1.csr" 2>/dev/null
	openssl x509 -req -in "$TMP/$1.csr" -CA "$TMP/ca.pem" -CAkey "$TMP/ca.key" \
		-set_serial "0x$(openssl rand -hex 16)" -days "$DAYS" \
		-extfile "$TMP/openssl.cnf" -extensions "$2" -out "$TMP/$1.pem" 2>/dev/null
}

issue server leaf_ext "/CN=127.0.0.1"
openssl verify -CAfile "$TMP/ca.pem" "$TMP/server.pem" > /dev/null

# Self-check: the name constraints must reject any other name.
issue bad bad_ext "/CN=example.com"
if openssl verify -CAfile "$TMP/ca.pem" "$TMP/bad.pem" > /dev/null 2>&1; then
	echo "Name constraints are not enforced, refusing to continue." >&2
	exit 1
fi

cp "$TMP/ca.pem" "$OUT/ca.pem"
cp "$TMP/server.pem" "$OUT/server.pem"
cp "$TMP/server.key" "$OUT/server.key"
chmod 644 "$OUT/ca.pem" "$OUT/server.pem"
# $TMP, including ca.key, is removed by the trap.

echo "Wrote $OUT/ca.pem, server.pem and server.key (CA key destroyed)."
openssl x509 -in "$OUT/server.pem" -noout -subject -enddate
echo
echo "Import the CA into Chrome/Chromium (Linux NSS database):"
echo "  certutil -d sql:\$HOME/.pki/nssdb -A -t 'C,,' -n 'NCALayerJS local CA' -i $OUT/ca.pem"
echo "Firefox: Settings, Certificates, View Certificates, Authorities, Import."

#!/bin/sh
# Downloads the NCALayer update manifest, signed by NIT with Kalkan, for
# use as a real-world GOST CMS test vector. We do not redistribute it.
#
# NIT serves it over plain HTTP. That is fine for a test vector: the tests
# only check that the signature is valid, and NIT may replace the file at
# any time when NCALayer is updated.
set -e
cd "$(dirname "$0")"

curl -fsSL -o kalkan-manifest.der.tmp http://crl.pki.gov.kz/updates/ncalayer.der
mv kalkan-manifest.der.tmp kalkan-manifest.der
echo "saved $(wc -c < kalkan-manifest.der) bytes to $(pwd)/kalkan-manifest.der"

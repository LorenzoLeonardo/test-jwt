#!/usr/bin/env bash
set -euo pipefail

OUT=test-pki
mkdir -p "$OUT"
cd "$OUT"

DAYS_CA=36500
DAYS_LEAF=825

echo "==> Root CA A (unused)"
openssl ecparam -name prime256v1 -genkey -noout -out root-a-key.pem
openssl req -new -x509 -key root-a-key.pem -sha256 -days $DAYS_CA \
  -subj "/C=JP/O=Test PKI/CN=Root A" \
  -out root-a-cert.pem

echo "==> Root CA B (used)"
openssl ecparam -name prime256v1 -genkey -noout -out root-b-key.pem
openssl req -new -x509 -key root-b-key.pem -sha256 -days $DAYS_CA \
  -subj "/C=JP/O=Test PKI/CN=Root B" \
  -out root-b-cert.pem

echo "==> Leaf cert (signed by Root B)"
openssl ecparam -name prime256v1 -genkey -noout -out leaf-key.pem
openssl req -new -key leaf-key.pem \
  -subj "/C=JP/O=Test PKI/CN=leaf.test" \
  -out leaf.csr

cat > leaf.ext <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth,serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

openssl x509 -req -in leaf.csr \
  -CA root-b-cert.pem -CAkey root-b-key.pem -CAcreateserial \
  -days $DAYS_LEAF -sha256 -extfile leaf.ext \
  -out leaf-cert.pem

echo "==> CA bundle (multiple CAs)"
cat root-a-cert.pem root-b-cert.pem > ca-bundle.pem

echo
echo "==> Generated files:"
ls -1
#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="ec224"
DAYS_CA=36500
DAYS_LEAF=825

mkdir -p "${OUT_DIR}"
cd "${OUT_DIR}"

echo "==> Generating EC224 CA private key"
openssl ecparam \
  -name secp224r1 \
  -genkey \
  -noout \
  -out ca-key.pem

echo "==> Generating EC224 CA self-signed certificate"
openssl req \
  -new \
  -x509 \
  -key ca-key.pem \
  -sha224 \
  -days "${DAYS_CA}" \
  -subj "/C=JP/O=Test CA/OU=Crypto/CN=EC224 Test CA" \
  -out ca-cert.pem

echo "==> Generating EC224 leaf private key"
openssl ecparam \
  -name secp224r1 \
  -genkey \
  -noout \
  -out leaf-key.pem

echo "==> Generating leaf CSR"
openssl req \
  -new \
  -key leaf-key.pem \
  -sha224 \
  -subj "/C=JP/O=Test Org/OU=Leaf/CN=leaf.test" \
  -out leaf.csr

echo "==> Creating leaf certificate extensions"
cat > leaf.ext <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

echo "==> Signing leaf certificate with CA"
openssl x509 \
  -req \
  -in leaf.csr \
  -CA ca-cert.pem \
  -CAkey ca-key.pem \
  -CAcreateserial \
  -sha224 \
  -days "${DAYS_LEAF}" \
  -extfile leaf.ext \
  -out leaf-cert.pem

echo "==> Done"
echo
echo "Generated files:"
ls -1

#!/bin/sh
# Generates a test PKI: root -> intermediate -> end-entity (ES256), plus a
# "bad" chain where a non-CA end-entity cert issues another cert.
set -e
export MSYS_NO_PATHCONV=1
DAYS=3650
key() { openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$1"; }

cat > ca.ext <<X
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
X
cat > ee.ext <<X
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=emailProtection
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
X

# Root (self-signed trust anchor)
key root.key
openssl req -new -x509 -key root.key -sha256 -days $DAYS -subj "/C=US/O=C2PA Test/OU=Test Root CA/CN=C2PA Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out root.pem

# Intermediate
key int.key
openssl req -new -key int.key -subj "/C=US/O=C2PA Test/OU=Test Intermediate CA/CN=C2PA Test Intermediate CA" -out int.csr
openssl x509 -req -in int.csr -CA root.pem -CAkey root.key -CAcreateserial -sha256 -days $DAYS -extfile ca.ext -out int.pem

# End-entity signer
key ee.key
openssl req -new -key ee.key -subj "/C=US/O=C2PA Test/OU=Test Signing/CN=C2PA Test Signer" -out ee.csr
openssl x509 -req -in ee.csr -CA int.pem -CAkey int.key -CAcreateserial -sha256 -days $DAYS -extfile ee.ext -out ee.pem

cat ee.pem int.pem > ee_chain.pem          # chain as it would appear in x5chain (leaf first)

# Negative case: non-CA signer (issued directly by root) that mints another cert
key bad_signer.key
openssl req -new -key bad_signer.key -subj "/C=US/O=C2PA Test/OU=Test Signing/CN=Legit Non-CA Signer" -out bad_signer.csr
openssl x509 -req -in bad_signer.csr -CA root.pem -CAkey root.key -CAcreateserial -sha256 -days $DAYS -extfile ee.ext -out bad_signer.pem
key bad_forged.key
openssl req -new -key bad_forged.key -subj "/C=US/O=C2PA Test/OU=Forged/CN=Forged Signer" -out bad_forged.csr
openssl x509 -req -in bad_forged.csr -CA bad_signer.pem -CAkey bad_signer.key -CAcreateserial -sha256 -days $DAYS -extfile ee.ext -out bad_forged.pem
cat bad_forged.pem bad_signer.pem > bad_forged_chain.pem

rm -f *.csr *.srl *.ext

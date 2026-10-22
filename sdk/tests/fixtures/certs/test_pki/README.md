# Test PKI (valid chain)

Throwaway ES256 PKI for certificate-handling tests. Not for production use.

* `root.pem` / `root.key` - self-signed root CA (trust anchor)
* `int.pem` / `int.key` - intermediate CA issued by the root
* `ee.pem` / `ee.key` - end-entity signer issued by the intermediate
* `ee_chain.pem` - `ee.pem` followed by `int.pem` (x5chain order)
* `gen.sh` - regenerates all of the above (also emits negative-case certs, which are not checked in here)

The end-entity cert is X.509 v3, ES256, `basicConstraints CA:FALSE`, `keyUsage digitalSignature`,
`extendedKeyUsage emailProtection`, with SKI/AKI and no unique IDs, so it meets the C2PA certificate profile.
Validity is 10 years from 2026-10-22.

# Combined branch conformance results

Suite revision: `9837e21771b546a1d7ce63db5143b92b1b87a90b`. Spec version: 2.4.
SDK commit: `7c54e87fffd0adc96bbdf6a88914640c057b4403`; branch `codex/integration-conformance-all-changes`.

**42 passed; 68 failed; 0 not applicable.**

Every case uses its specified signer/TSA trust anchors and historical validation time. Network fetches are disabled. Original YAML expectations are evaluated without filtering or remapping SDK statuses.

## Findings

All 25 PR branch heads are included; see `sources.json`. The nine fixes from this chat are merged without duplicating their dependent commits. The integration resolution preserves text NFC hashing, RIFF payload exclusions, and the multipart fallback's manifest-exclusion check.

- **35 of the 68 failures fail solely because of an additional `signingCredential.invalid` status.** Across 55 failing cases, the SDK records “certificate params incorrect”. The valid JPEG control's signing certificate has no authority-key identifier, while the SDK certificate-profile check requires one. This is a useful next investigation; the report preserves the failure rather than filtering it out.
- **OCSP and timestamp expectations remain unmet.** Their raw results include untrusted timestamps and missing revocation statuses. These are validation failures to investigate, not cases silently excluded from the run.
- **Signature/trust validation emits contradictory success statuses in several negative cases**, including expired or invalid signers. Some trust tests accept a signer that should not be trusted under the supplied signer trust list.
- **Malformed assertion CBOR still terminates the reader** with an assertion-decoding error. The structural-claim PR covers claims; this is a distinct remaining assertion-loader path.

Failure groups (categories can share underlying causes):

| Category | Failed cases |
| --- | ---: |
| assertions | 1 |
| formats | 20 |
| ingredients | 2 |
| ocsp | 12 |
| signature | 10 |
| timestamps | 9 |
| trust | 14 |

## SDK regression verification

- `cargo +1.96.0 check -p c2pa --all-features`: passed.
- SDK unit tests with every feature: **1,442 passed, 4 failed, 15 ignored**. The four failures are the existing cross-platform ZIP fixtures containing the old `uris` map, intentionally rejected by the spec-array fix. Original conformance assets and YAML expectations were not modified.
- All SDK integration-test targets with every feature: **140 passed, 0 failed, 1 ignored**, across 16 targets.
- Clippy for the SDK library, tests, and examples with every feature, with warnings denied: passed. Nightly formatting and `git diff --check`: passed.
- The first unit run inside the sandbox could not bind HTTP mock servers; the reported unit rerun allowed localhost sockets. These sandbox failures are excluded from the final SDK regression count.

## Remaining failures

### assertions/malformed_assertion.yaml

assertion CBOR is malformed (assertion.cbor.invalid)

- reader error: could not decode assertion c2pa.actions.v2 (version 2, content type application/cbor): Syntax error: Unsigned integer cannot be indefinite

### formats/bmff/avif_valid.yaml

AVIF with valid C2PA manifest

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/bmff/m4a_valid.yaml

M4A with valid C2PA manifest

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/bmff/mp4_valid.yaml

MP4 with valid C2PA manifest

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/gif/valid.yaml

GIF with valid C2PA manifest

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/id3/flac_valid.yaml

FLAC with valid C2PA manifest

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/id3/mp3_valid.yaml

MP3 with valid C2PA manifest

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/jpeg/c2pa_single_segment.yaml

JPEG with valid C2PA manifest store in a single APP11 segment

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/jpeg/edited_action.yaml

JPEG with valid C2PA manifest that includes a c2pa.edited action

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/jpeg/multipart_intact.yaml

Multipart JPEG with multi-asset hash, all three parts intact

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/jpeg/multipart_one_optional_part_removed.yaml

Multipart JPEG with multi-asset hash, optional part 3 of 3 removed

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/jpeg/multipart_required_part_intact.yaml

Multipart JPEG with multi-asset hash where the second part is required, fully intact and valid

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/jpeg/multipart_two_optional_parts_removed.yaml

Multipart JPEG with multi-asset hash, optional parts 2 and 3 of 3 removed

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/mov/valid.yaml

MOV with valid C2PA manifest

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/pdf/valid.yaml

PDF with valid C2PA manifest

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/png/valid.yaml

PNG with valid C2PA manifest

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/riff/wav_valid.yaml

WAV with valid C2PA manifest

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/riff/webp_valid.yaml

WebP with valid C2PA manifest

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/tiff/dng_valid.yaml

DNG with valid C2PA manifest

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/tiff/tiff_valid.yaml

TIFF with valid C2PA manifest

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### formats/zip/valid.yaml

DOCX with valid C2PA manifest

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### ingredients/ingredient_with_hard_binding_mismatch.yaml

JPEG with C2PA manifest, carrying a c2pa.opened action that references an ingredient with a data hash failure

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### ingredients/opened_with_ingredient.yaml

JPEG with valid C2PA manifest, carrying a c2pa.opened action and one ingredient

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### ocsp/bad_ocsp_intermediate_revoked.yaml

valid REVOKED OCSP response associated with intermediate CA cert

- activeManifest.failures: missing ['signingCredential.untrusted']
- activeManifest.successes: forbidden ['signingCredential.trusted']

### ocsp/bad_ocsp_revoked.yaml

valid REVOKED OCSP response

- activeManifest.failures: missing ['signingCredential.ocsp.revoked']
- activeManifest.successes: forbidden ['signingCredential.trusted']

### ocsp/ocsp_good.yaml

valid GOOD OCSP response

- activeManifest.successes: missing ['signingCredential.ocsp.notRevoked']

### ocsp/ocsp_intermediate_good_leaf_missing.yaml

valid GOOD OCSP response associated with intermediate CA, no response for leaf

- activeManifest.informationals: missing ['signingCredential.ocsp.skipped']

### ocsp/ocsp_skipped_bad_sig.yaml

OCSP invalid signature (skipped)

- activeManifest.informationals: missing ['signingCredential.ocsp.skipped']

### ocsp/ocsp_skipped_expired_next_update.yaml

OCSP expired against nextUpdate (skipped)

- activeManifest.informationals: missing ['signingCredential.ocsp.skipped']

### ocsp/ocsp_skipped_no_eku.yaml

OCSP responder missing EKU (skipped)

- activeManifest.informationals: missing ['signingCredential.ocsp.skipped']

### ocsp/ocsp_skipped_unauthorized.yaml

OCSP responder from wrong CA (skipped)

- activeManifest.informationals: missing ['signingCredential.ocsp.skipped']

### ocsp/ocsp_skipped_validation_before_this_update.yaml

Validation time before OCSP thisUpdate (skipped)

- activeManifest.informationals: missing ['signingCredential.ocsp.skipped']

### ocsp/ocsp_skipped_wrong_cert.yaml

OCSP certificate mismatch (skipped)

- activeManifest.informationals: missing ['signingCredential.ocsp.skipped']

### ocsp/ocsp_ts_before_this_update_ok.yaml

TS time before OCSP thisUpdate

- activeManifest.successes: missing ['signingCredential.ocsp.notRevoked']

### ocsp/ocsp_valid_at_ts_ok.yaml

OCSP valid at TS time but expired at validation time

- activeManifest.successes: missing ['signingCredential.ocsp.notRevoked']

### signature/claim_signer_ca.yaml

claim signer certificate has disallowed CA:true flag

- activeManifest.successes: forbidden ['claimSignature.validated']

### signature/claim_signer_cert_expired.yaml

claim signer certificate expired, no timestamp

- activeManifest.successes: forbidden ['claimSignature.validated']

### signature/claim_signer_cert_not_yet_valid.yaml

claim signer certificate not yet valid, no timestamp

- activeManifest.successes: forbidden ['claimSignature.validated']

### signature/claim_signer_key_cert_sign.yaml

claim signer certificate has disallowed certSign KeyUsage

- activeManifest.successes: forbidden ['claimSignature.validated']

### signature/es256.yaml

valid ES256 claim signature

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### signature/es384.yaml

valid ES384 claim signature

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### signature/es512.yaml

valid ES512 claim signature

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### signature/ps256.yaml

valid PS256 claim signature

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### signature/ps384.yaml

valid PS384 claim signature

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### signature/ps512.yaml

valid PS512 claim signature

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### timestamps/bad_expired_late_ts.yaml

signer expired, timestamp also after signer expired

- activeManifest.successes: missing ['timeStamp.trusted']
- activeManifest.successes: forbidden ['claimSignature.validated']

### timestamps/bad_expired_no_ts.yaml

signer expired, no timestamp

- activeManifest.successes: forbidden ['claimSignature.validated']

### timestamps/bad_expired_ts_outside_tsa.yaml

timestamp asserted time outside TSA cert validity

- activeManifest.successes: forbidden ['claimSignature.validated']
- activeManifest.informationals: missing ['timeStamp.outsideValidity']

### timestamps/bad_expired_untrusted_ts.yaml

signer expired, timestamp is untrusted

- activeManifest.successes: forbidden ['claimSignature.validated']

### timestamps/bad_tsa_no_eku.yaml

TSA certificate does not include the required id-kp-timeStamping EKU

- activeManifest.successes: forbidden ['claimSignature.validated']

### timestamps/bad_tsa_wrong_trust_list.yaml

TSA cert issuing CA on claim signing trust list but not TSA trust list

- activeManifest.successes: forbidden ['claimSignature.validated']

### timestamps/ts_ica_expired_ok.yaml

ICA expired at validation time, but trusted timestamp is within ICA validity

- activeManifest.successes: missing ['signingCredential.trusted', 'timeStamp.trusted', 'timeStamp.validated']

### timestamps/ts_signer_expired_ok.yaml

signer expired at validation time, but trusted timestamp is within validity

- activeManifest.successes: missing ['signingCredential.trusted', 'timeStamp.trusted', 'timeStamp.validated']

### timestamps/tsa_cert_expired_ok.yaml

TSA cert expired at validation time, but was valid at asserted time

- activeManifest.successes: missing ['signingCredential.trusted', 'timeStamp.trusted', 'timeStamp.validated']

### trust/bad_eku_c2pa_any.yaml

signer has C2PA EKU and anyExtendedKeyUsage (forbidden)

- activeManifest.successes: forbidden ['signingCredential.trusted']

### trust/bad_eku_wrong.yaml

signer has emailProtection but no C2PA EKU

- activeManifest.successes: forbidden ['signingCredential.trusted']

### trust/bad_issuing_ca_not_on_trust_list.yaml

issuing root CA not on trust list

- activeManifest.failures: missing ['signingCredential.untrusted']
- activeManifest.successes: forbidden ['signingCredential.trusted']

### trust/bad_issuing_ca_on_tsa_only.yaml

issuing CA on TSA trust list but not claim signing trust list

- activeManifest.failures: missing ['signingCredential.untrusted']
- activeManifest.successes: forbidden ['signingCredential.trusted']

### trust/bad_ku_none.yaml

signer missing digitalSignature KU bit

- activeManifest.successes: forbidden ['signingCredential.trusted']

### trust/bad_sub_ca_expired.yaml

intermediate CA expired (vTime 2015, CA valid 2010-2014)

- activeManifest.failures: missing ['claimSignature.outsideValidity']
- activeManifest.successes: expected empty, got ['assertion.dataHash.match', 'assertion.hashedURI.match', 'claimSignature.insideValidity', 'claimSignature.validated']

### trust/bad_sub_ca_not_yet_valid.yaml

intermediate CA not yet valid (vTime 2005, CA valid 2010-2014)

- activeManifest.failures: missing ['claimSignature.outsideValidity']
- activeManifest.successes: expected empty, got ['assertion.dataHash.match', 'assertion.hashedURI.match', 'claimSignature.insideValidity', 'claimSignature.validated']

### trust/cert_chain_reverse_order.yaml

COSE x5chain in reverse order (leaf-last)

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### trust/eku_multiple.yaml

signer has C2PA EKU and other EKUs (valid)

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### trust/intermediate_ca_on_trust_list.yaml

issuing intermediate CA on trust list

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### trust/issuing_ca_and_root_on_trust_list.yaml

issuing intermediate CA and root CA on trust list

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### trust/issuing_ca_embedded_and_on_trust_list.yaml

issuing intermediate CA cert embedded and on trust list

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### trust/pathlen_sub1_ok.yaml

intermediate CA pathlen constraint met (Root -> Sub1 pathlen:1 -> Sub2 -> Signer)

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

### trust/root_ca_on_trust_list.yaml

root CA on trust list, intermediate CA cert embedded

- activeManifest.failures: expected empty, got ['signingCredential.invalid']

## All cases

| Case | Result |
| --- | --- |
| `assertions/hashed_uri_unresolvable.yaml` | pass |
| `assertions/malformed_assertion.yaml` | fail |
| `assertions/missing_created_assertions.yaml` | pass |
| `assertions/tampered_assertion.yaml` | pass |
| `claims/claim_cbor_invalid.yaml` | pass |
| `claims/claim_missing.yaml` | pass |
| `claims/claim_multiple.yaml` | pass |
| `claims/hard_bindings_missing.yaml` | pass |
| `claims/missing_instance_id.yaml` | pass |
| `claims/unsupported_hashed_uri_algorithm.yaml` | pass |
| `formats/bmff/avif_no_manifest.yaml` | pass |
| `formats/bmff/avif_valid.yaml` | fail |
| `formats/bmff/m4a_no_manifest.yaml` | pass |
| `formats/bmff/m4a_valid.yaml` | fail |
| `formats/bmff/mp4_no_manifest.yaml` | pass |
| `formats/bmff/mp4_valid.yaml` | fail |
| `formats/gif/no_manifest.yaml` | pass |
| `formats/gif/valid.yaml` | fail |
| `formats/id3/flac_no_manifest.yaml` | pass |
| `formats/id3/flac_valid.yaml` | fail |
| `formats/id3/mp3_no_manifest.yaml` | pass |
| `formats/id3/mp3_valid.yaml` | fail |
| `formats/jpeg/c2pa_single_segment.yaml` | fail |
| `formats/jpeg/data_hash_mismatch.yaml` | pass |
| `formats/jpeg/edited_action.yaml` | fail |
| `formats/jpeg/multipart_extra_data.yaml` | pass |
| `formats/jpeg/multipart_gap.yaml` | pass |
| `formats/jpeg/multipart_intact.yaml` | fail |
| `formats/jpeg/multipart_one_optional_part_removed.yaml` | fail |
| `formats/jpeg/multipart_optional_part_mismatch.yaml` | pass |
| `formats/jpeg/multipart_optional_part_partly_removed.yaml` | pass |
| `formats/jpeg/multipart_required_part_intact.yaml` | fail |
| `formats/jpeg/multipart_required_part_removed.yaml` | pass |
| `formats/jpeg/multipart_two_optional_parts_removed.yaml` | fail |
| `formats/jpeg/no_manifest.yaml` | pass |
| `formats/mov/no_manifest.yaml` | pass |
| `formats/mov/valid.yaml` | fail |
| `formats/mp4/bmff_hash_mismatch.yaml` | pass |
| `formats/pdf/no_manifest.yaml` | pass |
| `formats/pdf/valid.yaml` | fail |
| `formats/png/no_manifest.yaml` | pass |
| `formats/png/valid.yaml` | fail |
| `formats/riff/wav_no_manifest.yaml` | pass |
| `formats/riff/wav_valid.yaml` | fail |
| `formats/riff/webp_no_manifest.yaml` | pass |
| `formats/riff/webp_valid.yaml` | fail |
| `formats/tiff/dng_no_manifest.yaml` | pass |
| `formats/tiff/dng_valid.yaml` | fail |
| `formats/tiff/tiff_no_manifest.yaml` | pass |
| `formats/tiff/tiff_valid.yaml` | fail |
| `formats/zip/no_manifest.yaml` | pass |
| `formats/zip/valid.yaml` | fail |
| `ingredients/ingredient_with_hard_binding_mismatch.yaml` | fail |
| `ingredients/ingredient_with_missing_manifest.yaml` | pass |
| `ingredients/ingredient_with_missing_validation_results.yaml` | pass |
| `ingredients/opened_with_ingredient.yaml` | fail |
| `ocsp/bad_ocsp_intermediate_revoked.yaml` | fail |
| `ocsp/bad_ocsp_revoked.yaml` | fail |
| `ocsp/ocsp_good.yaml` | fail |
| `ocsp/ocsp_intermediate_good_leaf_missing.yaml` | fail |
| `ocsp/ocsp_skipped_bad_sig.yaml` | fail |
| `ocsp/ocsp_skipped_expired_next_update.yaml` | fail |
| `ocsp/ocsp_skipped_no_eku.yaml` | fail |
| `ocsp/ocsp_skipped_unauthorized.yaml` | fail |
| `ocsp/ocsp_skipped_validation_before_this_update.yaml` | fail |
| `ocsp/ocsp_skipped_wrong_cert.yaml` | fail |
| `ocsp/ocsp_ts_before_this_update_ok.yaml` | fail |
| `ocsp/ocsp_valid_at_ts_ok.yaml` | fail |
| `signature/claim_signer_ca.yaml` | fail |
| `signature/claim_signer_cert_expired.yaml` | fail |
| `signature/claim_signer_cert_not_yet_valid.yaml` | fail |
| `signature/claim_signer_key_cert_sign.yaml` | fail |
| `signature/es256.yaml` | fail |
| `signature/es384.yaml` | fail |
| `signature/es512.yaml` | fail |
| `signature/missing.yaml` | pass |
| `signature/ps256.yaml` | fail |
| `signature/ps384.yaml` | fail |
| `signature/ps512.yaml` | fail |
| `signature/uri_invalid.yaml` | pass |
| `signature/wrong_signing_key.yaml` | pass |
| `timestamps/bad_expired_late_ts.yaml` | fail |
| `timestamps/bad_expired_no_ts.yaml` | fail |
| `timestamps/bad_expired_ts_outside_tsa.yaml` | fail |
| `timestamps/bad_expired_untrusted_ts.yaml` | fail |
| `timestamps/bad_tsa_no_eku.yaml` | fail |
| `timestamps/bad_tsa_wrong_trust_list.yaml` | fail |
| `timestamps/ts_ica_expired_ok.yaml` | fail |
| `timestamps/ts_signer_expired_ok.yaml` | fail |
| `timestamps/ts_untrusted_signer_ok.yaml` | pass |
| `timestamps/tsa_cert_expired_ok.yaml` | fail |
| `trust/bad_eku_any.yaml` | pass |
| `trust/bad_eku_c2pa_any.yaml` | fail |
| `trust/bad_eku_none.yaml` | pass |
| `trust/bad_eku_wrong.yaml` | fail |
| `trust/bad_issuing_ca_missing_from_chain.yaml` | pass |
| `trust/bad_issuing_ca_not_on_trust_list.yaml` | fail |
| `trust/bad_issuing_ca_on_tsa_only.yaml` | fail |
| `trust/bad_ku_none.yaml` | fail |
| `trust/bad_pathlen_sub0.yaml` | pass |
| `trust/bad_sub_ca_expired.yaml` | fail |
| `trust/bad_sub_ca_not_yet_valid.yaml` | fail |
| `trust/cert_chain_reverse_order.yaml` | fail |
| `trust/eku_multiple.yaml` | fail |
| `trust/intermediate_ca_on_trust_list.yaml` | fail |
| `trust/issuing_ca_and_root_on_trust_list.yaml` | fail |
| `trust/issuing_ca_embedded_and_on_trust_list.yaml` | fail |
| `trust/pathlen_sub1_ok.yaml` | fail |
| `trust/root_ca_on_trust_list.yaml` | fail |
| `trust/sub_ca_cert_valid_now.yaml` | pass |

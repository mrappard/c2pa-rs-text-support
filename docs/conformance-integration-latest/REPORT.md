# Combined branch conformance results

Suite revision: `9837e21771b546a1d7ce63db5143b92b1b87a90b`. Spec version: 2.4.
SDK commit: `81125b7422df9d91937db38981de98cf03ea4ad9`; branch `codex/fix-conformance-certificate-profile`.

**94 passed; 16 failed; 0 not applicable.**

Every case uses its specified signer/TSA trust anchors and historical validation time. Network fetches are disabled. Original YAML expectations are evaluated without filtering or remapping SDK statuses.

## Remaining failures

### ocsp/bad_ocsp_intermediate_revoked.yaml

valid REVOKED OCSP response associated with intermediate CA cert

- activeManifest.failures: missing ['signingCredential.untrusted']
- activeManifest.successes: forbidden ['signingCredential.trusted']

### ocsp/ocsp_good.yaml

valid GOOD OCSP response

- activeManifest.successes: missing ['signingCredential.ocsp.notRevoked']

### ocsp/ocsp_ts_before_this_update_ok.yaml

TS time before OCSP thisUpdate

- activeManifest.successes: missing ['signingCredential.ocsp.notRevoked']
- activeManifest.informationals: forbidden ['signingCredential.ocsp.skipped']

### ocsp/ocsp_valid_at_ts_ok.yaml

OCSP valid at TS time but expired at validation time

- activeManifest.successes: missing ['signingCredential.ocsp.notRevoked']

### timestamps/bad_expired_late_ts.yaml

signer expired, timestamp also after signer expired

- activeManifest.successes: missing ['timeStamp.trusted']

### timestamps/bad_expired_ts_outside_tsa.yaml

timestamp asserted time outside TSA cert validity

- activeManifest.informationals: missing ['timeStamp.outsideValidity']

### timestamps/ts_ica_expired_ok.yaml

ICA expired at validation time, but trusted timestamp is within ICA validity

- activeManifest.successes: missing ['claimSignature.validated', 'signingCredential.trusted', 'timeStamp.trusted', 'timeStamp.validated']

### timestamps/ts_signer_expired_ok.yaml

signer expired at validation time, but trusted timestamp is within validity

- activeManifest.successes: missing ['claimSignature.validated', 'signingCredential.trusted', 'timeStamp.trusted', 'timeStamp.validated']

### timestamps/tsa_cert_expired_ok.yaml

TSA cert expired at validation time, but was valid at asserted time

- activeManifest.successes: missing ['claimSignature.validated', 'signingCredential.trusted', 'timeStamp.trusted', 'timeStamp.validated']

### trust/bad_eku_c2pa_any.yaml

signer has C2PA EKU and anyExtendedKeyUsage (forbidden)

- activeManifest.successes: forbidden ['signingCredential.trusted']

### trust/bad_eku_wrong.yaml

signer has emailProtection but no C2PA EKU

- activeManifest.failures: expected one of ['signingCredential.invalid', 'signingCredential.untrusted']
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
- activeManifest.successes: expected empty, got ['assertion.dataHash.match', 'assertion.hashedURI.match']

### trust/bad_sub_ca_not_yet_valid.yaml

intermediate CA not yet valid (vTime 2005, CA valid 2010-2014)

- activeManifest.failures: missing ['claimSignature.outsideValidity']
- activeManifest.successes: expected empty, got ['assertion.dataHash.match', 'assertion.hashedURI.match']

## All cases

| Case | Result |
| --- | --- |
| `assertions/hashed_uri_unresolvable.yaml` | pass |
| `assertions/malformed_assertion.yaml` | pass |
| `assertions/missing_created_assertions.yaml` | pass |
| `assertions/tampered_assertion.yaml` | pass |
| `claims/claim_cbor_invalid.yaml` | pass |
| `claims/claim_missing.yaml` | pass |
| `claims/claim_multiple.yaml` | pass |
| `claims/hard_bindings_missing.yaml` | pass |
| `claims/missing_instance_id.yaml` | pass |
| `claims/unsupported_hashed_uri_algorithm.yaml` | pass |
| `formats/bmff/avif_no_manifest.yaml` | pass |
| `formats/bmff/avif_valid.yaml` | pass |
| `formats/bmff/m4a_no_manifest.yaml` | pass |
| `formats/bmff/m4a_valid.yaml` | pass |
| `formats/bmff/mp4_no_manifest.yaml` | pass |
| `formats/bmff/mp4_valid.yaml` | pass |
| `formats/gif/no_manifest.yaml` | pass |
| `formats/gif/valid.yaml` | pass |
| `formats/id3/flac_no_manifest.yaml` | pass |
| `formats/id3/flac_valid.yaml` | pass |
| `formats/id3/mp3_no_manifest.yaml` | pass |
| `formats/id3/mp3_valid.yaml` | pass |
| `formats/jpeg/c2pa_single_segment.yaml` | pass |
| `formats/jpeg/data_hash_mismatch.yaml` | pass |
| `formats/jpeg/edited_action.yaml` | pass |
| `formats/jpeg/multipart_extra_data.yaml` | pass |
| `formats/jpeg/multipart_gap.yaml` | pass |
| `formats/jpeg/multipart_intact.yaml` | pass |
| `formats/jpeg/multipart_one_optional_part_removed.yaml` | pass |
| `formats/jpeg/multipart_optional_part_mismatch.yaml` | pass |
| `formats/jpeg/multipart_optional_part_partly_removed.yaml` | pass |
| `formats/jpeg/multipart_required_part_intact.yaml` | pass |
| `formats/jpeg/multipart_required_part_removed.yaml` | pass |
| `formats/jpeg/multipart_two_optional_parts_removed.yaml` | pass |
| `formats/jpeg/no_manifest.yaml` | pass |
| `formats/mov/no_manifest.yaml` | pass |
| `formats/mov/valid.yaml` | pass |
| `formats/mp4/bmff_hash_mismatch.yaml` | pass |
| `formats/pdf/no_manifest.yaml` | pass |
| `formats/pdf/valid.yaml` | pass |
| `formats/png/no_manifest.yaml` | pass |
| `formats/png/valid.yaml` | pass |
| `formats/riff/wav_no_manifest.yaml` | pass |
| `formats/riff/wav_valid.yaml` | pass |
| `formats/riff/webp_no_manifest.yaml` | pass |
| `formats/riff/webp_valid.yaml` | pass |
| `formats/tiff/dng_no_manifest.yaml` | pass |
| `formats/tiff/dng_valid.yaml` | pass |
| `formats/tiff/tiff_no_manifest.yaml` | pass |
| `formats/tiff/tiff_valid.yaml` | pass |
| `formats/zip/no_manifest.yaml` | pass |
| `formats/zip/valid.yaml` | pass |
| `ingredients/ingredient_with_hard_binding_mismatch.yaml` | pass |
| `ingredients/ingredient_with_missing_manifest.yaml` | pass |
| `ingredients/ingredient_with_missing_validation_results.yaml` | pass |
| `ingredients/opened_with_ingredient.yaml` | pass |
| `ocsp/bad_ocsp_intermediate_revoked.yaml` | fail |
| `ocsp/bad_ocsp_revoked.yaml` | pass |
| `ocsp/ocsp_good.yaml` | fail |
| `ocsp/ocsp_intermediate_good_leaf_missing.yaml` | pass |
| `ocsp/ocsp_skipped_bad_sig.yaml` | pass |
| `ocsp/ocsp_skipped_expired_next_update.yaml` | pass |
| `ocsp/ocsp_skipped_no_eku.yaml` | pass |
| `ocsp/ocsp_skipped_unauthorized.yaml` | pass |
| `ocsp/ocsp_skipped_validation_before_this_update.yaml` | pass |
| `ocsp/ocsp_skipped_wrong_cert.yaml` | pass |
| `ocsp/ocsp_ts_before_this_update_ok.yaml` | fail |
| `ocsp/ocsp_valid_at_ts_ok.yaml` | fail |
| `signature/claim_signer_ca.yaml` | pass |
| `signature/claim_signer_cert_expired.yaml` | pass |
| `signature/claim_signer_cert_not_yet_valid.yaml` | pass |
| `signature/claim_signer_key_cert_sign.yaml` | pass |
| `signature/es256.yaml` | pass |
| `signature/es384.yaml` | pass |
| `signature/es512.yaml` | pass |
| `signature/missing.yaml` | pass |
| `signature/ps256.yaml` | pass |
| `signature/ps384.yaml` | pass |
| `signature/ps512.yaml` | pass |
| `signature/uri_invalid.yaml` | pass |
| `signature/wrong_signing_key.yaml` | pass |
| `timestamps/bad_expired_late_ts.yaml` | fail |
| `timestamps/bad_expired_no_ts.yaml` | pass |
| `timestamps/bad_expired_ts_outside_tsa.yaml` | fail |
| `timestamps/bad_expired_untrusted_ts.yaml` | pass |
| `timestamps/bad_tsa_no_eku.yaml` | pass |
| `timestamps/bad_tsa_wrong_trust_list.yaml` | pass |
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
| `trust/cert_chain_reverse_order.yaml` | pass |
| `trust/eku_multiple.yaml` | pass |
| `trust/intermediate_ca_on_trust_list.yaml` | pass |
| `trust/issuing_ca_and_root_on_trust_list.yaml` | pass |
| `trust/issuing_ca_embedded_and_on_trust_list.yaml` | pass |
| `trust/pathlen_sub1_ok.yaml` | pass |
| `trust/root_ca_on_trust_list.yaml` | pass |
| `trust/sub_ca_cert_valid_now.yaml` | pass |

// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Generates CAWG identity assertion conformance fixtures.
//!
//! This is not a regular test: it is `#[ignore]`d and writes signed JPEGs
//! (plus an `index.json` describing what each one exercises and the status
//! codes the specification expects) for use by an external conformance suite.
//!
//! ```text
//! CAWG_FIXTURES_OUT=/path/to/out \
//!   cargo test -p c2pa --lib generate_cawg_conformance_fixtures -- --ignored --nocapture
//! ```
//!
//! Without `CAWG_FIXTURES_OUT`, files go to `target/cawg-conformance-fixtures`.
//! Everything is signed offline with the c2pa-rs test credentials (and, for
//! the trust-model cases, certificates minted at run time), so the output
//! differs on every run.

mod certs;
mod holders;

use std::{
    io::Cursor,
    path::{Path, PathBuf},
    sync::Arc,
};

use c2pa_raw_crypto::signer_from_private_key;
use serde_json::{json, Value};

use self::{
    certs::{Eku, TestCa, POLICY_SMIME_MAILBOX_MULTIPURPOSE, POLICY_SMIME_ORG_MULTIPURPOSE},
    holders::{
        corrupt_signature, set_subject_field, set_unsupported_algorithm, verified_identities_mut,
        IcaFixtureHolder, TamperingX509Holder,
    },
};
use crate::{
    crypto::cert_chain_pem_to_der,
    identity::{
        builder::{AsyncIdentityAssertionBuilder, AsyncIdentityAssertionSigner},
        tests::{
            fixtures::{cert_chain_and_private_key_for_alg, manifest_json, parent_json},
            ica_test_context, ICA_FIXTURE_JWK_ISSUER,
        },
        x509::AsyncX509CredentialHolder,
        SignerPayload,
    },
    Builder, HashedUri, Reader, SigningAlg,
};

const TEST_IMAGE: &[u8] = include_bytes!("../../../../tests/fixtures/CA.jpg");
const TEST_THUMBNAIL: &[u8] = include_bytes!("../../../../tests/fixtures/thumbnail.jpg");
const EXPIRED_CERT: &[u8] = include_bytes!("../../../../tests/fixtures/rsa-pss256_key-expired.pub");
const EXPIRED_KEY: &[u8] = include_bytes!("../../../../tests/fixtures/rsa-pss256-expired.pem");

/// One generated fixture and what the CAWG specification expects of it.
struct Fixture {
    group: &'static str,
    name: &'static str,
    description: &'static str,
    spec: &'static str,
    /// Status codes a conforming validator must report as failures.
    expect_failure: Vec<&'static str>,
    /// At least one of these must be reported (any category).
    expect_any: Vec<&'static str>,
    /// Extra validator configuration the expectation depends on.
    requires: Option<&'static str>,
}

impl Fixture {
    fn new(group: &'static str, name: &'static str, description: &'static str) -> Self {
        Self {
            group,
            name,
            description,
            spec: "",
            expect_failure: vec![],
            expect_any: vec![],
            requires: None,
        }
    }

    fn spec(mut self, spec: &'static str) -> Self {
        self.spec = spec;
        self
    }

    fn fails_with(mut self, codes: &[&'static str]) -> Self {
        self.expect_failure = codes.to_vec();
        self
    }

    fn reports_any(mut self, codes: &[&'static str]) -> Self {
        self.expect_any = codes.to_vec();
        self
    }

    fn requires(mut self, requirement: &'static str) -> Self {
        self.requires = Some(requirement);
        self
    }

    fn path(&self) -> String {
        format!("{}/{}.jpg", self.group, self.name)
    }
}

/// Leaf common name, issuing CA, EKU, certificate policy, and the fixture.
type TrustCase<'a> = (&'a str, &'a TestCa, Eku, Option<&'a str>, Fixture);

const WELL_FORMED_OR_TRUSTED: &[&str] = &["cawg.identity.well-formed", "cawg.identity.trusted"];

fn output_dir() -> PathBuf {
    std::env::var_os("CAWG_FIXTURES_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/cawg-conformance-fixtures"))
}

/// Sign the standard test asset with the given identity assertions.
async fn sign_asset(identity_assertions: Vec<AsyncIdentityAssertionBuilder>) -> Vec<u8> {
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::default().with_definition(manifest_json()).unwrap();
    builder
        .add_ingredient_from_stream(parent_json(), format, &mut source)
        .unwrap();
    builder
        .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
        .unwrap();

    let mut c2pa_signer = AsyncIdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);
    for iab in identity_assertions {
        c2pa_signer.add_identity_assertion(iab);
    }

    builder
        .sign_async(&c2pa_signer, format, &mut source, &mut dest)
        .await
        .unwrap();
    dest.into_inner()
}

/// X.509 credential holder using the c2pa-rs Ed25519 test credentials.
fn test_x509_holder() -> AsyncX509CredentialHolder {
    let (chain, key) = cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);
    AsyncX509CredentialHolder::from_async_raw_signer(
        signer_from_private_key(&key, SigningAlg::Ed25519).unwrap(),
        cert_chain_pem_to_der(&chain).unwrap(),
    )
}

fn x509_holder_from(
    chain_der: Vec<Vec<u8>>,
    key_pem: &[u8],
    alg: SigningAlg,
) -> AsyncX509CredentialHolder {
    AsyncX509CredentialHolder::from_async_raw_signer(
        signer_from_private_key(key_pem, alg).unwrap(),
        chain_der,
    )
}

/// ICA credential holder signing as the did:jwk issuer used by the bundled
/// c2pa-rs ICA fixtures (trusted by [`ica_test_context`]).
fn test_ica_holder() -> IcaFixtureHolder {
    let (_, key) = cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);
    IcaFixtureHolder::new(
        signer_from_private_key(&key, SigningAlg::Ed25519).unwrap(),
        ICA_FIXTURE_JWK_ISSUER,
    )
}

/// Hashed URIs (made absolute) for assertions in the ingredient's manifest,
/// keyed by assertion label.
async fn ingredient_refs() -> Vec<(String, HashedUri)> {
    let reader = Reader::default()
        .with_stream_async("image/jpeg", Cursor::new(TEST_IMAGE))
        .await
        .unwrap();
    let label = reader.active_label().unwrap().to_owned();
    let claim = reader.store.get_claim(&label).unwrap();

    let mut refs = vec![];
    for a in claim.assertions() {
        let assertion_label = a.url().rsplit('/').next().unwrap_or_default().to_owned();
        let url = format!("self#jumbf=/c2pa/{label}/c2pa.assertions/{assertion_label}");
        refs.push((assertion_label, HashedUri::new(url, a.alg(), &a.hash())));
    }
    refs
}

fn find_ref(refs: &[(String, HashedUri)], prefix: &str) -> HashedUri {
    refs.iter()
        .find(|(label, _)| label.starts_with(prefix))
        .map(|(_, r)| r.clone())
        .unwrap_or_else(|| panic!("ingredient has no assertion starting with {prefix}"))
}

fn write(out: &Path, fixture: &Fixture, bytes: &[u8]) {
    let path = out.join(fixture.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, bytes).unwrap();
}

/// Read a generated asset back and list the cawg.* status codes c2pa-rs
/// reports for it (informational; printed for whoever runs the generator).
async fn cawg_codes(bytes: &[u8]) -> Vec<String> {
    let context = ica_test_context().into_shared();
    let reader = match Reader::from_shared_context(&context)
        .with_stream_async("image/jpeg", Cursor::new(bytes.to_vec()))
        .await
    {
        Ok(r) => r,
        Err(e) => return vec![format!("read error: {e}")],
    };
    let Ok(crjson) = reader.to_crjson_value() else {
        return vec!["crJSON error".to_owned()];
    };
    let mut codes = vec![];
    for manifest in crjson["manifests"].as_array().into_iter().flatten() {
        for category in ["success", "informational", "failure"] {
            for entry in manifest["validationResults"][category]
                .as_array()
                .into_iter()
                .flatten()
            {
                if let Some(code) = entry["code"].as_str() {
                    if code.starts_with("cawg.") {
                        codes.push(format!("{category}:{code}"));
                    }
                }
            }
        }
    }
    codes.sort();
    codes.dedup();
    codes
}

#[tokio::test]
#[ignore = "generates CAWG conformance fixtures; run explicitly with --ignored"]
async fn generate_cawg_conformance_fixtures() {
    let out = output_dir();
    std::fs::create_dir_all(&out).unwrap();
    let mut fixtures: Vec<(Fixture, Vec<u8>)> = vec![];
    let ingredient = ingredient_refs().await;

    // ---- Identity assertion structure (§5, §7.1) --------------------------

    {
        let mut first = AsyncIdentityAssertionBuilder::for_credential_holder(test_x509_holder());
        first.add_roles(&["cawg.creator"]);
        let mut second = AsyncIdentityAssertionBuilder::for_credential_holder(test_x509_holder());
        second.add_roles(&["cawg.editor"]);
        let bytes = sign_asset(vec![first, second]).await;
        fixtures.push((
            Fixture::new(
                "identity",
                "multiple_identity_assertions",
                "Two valid X.509 identity assertions (cawg.identity and cawg.identity__1) with different roles.",
            )
            .spec("Identity 1.3 §5.1, §7.2")
            .reports_any(WELL_FORMED_OR_TRUSTED),
            bytes,
        ));
    }

    {
        let mut iab = AsyncIdentityAssertionBuilder::for_credential_holder(test_x509_holder());
        iab.add_roles(&["cawg.creator", "com.example.reviewer"]);
        let bytes = sign_asset(vec![iab]).await;
        fixtures.push((
            Fixture::new(
                "identity",
                "custom_role",
                "Valid X.509 identity assertion with a recommended role and an entity-specific custom role.",
            )
            .spec("Identity 1.3 §5.1.2")
            .reports_any(WELL_FORMED_OR_TRUSTED),
            bytes,
        ));
    }

    {
        let ingredient_actions = find_ref(&ingredient, "c2pa.actions");
        let mut iab = AsyncIdentityAssertionBuilder::for_credential_holder(test_x509_holder());
        iab.test_hooks.signer_payload = Some(Arc::new(move |sp: &mut SignerPayload| {
            sp.referenced_assertions.push(ingredient_actions.clone());
        }));
        let bytes = sign_asset(vec![iab]).await;
        fixtures.push((
            Fixture::new(
                "identity",
                "references_ingredient_assertion",
                "Valid identity assertion that also references an assertion in the ingredient's claim, which §5.1.1 allows.",
            )
            .spec("Identity 1.3 §5.1.1, §7.1 step 2")
            .reports_any(WELL_FORMED_OR_TRUSTED),
            bytes,
        ));
    }

    {
        let ingredient_hard_binding = find_ref(&ingredient, "c2pa.hash.");
        let mut iab = AsyncIdentityAssertionBuilder::for_credential_holder(test_x509_holder());
        iab.test_hooks.signer_payload = Some(Arc::new(move |sp: &mut SignerPayload| {
            for r in sp.referenced_assertions.iter_mut() {
                if r.url().contains("c2pa.assertions/c2pa.hash.") {
                    *r = ingredient_hard_binding.clone();
                }
            }
        }));
        let bytes = sign_asset(vec![iab]).await;
        fixtures.push((
            Fixture::new(
                "identity",
                "hard_binding_incorrect",
                "References the ingredient manifest's hard binding instead of its own claim's. The reference resolves, so the defect is the hard binding, not a mismatch.",
            )
            .spec("Identity 1.3 §5.1.1, §7.1 step 4, §7.2")
            .fails_with(&["cawg.identity.hard_binding_incorrect"]),
            bytes,
        ));
    }

    // ---- X.509 signatures (§8.2) -----------------------------------------

    {
        let holder = TamperingX509Holder {
            inner: test_x509_holder(),
            tamper: corrupt_signature(),
        };
        let bytes = sign_asset(vec![AsyncIdentityAssertionBuilder::for_credential_holder(
            holder,
        )])
        .await;
        fixtures.push((
            Fixture::new(
                "x509",
                "signature_mismatch",
                "X.509 identity signature with one bit flipped, so it does not verify.",
            )
            .spec("Identity 1.3 §8.2.2")
            .fails_with(&["cawg.x509.signature.mismatch"]),
            bytes,
        ));
    }

    {
        let holder = TamperingX509Holder {
            inner: test_x509_holder(),
            tamper: set_unsupported_algorithm(),
        };
        let bytes = sign_asset(vec![AsyncIdentityAssertionBuilder::for_credential_holder(
            holder,
        )])
        .await;
        fixtures.push((
            Fixture::new(
                "x509",
                "algorithm_unsupported",
                "X.509 identity signature whose protected alg header is RS256, which C2PA §13.2 does not allow.",
            )
            .spec("Identity 1.3 §8.2.2")
            .fails_with(&["cawg.x509.algorithm.unsupported"]),
            bytes,
        ));
    }

    {
        let chain = cert_chain_pem_to_der(EXPIRED_CERT).unwrap();
        let holder = x509_holder_from(chain, EXPIRED_KEY, SigningAlg::Ps256);
        let bytes = sign_asset(vec![AsyncIdentityAssertionBuilder::for_credential_holder(
            holder,
        )])
        .await;
        fixtures.push((
            Fixture::new(
                "x509",
                "outside_validity",
                "X.509 identity signature from a certificate that expired in 2022, with no time stamp.",
            )
            .spec("Identity 1.3 §8.2.2")
            .fails_with(&["cawg.x509.signature.outside_validity"]),
            bytes,
        ));
    }

    // Trust-model cases use freshly minted chains. Only `trusted_root` is
    // exported (to x509/trust_anchor.pem) for validators to trust.
    let trusted_root = TestCa::new("CAWG Test Suite Trusted Root");
    let untrusted_root = TestCa::new("CAWG Test Suite Untrusted Root");

    let trust_cases: [TrustCase<'_>; 4] = [
        (
            "Leaf",
            &untrusted_root,
            Eku::EmailProtection,
            Some(POLICY_SMIME_ORG_MULTIPURPOSE),
            Fixture::new(
                "x509",
                "untrusted_chain",
                "X.509 identity certificate that chains to a root no validator trusts.",
            )
            .spec("Identity 1.3 §8.2.2")
            .fails_with(&["cawg.x509.credential.untrusted"]),
        ),
        (
            "Interim Trusted Leaf",
            &trusted_root,
            Eku::EmailProtection,
            Some(POLICY_SMIME_ORG_MULTIPURPOSE),
            Fixture::new(
                "x509",
                "interim_trusted",
                "Meets the interim trust model: id-kp-emailProtection plus the S/MIME organization-validated multipurpose policy, chained to x509/trust_anchor.pem.",
            )
            .spec("Identity 1.3 §8.2.4 (interim, valid until 31 March 2027)")
            .reports_any(&["cawg.x509.credential.trusted"])
            .requires("x509/trust_anchor.pem configured as a CAWG trust anchor; validation on or before 2027-03-31"),
        ),
        (
            "Mailbox Policy Leaf",
            &trusted_root,
            Eku::EmailProtection,
            Some(POLICY_SMIME_MAILBOX_MULTIPURPOSE),
            Fixture::new(
                "x509",
                "interim_mailbox_policy",
                "id-kp-emailProtection with the mailbox-validated policy, which the interim trust model excludes.",
            )
            .spec("Identity 1.3 §8.2.4 (interim)")
            .fails_with(&["cawg.x509.credential.untrusted"])
            .requires("x509/trust_anchor.pem configured as a CAWG trust anchor; validation on or before 2027-03-31"),
        ),
        (
            "Document Signing Leaf",
            &trusted_root,
            Eku::DocumentSigning,
            None,
            Fixture::new(
                "x509",
                "document_signing_eku",
                "id-kp-documentSigning EKU with no certificate policy. The spec says this EKU must be accepted, but it is unclear whether such a certificate counts as trusted.",
            )
            .spec("Identity 1.3 §8.2.4")
            .reports_any(&["cawg.x509.credential.trusted", "cawg.x509.credential.untrusted"])
            .requires("x509/trust_anchor.pem configured as a CAWG trust anchor"),
        ),
    ];

    for (cn, ca, eku, policy, fixture) in trust_cases {
        let leaf = ca.issue_leaf(cn, eku, policy);
        let holder = x509_holder_from(
            leaf.cert_chain_der,
            &leaf.private_key_pem,
            SigningAlg::Es256,
        );
        let bytes = sign_asset(vec![AsyncIdentityAssertionBuilder::for_credential_holder(
            holder,
        )])
        .await;
        fixtures.push((fixture, bytes));
    }

    std::fs::create_dir_all(out.join("x509")).unwrap();
    std::fs::write(out.join("x509/trust_anchor.pem"), trusted_root.root_pem()).unwrap();

    // ---- Identity claims aggregation (§8.1) ------------------------------

    let ica_cases: Vec<(Fixture, Option<holders::VcMutation>)> = vec![
        (
            Fixture::new(
                "ica",
                "credential_visible_valid",
                "Valid ICA credential with no x5chain header, so crJSON writers can show the verifiable credential.",
            )
            .spec("Identity 1.3 §8.1")
            .reports_any(&["cawg.ica.credential_valid"])
            .requires("did:jwk issuer trusted (see c2pa-rs ICA_FIXTURE_JWK_ISSUER); otherwise cawg.ica.untrusted_issuer"),
            None,
        ),
        (
            Fixture::new(
                "ica",
                "verified_identities_empty",
                "credentialSubject.verifiedIdentities is an empty array.",
            )
            .spec("Identity 1.3 §8.1.2.5, §8.1.5")
            .fails_with(&["cawg.ica.verified_identities.missing"]),
            Some(Arc::new(|vc: &mut Value| {
                set_subject_field(vc, "verifiedIdentities", json!([]));
            })),
        ),
        (
            Fixture::new(
                "ica",
                "verified_identity_missing_provider_name",
                "A verified identity whose provider has no name.",
            )
            .spec("Identity 1.3 §8.1.2.5, §8.1.5")
            .fails_with(&["cawg.ica.verified_identities.invalid"]),
            Some(Arc::new(|vc: &mut Value| {
                if let Some(vi) = verified_identities_mut(vc).into_iter().next() {
                    if let Some(provider) = vi.get_mut("provider").and_then(Value::as_object_mut) {
                        provider.remove("name");
                    }
                }
            })),
        ),
        (
            Fixture::new(
                "ica",
                "crypto_wallet_missing_address",
                "The CAWG specification's own example identities: a cawg.crypto_wallet entry with username and no address.",
            )
            .spec("Identity 1.3 §8.1.2.5, §8.1.5")
            .fails_with(&["cawg.ica.verified_identities.invalid"]),
            Some(Arc::new(|vc: &mut Value| {
                for vi in verified_identities_mut(vc) {
                    if vi.get("type").and_then(Value::as_str) == Some("cawg.crypto_wallet") {
                        if let Some(obj) = vi.as_object_mut() {
                            obj.remove("address");
                            obj.insert("username".to_owned(), json!("username"));
                        }
                    }
                }
            })),
        ),
        (
            Fixture::new(
                "ica",
                "revocation_unsupported",
                "credentialStatus uses a status method no validator supports.",
            )
            .spec("Identity 1.3 §8.1.5")
            .reports_any(&["cawg.ica.revocation.unsupported"]),
            Some(Arc::new(|vc: &mut Value| {
                if let Some(obj) = vc.as_object_mut() {
                    obj.insert(
                        "credentialStatus".to_owned(),
                        json!({
                            "id": "https://example.com/status/unsupported#1",
                            "type": "ExampleUnsupportedStatusMethod",
                            "statusPurpose": "revocation"
                        }),
                    );
                }
            })),
        ),
    ];

    for (fixture, mutation) in ica_cases {
        let mut holder = test_ica_holder();
        if let Some(m) = mutation {
            holder = holder.with_vc_mutation(m);
        }
        let bytes = sign_asset(vec![AsyncIdentityAssertionBuilder::for_credential_holder(
            holder,
        )])
        .await;
        fixtures.push((fixture, bytes));
    }

    // ---- Write everything ------------------------------------------------

    let mut index = vec![];
    println!("\nCAWG conformance fixtures -> {}\n", out.display());
    for (fixture, bytes) in &fixtures {
        write(&out, fixture, bytes);
        let codes = cawg_codes(bytes).await;
        println!("{:<48} c2pa-rs: {}", fixture.path(), codes.join(", "));
        index.push(json!({
            "asset": fixture.path(),
            "description": fixture.description,
            "spec": fixture.spec,
            "expect_failure": fixture.expect_failure,
            "expect_any": fixture.expect_any,
            "requires": fixture.requires,
            "c2pa_rs_codes": codes,
        }));
    }
    let index = json!({
        "generator": "c2pa-rs identity::tests::conformance_fixtures",
        "fixtures": index,
    });
    std::fs::write(
        out.join("index.json"),
        serde_json::to_string_pretty(&index).unwrap() + "\n",
    )
    .unwrap();
    println!("\nWrote {} fixtures and index.json", fixtures.len());
}

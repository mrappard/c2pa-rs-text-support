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

//! Test-quality credential holders used to generate conformance fixtures.
//!
//! These deliberately produce both valid and invalid signatures. They are not
//! suitable for production use.

use std::sync::Arc;

use async_trait::async_trait;
use c2pa_raw_crypto::RawSigner;
use chrono::Utc;
use coset::{
    iana::{self, EnumI64},
    CoseSign1, CoseSign1Builder, HeaderBuilder, RegisteredLabelWithPrivate, TaggedCborSerializable,
};
use iref::UriBuf;
use nonempty_collections::nev;
use serde_json::Value;

use crate::{
    identity::{
        builder::{AsyncCredentialHolder, IdentityBuilderError},
        claim_aggregation::{IcaCredential, IdentityClaimsAggregationVc},
        tests::fixtures::claim_aggregation::ica_credential_example::ica_example_identities,
        x509::AsyncX509CredentialHolder,
        SignerPayload,
    },
    HashedUri,
};

/// Edits applied to a COSE_Sign1 produced by a wrapped credential holder.
pub(crate) type CoseTamper = Arc<dyn Fn(&mut CoseSign1) + Send + Sync>;

/// Wraps [`AsyncX509CredentialHolder`] and edits the COSE signature it
/// produces (for example to corrupt the signature or change the algorithm).
pub(crate) struct TamperingX509Holder {
    pub(crate) inner: AsyncX509CredentialHolder,
    pub(crate) tamper: CoseTamper,
}

#[async_trait]
impl AsyncCredentialHolder for TamperingX509Holder {
    fn sig_type(&self) -> &'static str {
        self.inner.sig_type()
    }

    fn reserve_size(&self) -> usize {
        // Header edits can grow the COSE structure by a few bytes.
        self.inner.reserve_size() + 64
    }

    async fn sign(&self, signer_payload: &SignerPayload) -> Result<Vec<u8>, IdentityBuilderError> {
        let signed = self.inner.sign(signer_payload).await?;
        let mut sign1 = CoseSign1::from_tagged_slice(&signed)
            .map_err(|e| IdentityBuilderError::SignerError(e.to_string()))?;
        (self.tamper)(&mut sign1);
        sign1
            .to_tagged_vec()
            .map_err(|e| IdentityBuilderError::SignerError(e.to_string()))
    }
}

/// Flip one bit of the signature so it no longer verifies.
pub(crate) fn corrupt_signature() -> CoseTamper {
    Arc::new(|sign1: &mut CoseSign1| {
        if let Some(last) = sign1.signature.last_mut() {
            *last ^= 0x01;
        }
    })
}

/// Replace the protected `alg` header with an algorithm C2PA does not allow.
pub(crate) fn set_unsupported_algorithm() -> CoseTamper {
    Arc::new(|sign1: &mut CoseSign1| {
        sign1.protected.original_data = None;
        sign1.protected.header.alg =
            Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::RS256));
    })
}

/// Edits applied to the ICA verifiable credential (as JSON) before signing.
pub(crate) type VcMutation = Arc<dyn Fn(&mut Value) + Send + Sync>;

/// An identity claims aggregation credential holder that issues a
/// verifiable credential for the CAWG specification's example identities.
///
/// The COSE envelope is built directly with `coset` so that test cases can
/// control exactly which headers are present. By default no `x5chain` header
/// is included, which matches how ICA credentials are resolved (via the
/// issuer's DID document) and lets crJSON writers show the credential.
pub(crate) struct IcaFixtureHolder {
    pub(crate) signer: Box<dyn RawSigner + Send + Sync + 'static>,
    pub(crate) issuer: String,
    pub(crate) x5chain: Option<Vec<Vec<u8>>>,
    pub(crate) mutate_vc: Option<VcMutation>,
}

impl IcaFixtureHolder {
    pub(crate) fn new(signer: Box<dyn RawSigner + Send + Sync + 'static>, issuer: &str) -> Self {
        Self {
            signer,
            issuer: issuer.to_owned(),
            x5chain: None,
            mutate_vc: None,
        }
    }

    pub(crate) fn with_vc_mutation(mut self, mutation: VcMutation) -> Self {
        self.mutate_vc = Some(mutation);
        self
    }

    fn credential_json(
        &self,
        signer_payload: &SignerPayload,
    ) -> Result<Value, IdentityBuilderError> {
        // ICA §8.1.2: c2paAsset is the JSON form of signer_payload with byte
        // strings encoded as standard base64.
        let mut c2pa_asset = signer_payload.clone();
        c2pa_asset.referenced_assertions = signer_payload
            .referenced_assertions
            .iter()
            .map(|a| {
                let encoded = crate::crypto::base64::encode(&a.hash());
                HashedUri::new(a.url(), a.alg(), encoded.as_bytes())
            })
            .collect();

        let subject = IdentityClaimsAggregationVc {
            c2pa_asset,
            verified_identities: ica_example_identities(),
            time_stamp: None,
        };

        let issuer = UriBuf::new(self.issuer.as_bytes().to_vec())
            .map_err(|e| IdentityBuilderError::SignerError(format!("invalid issuer: {e:?}")))?;
        let mut vc = IcaCredential::new(None, issuer, nev![subject]);
        vc.valid_from = Some(Utc::now().fixed_offset());

        let mut json = serde_json::to_value(&vc)
            .map_err(|e| IdentityBuilderError::CborGenerationError(e.to_string()))?;

        // The CAWG example identities carry a cawg.crypto_wallet entry with
        // `username` but no `address`, which the specification forbids. Fix it
        // here so the default credential is valid; test cases that want the
        // original example re-introduce the defect via `mutate_vc`.
        fix_crypto_wallet_entries(&mut json);

        if let Some(mutate) = &self.mutate_vc {
            mutate(&mut json);
        }
        Ok(json)
    }
}

/// Give every `cawg.crypto_wallet` verified identity an `address` (and drop
/// its `username`), as ICA §8.1.2.5 requires.
pub(crate) fn fix_crypto_wallet_entries(vc: &mut Value) {
    for vi in verified_identities_mut(vc) {
        if vi.get("type").and_then(Value::as_str) == Some("cawg.crypto_wallet") {
            if let Some(obj) = vi.as_object_mut() {
                obj.remove("username");
                obj.insert(
                    "address".to_owned(),
                    Value::String("fa64ef445f994138bdeb9baac6ce1e16".to_owned()),
                );
                obj.insert(
                    "uri".to_owned(),
                    Value::String(
                        "https://example-crypto-wallet.com/fa64ef445f994138bdeb9baac6ce1e16"
                            .to_owned(),
                    ),
                );
            }
        }
    }
}

/// Mutable access to `credentialSubject.verifiedIdentities[*]`.
pub(crate) fn verified_identities_mut(vc: &mut Value) -> Vec<&mut Value> {
    let subject = match vc.get_mut("credentialSubject") {
        Some(Value::Array(subjects)) => subjects.first_mut(),
        Some(subject @ Value::Object(_)) => Some(subject),
        _ => None,
    };
    match subject.and_then(|s| s.get_mut("verifiedIdentities")) {
        Some(Value::Array(list)) => list.iter_mut().collect(),
        _ => vec![],
    }
}

/// Set `credentialSubject.<key>` to `value`.
pub(crate) fn set_subject_field(vc: &mut Value, key: &str, value: Value) {
    let subject = match vc.get_mut("credentialSubject") {
        Some(Value::Array(subjects)) => subjects.first_mut(),
        Some(subject @ Value::Object(_)) => Some(subject),
        _ => None,
    };
    if let Some(Value::Object(obj)) = subject {
        obj.insert(key.to_owned(), value);
    }
}

#[async_trait]
impl AsyncCredentialHolder for IcaFixtureHolder {
    fn sig_type(&self) -> &'static str {
        crate::identity::claim_aggregation::CAWG_ICA_SIG_TYPE
    }

    fn reserve_size(&self) -> usize {
        let chain: usize = self.x5chain.iter().flatten().map(Vec::len).sum();
        self.signer.max_signature_size() + chain + 6000
    }

    async fn sign(&self, signer_payload: &SignerPayload) -> Result<Vec<u8>, IdentityBuilderError> {
        let vc = self.credential_json(signer_payload)?;
        let payload = serde_json::to_vec(&vc)
            .map_err(|e| IdentityBuilderError::CborGenerationError(e.to_string()))?;

        let alg = match self.signer.alg() {
            crate::SigningAlg::Ed25519 => iana::Algorithm::EdDSA,
            crate::SigningAlg::Es256 => iana::Algorithm::ES256,
            crate::SigningAlg::Es384 => iana::Algorithm::ES384,
            crate::SigningAlg::Es512 => iana::Algorithm::ES512,
            crate::SigningAlg::Ps256 => iana::Algorithm::PS256,
            crate::SigningAlg::Ps384 => iana::Algorithm::PS384,
            crate::SigningAlg::Ps512 => iana::Algorithm::PS512,
            other => {
                return Err(IdentityBuilderError::SignerError(format!(
                    "unsupported ICA signing algorithm {other}"
                )))
            }
        };

        let mut protected = HeaderBuilder::new()
            .algorithm(alg)
            .content_type("application/vc".to_owned());
        if let Some(chain) = &self.x5chain {
            protected = protected.value(
                iana::HeaderParameter::X5Chain.to_i64(),
                coset::cbor::value::Value::Array(
                    chain
                        .iter()
                        .cloned()
                        .map(coset::cbor::value::Value::Bytes)
                        .collect(),
                ),
            );
        }

        let mut sign_error = None;
        let sign1 = CoseSign1Builder::new()
            .protected(protected.build())
            .payload(payload)
            .create_signature(b"", |data| match self.signer.sign(data) {
                Ok(sig) => sig,
                Err(e) => {
                    sign_error = Some(e.to_string());
                    vec![]
                }
            })
            .build();
        if let Some(e) = sign_error {
            return Err(IdentityBuilderError::SignerError(e));
        }

        sign1
            .to_tagged_vec()
            .map_err(|e| IdentityBuilderError::SignerError(e.to_string()))
    }
}

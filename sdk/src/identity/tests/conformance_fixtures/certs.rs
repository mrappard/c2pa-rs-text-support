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

//! Mints throwaway X.509 certificate chains for CAWG trust-model fixtures.
//!
//! Each call to [`TestCa::new`] creates a fresh self-signed root. Fixtures
//! that should be trusted are issued by a root whose PEM is written next to
//! the fixtures so a validator can be configured to trust it; fixtures that
//! should be untrusted are issued by a root that is never exported.

use openssl::{
    asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time},
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectKeyIdentifier,
        },
        X509Builder, X509Extension, X509NameBuilder, X509,
    },
};

/// OID for `id-kp-documentSigning` (RFC 9336).
pub(crate) const EKU_DOCUMENT_SIGNING: &str = "1.3.6.1.5.5.7.3.36";

/// CA/Browser Forum S/MIME "Organization-validated Multipurpose" policy OID,
/// one of the policies accepted by the CAWG interim trust model.
pub(crate) const POLICY_SMIME_ORG_MULTIPURPOSE: &str = "2.23.140.1.5.2.2";

/// CA/Browser Forum S/MIME "Mailbox-validated Multipurpose" policy OID, which
/// the CAWG interim trust model does not accept.
pub(crate) const POLICY_SMIME_MAILBOX_MULTIPURPOSE: &str = "2.23.140.1.5.1.2";

/// What extended key usage to put in a leaf certificate.
pub(crate) enum Eku {
    EmailProtection,
    DocumentSigning,
}

pub(crate) struct TestCa {
    key: PKey<Private>,
    cert: X509,
}

pub(crate) struct LeafCredential {
    /// End-entity certificate in DER form (the `x5chain` to sign with).
    pub(crate) cert_chain_der: Vec<Vec<u8>>,
    /// PKCS#8 private key in PEM form.
    pub(crate) private_key_pem: Vec<u8>,
}

/// DER-encode an OBJECT IDENTIFIER (tag, length, value).
fn der_oid(oid: &str) -> Vec<u8> {
    let arcs: Vec<u64> = oid.split('.').map(|a| a.parse().unwrap()).collect();
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut chunk = vec![(arc & 0x7f) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            chunk.push(((rest & 0x7f) as u8) | 0x80);
            rest >>= 7;
        }
        chunk.reverse();
        body.extend(chunk);
    }
    let mut der = vec![0x06, body.len() as u8];
    der.extend(body);
    der
}

fn der_sequence(content: Vec<u8>) -> Vec<u8> {
    let mut der = vec![0x30, content.len() as u8];
    der.extend(content);
    der
}

/// certificatePolicies extension with a single policy OID (no qualifiers).
/// Built from DER because OpenSSL's text form needs a config database.
fn certificate_policies(policy_oid: &str) -> X509Extension {
    let value = der_sequence(der_sequence(der_oid(policy_oid)));
    let ext_oid = Asn1Object::from_str("2.5.29.32").unwrap();
    let octets = Asn1OctetString::new_from_bytes(&value).unwrap();
    X509Extension::new_from_der(&ext_oid, false, &octets).unwrap()
}

fn new_key() -> PKey<Private> {
    #[allow(clippy::unwrap_used)]
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    #[allow(clippy::unwrap_used)]
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn serial() -> Asn1Integer {
    let mut bn = BigNum::new().unwrap();
    bn.rand(126, MsbOption::MAYBE_ZERO, false).unwrap();
    bn.to_asn1_integer().unwrap()
}

#[allow(clippy::unwrap_used)]
impl TestCa {
    pub(crate) fn new(common_name: &str) -> Self {
        let key = new_key();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("O", "CAWG Test Suite (FOR TESTING ONLY)")
            .unwrap();
        name.append_entry_by_text("CN", common_name).unwrap();
        let name = name.build();

        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&serial()).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(3650).unwrap())
            .unwrap();
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        b.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
        let ski = SubjectKeyIdentifier::new()
            .build(&b.x509v3_context(None, None))
            .unwrap();
        b.append_extension(ski).unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();

        Self {
            key,
            cert: b.build(),
        }
    }

    pub(crate) fn root_pem(&self) -> Vec<u8> {
        self.cert.to_pem().unwrap()
    }

    /// Issue an end-entity signing certificate.
    pub(crate) fn issue_leaf(
        &self,
        common_name: &str,
        eku: Eku,
        policy_oid: Option<&str>,
    ) -> LeafCredential {
        let key = new_key();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("O", "CAWG Test Suite Named Actor")
            .unwrap();
        name.append_entry_by_text("CN", common_name).unwrap();
        let name = name.build();

        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&serial()).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(self.cert.subject_name()).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1825).unwrap())
            .unwrap();
        b.append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        b.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
        let eku_ext = match eku {
            Eku::EmailProtection => ExtendedKeyUsage::new().email_protection().build(),
            Eku::DocumentSigning => ExtendedKeyUsage::new().other(EKU_DOCUMENT_SIGNING).build(),
        }
        .unwrap();
        b.append_extension(eku_ext).unwrap();
        if let Some(oid) = policy_oid {
            b.append_extension(certificate_policies(oid)).unwrap();
        }
        let ski = SubjectKeyIdentifier::new()
            .build(&b.x509v3_context(Some(&self.cert), None))
            .unwrap();
        b.append_extension(ski).unwrap();
        let aki = AuthorityKeyIdentifier::new()
            .keyid(false)
            .build(&b.x509v3_context(Some(&self.cert), None))
            .unwrap();
        b.append_extension(aki).unwrap();
        b.sign(&self.key, MessageDigest::sha256()).unwrap();

        LeafCredential {
            cert_chain_der: vec![b.build().to_der().unwrap()],
            private_key_pem: key.private_key_to_pem_pkcs8().unwrap(),
        }
    }
}

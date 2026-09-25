// End-to-end signing and validation of the C2PA 2.4 text embeddings: HTML (§A.7),
// unstructured text (§A.8) and structured text (§A.9).
#![cfg(feature = "spec_2_4_text")]
use std::io::Cursor;

use c2pa::{create_signer, Builder, Context, Reader, SigningAlg, ValidationState};
use serde_json::json;

const SIGNCERT: &[u8] = include_bytes!("fixtures/certs/es256.pub");
const PKEY: &[u8] = include_bytes!("fixtures/certs/es256.pem");

const HTML_DOC: &str = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Example</title>\n</head>\n<body>\n<p>Content here.</p>\n</body>\n</html>\n";

fn sign(format: &str, content: &[u8], no_embed: bool) -> Vec<u8> {
    let mut builder = Builder::from_context(Context::new())
        .with_definition(json!({
            "claim_generator_info": [{ "name": "text-2.4-test" }],
            "title": "text asset",
            "assertions": [
                { "label": "c2pa.actions", "data": { "actions": [
                    { "action": "c2pa.created", "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation" }
                ] } }
            ]
        }))
        .unwrap();
    builder.set_no_embed(no_embed);
    let signer = create_signer::from_keys(SIGNCERT, PKEY, SigningAlg::Es256, None).unwrap();
    let mut dest = Cursor::new(Vec::new());
    builder
        .sign(
            signer.as_ref(),
            format,
            &mut Cursor::new(content.to_vec()),
            &mut dest,
        )
        .unwrap_or_else(|e| panic!("signing {format} should succeed: {e:?}"));
    dest.into_inner()
}

fn read(format: &str, asset: &[u8]) -> Reader {
    Reader::from_context(Context::new())
        .with_stream(format, Cursor::new(asset.to_vec()))
        .unwrap_or_else(|e| panic!("reading {format} should succeed: {e:?}"))
}

fn assert_valid(format: &str, asset: &[u8]) {
    let reader = read(format, asset);
    let crjson = reader.crjson();
    assert_ne!(
        reader.validation_state(),
        ValidationState::Invalid,
        "{crjson}"
    );
    assert!(crjson.contains("assertion.dataHash.match"), "{crjson}");
}

fn assert_mismatch(format: &str, asset: &[u8]) {
    let reader = read(format, asset);
    let crjson = reader.crjson();
    assert_eq!(
        reader.validation_state(),
        ValidationState::Invalid,
        "{crjson}"
    );
    assert!(crjson.contains("assertion.dataHash.mismatch"), "{crjson}");
}

/// Replaces the first occurrence of `from` in `asset` with `to` (same length).
fn tamper(asset: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let pos = asset
        .windows(from.len())
        .position(|w| w == from)
        .expect("text to tamper with");
    let mut out = asset.to_vec();
    out[pos..pos + to.len()].copy_from_slice(to);
    out
}

#[test]
fn unstructured_text_signs_and_validates() {
    for format in ["txt", "text/plain", "csv", "tsv"] {
        let signed = sign(format, b"Hello, world.\nSecond line.\n", false);
        assert!(signed.starts_with("Hello, world.\nSecond line.\n\u{FEFF}".as_bytes()));
        assert_valid(format, &signed);
    }
}

#[test]
fn unstructured_text_is_signed_as_nfc() {
    let signed = sign("txt", "cafe\u{0301} au lait\n".as_bytes(), false);
    assert!(signed.starts_with("caf\u{00E9} au lait\n".as_bytes()));
    assert_valid("txt", &signed);
}

#[test]
fn unstructured_text_tampering_is_detected() {
    let signed = sign("txt", b"The quick brown fox.\n", false);
    assert_mismatch("txt", &tamper(&signed, b"quick", b"quack"));
}

#[test]
fn unstructured_text_resign_replaces_wrapper() {
    let once = sign("txt", b"Draft text.\n", false);
    let twice = sign("txt", &once, false);
    assert_eq!(
        twice
            .windows(3)
            .filter(|w| *w == [0xEF, 0xBB, 0xBF])
            .count(),
        1
    );
    assert_valid("txt", &twice);
}

#[test]
fn unstructured_text_no_embed_hashes_whole_text() {
    let signed = sign("txt", b"Sidecar text.\n", true);
    assert_eq!(signed, b"Sidecar text.\n");
}

#[test]
fn html_signs_and_validates() {
    for format in ["html", "text/html"] {
        let signed = sign(format, HTML_DOC.as_bytes(), false);
        let text = String::from_utf8(signed.clone()).unwrap();
        let script = text
            .find("<script type=\"application/c2pa\">")
            .expect("script element");
        assert!(script < text.find("</head>").unwrap());
        assert_valid(format, &signed);
    }
}

#[test]
fn html_tampering_is_detected() {
    let signed = sign("html", HTML_DOC.as_bytes(), false);
    assert_mismatch("html", &tamper(&signed, b"Content here.", b"Content HERE."));
}

#[test]
fn html_multiple_manifests_rejected() {
    let signed = String::from_utf8(sign("html", HTML_DOC.as_bytes(), false)).unwrap();
    let doubled = signed.replace(
        "</head>",
        "<link rel=\"c2pa-manifest\" href=\"https://example.com/a.c2pa\"></head>",
    );
    let result =
        Reader::from_context(Context::new()).with_stream("html", Cursor::new(doubled.into_bytes()));
    let err = result.expect_err("two manifest elements must be rejected");
    assert!(
        format!("{err:?}").contains("manifest.html.multipleManifests"),
        "{err:?}"
    );
}

#[test]
fn structured_text_signs_and_validates() {
    let signed = sign("md", b"# Title\n\nSome markdown.\n", false);
    assert!(signed.starts_with(b"<!-- -----BEGIN C2PA MANIFEST----- data:application/c2pa;base64,"));
    assert_valid("md", &signed);
    assert_mismatch("md", &tamper(&signed, b"Some markdown.", b"Some MARKDOWN."));
}

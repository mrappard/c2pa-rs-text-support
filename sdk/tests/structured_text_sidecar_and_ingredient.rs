// Regression coverage for two bugs found while signing jsonc/md assets outside the
// embed-into-file path:
//
// 1. `no_embed` (sidecar) signing of a structured-text asset failed with `JumbfNotFound`.
//    `Builder::sign` strips the placeholder manifest block from the source before
//    computing hash-object positions for a no-embed sign, and
//    `StructuredTextIdIO::get_object_locations_from_stream` treated "no manifest marker
//    present" as an error instead of "nothing to exclude, hash the whole stream" — which
//    is the normal state for a no-embed asset. Fixed in
//    `asset_handlers/structured_text_id.rs`.
//
// 2. A structured-text asset that already carries a real (non-placeholder) manifest could
//    be read back on its own via `Reader`, but failed with the same `JumbfNotFound` when
//    added as a parent ingredient to a *different* Builder via `add_ingredient_from_stream`
//    — because the caller (the JS wasm bindings) signed the ingredient's source asset
//    without first pre-embedding the placeholder block that `Builder::sign` requires for
//    structured-text formats. Fixed at the call-site layer (the TS wrapper now runs every
//    structured-text asset through `prepareAsset` before signing, not just `signAsset`).
//    This file exercises the underlying Rust API directly, matching what the TS layer
//    now does.
use std::io::Cursor;

use c2pa_rs_text_support::{create_signer, Builder, Context, Reader, SigningAlg, ValidationState};
use serde_json::json;

const SIGNCERT: &[u8] = include_bytes!("../../cli/sample/es256_certs.pem");
const PKEY: &[u8] = include_bytes!("../../cli/sample/es256_private.key");

// Matches the placeholder block the JS wrapper's `ensureJsoncManifestPlaceholder` (and
// its md/xml equivalents) pre-embeds before handing a structured-text asset to `Builder::sign`.
const PLACEHOLDER: &[u8] =
    b"// -----BEGIN C2PA MANIFEST----- data:application/c2pa;base64, -----END C2PA MANIFEST-----\n";

fn manifest_def(title: &str) -> serde_json::Value {
    json!({
        "claim_generator_info": [{ "name": "repro" }],
        "title": title,
        "assertions": [
            { "label": "c2pa.actions", "data": { "actions": [
                { "action": "c2pa.created", "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture" }
            ] } }
        ]
    })
}

fn placeholder_prefixed_payload(json_body: &[u8]) -> Vec<u8> {
    let mut payload = PLACEHOLDER.to_vec();
    payload.extend_from_slice(json_body);
    payload
}

fn sign_jsonc(title: &str, json_body: &[u8]) -> Vec<u8> {
    let context = Context::new();
    let mut builder = Builder::from_context(context)
        .with_definition(manifest_def(title))
        .unwrap();
    let signer = create_signer::from_keys(SIGNCERT, PKEY, SigningAlg::Es256, None).unwrap();
    let mut source = Cursor::new(placeholder_prefixed_payload(json_body));
    let mut dest = Cursor::new(Vec::new());
    builder
        .sign(signer.as_ref(), "jsonc", &mut source, &mut dest)
        .expect("embed sign of a placeholder-prefixed jsonc asset should succeed");
    dest.into_inner()
}

#[test]
fn sidecar_no_embed_sign_succeeds() {
    let context = Context::new();
    let mut builder = Builder::from_context(context)
        .with_definition(manifest_def("governance-0"))
        .unwrap();
    builder.set_no_embed(true);
    let signer = create_signer::from_keys(SIGNCERT, PKEY, SigningAlg::Es256, None).unwrap();
    let mut source = Cursor::new(placeholder_prefixed_payload(
        br#"{"action":"genesis","writer":"urn:org:acme:writer"}"#,
    ));
    let mut dest = Cursor::new(Vec::new());

    let result = builder.sign(signer.as_ref(), "jsonc", &mut source, &mut dest);

    assert!(
        result.is_ok(),
        "no_embed (sidecar) sign of a jsonc asset should succeed: {result:?}"
    );
}

#[test]
fn signed_structured_text_verifies_standalone() {
    let line0 = sign_jsonc(
        "governance-0",
        br#"{"action":"genesis","writer":"urn:org:acme:writer"}"#,
    );
    let context = Context::new();
    let reader = Reader::from_context(context)
        .with_stream("jsonc", Cursor::new(line0))
        .expect("verifying a freshly signed jsonc asset should succeed");
    assert_ne!(reader.validation_state(), ValidationState::Invalid);
}

#[test]
fn signed_structured_text_usable_as_parent_ingredient_sync() {
    let line0 = sign_jsonc(
        "governance-0",
        br#"{"action":"genesis","writer":"urn:org:acme:writer"}"#,
    );
    let context = Context::new();
    let mut builder = Builder::from_context(context)
        .with_definition(manifest_def("block-1"))
        .unwrap();

    let ingredient_json = json!({ "title": "governance-0", "relationship": "parentOf" }).to_string();
    let result = builder.add_ingredient_from_stream(ingredient_json, "jsonc", &mut Cursor::new(line0));

    assert!(
        result.is_ok(),
        "a signed jsonc asset should be usable as a parent ingredient: {result:?}"
    );
}

#[tokio::test]
async fn signed_structured_text_usable_as_parent_ingredient_async() {
    let line0 = sign_jsonc(
        "governance-0",
        br#"{"action":"genesis","writer":"urn:org:acme:writer"}"#,
    );
    let context = Context::new();
    let mut builder = Builder::from_context(context)
        .with_definition(manifest_def("block-1"))
        .unwrap();

    let ingredient_json = json!({ "title": "governance-0", "relationship": "parentOf" }).to_string();
    let result = builder
        .add_ingredient_from_stream_async(ingredient_json, "jsonc", &mut Cursor::new(line0))
        .await;

    assert!(
        result.is_ok(),
        "a signed jsonc asset should be usable as a parent ingredient (async): {result:?}"
    );
}

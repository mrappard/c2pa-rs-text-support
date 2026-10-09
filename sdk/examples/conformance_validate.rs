// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license.
//! Produce unmodified reader validation results for one conformance case.

use anyhow::{Context as _, Result};
use c2pa::{Context, Reader};
use serde_json::{json, Value};

fn codes(status: &c2pa::validation_results::StatusCodes) -> Value {
    let list = |items: &[c2pa::validation_status::ValidationStatus]| {
        items
            .iter()
            .map(|item| item.code().to_owned())
            .collect::<Vec<_>>()
    };
    json!({"successes": list(status.success()), "informationals": list(status.informational()), "failures": list(status.failure())})
}

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .context("expected case input JSON path")?;
    let input: Value = serde_json::from_reader(std::fs::File::open(path)?)?;
    let settings = json!({
        "trust": {"trust_config": "1.3.6.1.4.1.62558.2.1", "anchors": [
            {"trust_anchors": input["signer"], "trust_kind": "manifest"},
            {"trust_anchors": input["tsa"], "trust_kind": "tsa"}
        ]},
        "verify": {"ocsp_fetch": false, "remote_manifest_fetch": false}
    });
    let context = Context::new().with_settings(settings.to_string().as_str())?;
    let result = match Reader::from_context(context)
        .with_file(input["asset"].as_str().context("asset must be a string")?)
    {
        Err(error) => {
            json!({"readError": error.to_string(), "noManifest": matches!(error, c2pa::Error::JumbfNotFound)})
        }
        Ok(reader) => {
            let results = reader.validation_results();
            let active = results
                .and_then(|results| results.active_manifest())
                .map(codes);
            let ingredients: Vec<Value> = reader.manifests().values().flat_map(|manifest| manifest.ingredients().iter()).map(|ingredient| json!({
                "label": ingredient.active_manifest(),
                "codes": ingredient.validation_results().and_then(|results| results.active_manifest()).map(codes),
            })).collect();
            json!({
                "activeLabel": reader.active_label(), "active": active, "ingredients": ingredients,
                "validationDetails": results,
                "deltas": results.and_then(|results| results.ingredient_deltas()).map(|deltas| deltas.iter().map(|delta| json!({
                    "uri": delta.ingredient_assertion_uri(), "codes": codes(delta.validation_deltas())
                })).collect::<Vec<_>>())
            })
        }
    };
    println!(
        "{}",
        json!({"observedEpoch": chrono::Utc::now().timestamp(), "result": result})
    );
    Ok(())
}

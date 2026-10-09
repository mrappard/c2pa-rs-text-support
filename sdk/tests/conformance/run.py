#!/usr/bin/env python3
"""Evaluate the unmodified conformance YAML expectations against the SDK reader.

Requires PyYAML. On macOS, --clock-dylib supplies the historical wall clock for
one child validator process per case. No expected statuses are filtered or remapped.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile

import yaml


def check_codes(expected, actual, location):
    actual = set(actual or [])
    problems = []
    for rule, value in expected.items():
        wanted = set(value.get("codes", [])) if isinstance(value, dict) else None
        if rule == "isEmpty" and actual:
            problems.append(f"{location}: expected empty, got {sorted(actual)}")
        elif rule == "isNotEmpty" and not actual:
            problems.append(f"{location}: expected nonempty")
        elif rule == "containsExactly" and actual != wanted:
            problems.append(f"{location}: missing {sorted(wanted - actual)}, unexpected {sorted(actual - wanted)}")
        elif rule == "containsAllOf" and not wanted <= actual:
            problems.append(f"{location}: missing {sorted(wanted - actual)}")
        elif rule == "containsNoneOf" and wanted & actual:
            problems.append(f"{location}: forbidden {sorted(wanted & actual)}")
        elif rule == "containsAnyOf":
            for group in value:
                choices = set(group.get("codes", []))
                if not choices & actual:
                    problems.append(f"{location}: expected one of {sorted(choices)}")
        elif rule not in {"isEmpty", "isNotEmpty", "containsExactly", "containsAllOf", "containsNoneOf", "containsAnyOf"}:
            raise ValueError(f"Unknown expectation {rule}")
    return problems


def check_manifest(expected, actual, label, location):
    if actual is None:
        return [f"{location}: no validation results"]
    problems = []
    if "label" in expected and expected["label"] != label:
        problems.append(f"{location}: expected label {expected['label']}, got {label}")
    for category in ("failures", "successes", "informationals"):
        problems.extend(check_codes(expected.get(category, {}), actual.get(category, []), f"{location}.{category}"))
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path, required=True, help="tests/validation directory")
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--clock-dylib", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--spec-version", default="2.4")
    parser.add_argument("--revision", required=True, help="pinned conformance suite commit")
    parser.add_argument("--case", help="optional substring filter for diagnostics")
    args = parser.parse_args()
    rows = []
    with tempfile.TemporaryDirectory(prefix="c2pa-conformance-") as directory:
        input_path = Path(directory) / "input.json"
        for path in sorted((args.suite / "tests").rglob("*.yaml")):
            name = path.relative_to(args.suite / "tests").as_posix()
            if args.case and args.case not in name:
                continue
            case = yaml.safe_load(path.read_text())
            versions = case.get("validatorSpecVersions", [])
            if versions and args.spec_version not in versions:
                rows.append({"name": name, "outcome": "not_applicable", "description": case["description"]})
                continue
            inputs = case["inputs"]
            epoch = int(datetime.datetime.fromisoformat(inputs["validationTime"].replace("Z", "+00:00")).timestamp())
            request = {
                "asset": str((args.suite / inputs["assetPath"]).resolve()),
                "signer": "\n".join((args.suite / p).read_text() for p in inputs["claimSignerTrustListPaths"]),
                "tsa": "\n".join((args.suite / p).read_text() for p in inputs["tsaTrustListPaths"]),
            }
            input_path.write_text(json.dumps(request))
            env = os.environ.copy()
            if args.clock_dylib:
                if platform.system() != "Darwin":
                    raise RuntimeError("clock_macos.c interposer is macOS-only")
                env["DYLD_INSERT_LIBRARIES"] = str(args.clock_dylib.resolve())
                env["C2PA_CONFORMANCE_EPOCH"] = str(epoch)
            issues = []
            observed = None
            try:
                child = subprocess.run([str(args.binary.resolve()), str(input_path)], env=env, text=True, capture_output=True, timeout=30)
                if child.returncode:
                    raise RuntimeError(f"validator exited {child.returncode}: {child.stderr.strip()}")
                observed = json.loads(child.stdout)
                result = observed["result"]
                if observed["observedEpoch"] != epoch:
                    issues.append(f"validation clock unavailable: expected epoch {epoch}, observed {observed['observedEpoch']}")
                if "activeManifest" not in case:
                    if not result.get("noManifest") and (result.get("readError") or result.get("active") is not None or result.get("activeLabel") is not None):
                        issues.append("expected no manifest")
                elif "readError" in result:
                    issues.append(f"reader error: {result['readError']}")
                else:
                    issues.extend(check_manifest(case["activeManifest"], result.get("active"), result.get("activeLabel"), "activeManifest"))
                    for ingredient in case.get("ingredientManifests", []):
                        matches = [item for item in result.get("ingredients", []) if item["label"] == ingredient["label"]]
                        if not matches:
                            issues.append(f"ingredient {ingredient['label']}: absent")
                        else:
                            alternatives = [check_manifest(ingredient, item.get("codes"), item["label"], f"ingredient {item['label']}") for item in matches]
                            if all(alternatives):
                                issues.extend(alternatives[0])
            except (RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
                issues.append(str(error))
            row = {"name": name, "description": case["description"], "validationTime": inputs["validationTime"], "outcome": "fail" if issues else "pass", "issues": issues, "observed": observed}
            rows.append(row)
            print(f"{row['outcome'].upper():4} {name}", flush=True)
    summary = {kind: sum(row["outcome"] == kind for row in rows) for kind in ("pass", "fail", "not_applicable")}
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"suiteRevision": args.revision, "specVersion": args.spec_version, "branch": subprocess.check_output(["git", "branch", "--show-current"], text=True).strip(), "sdkCommit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(), "processClock": str(args.clock_dylib) if args.clock_dylib else None, "networkFetch": False, "summary": summary, "cases": rows}
    (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    text = ["# Combined branch conformance results", "", f"Suite revision: `{args.revision}`. Spec version: {args.spec_version}.", f"SDK commit: `{report['sdkCommit']}`; branch `{report['branch']}`.", "", f"**{summary['pass']} passed; {summary['fail']} failed; {summary['not_applicable']} not applicable.**", "", "Every case uses its specified signer/TSA trust anchors and historical validation time. Network fetches are disabled. Original YAML expectations are evaluated without filtering or remapping SDK statuses.", "", "## Remaining failures", ""]
    for row in rows:
        if row["outcome"] == "fail":
            text.extend([f"### {row['name']}", "", row["description"], ""] + [f"- {issue}" for issue in row["issues"]] + [""])
    text.extend(["## All cases", "", "| Case | Result |", "| --- | --- |"] + [f"| `{row['name']}` | {row['outcome']} |" for row in rows])
    (args.output / "REPORT.md").write_text("\n".join(text) + "\n")
    print(json.dumps(summary), flush=True)
    return 1 if summary["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

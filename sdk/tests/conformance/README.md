# Conformance integration runner

This runner evaluates every applicable YAML case in conformance PR #504 against the public SDK reader. It preserves the original expected and actual status codes. The suite is pinned to `9837e21771b546a1d7ce63db5143b92b1b87a90b`.

The Rust example loads each case's signer and TSA PEM anchors. It enables the C2PA claim-signing EKU (`1.3.6.1.4.1.62558.2.1`) associated with the supplied signer trust lists. OCSP and remote-manifest network fetching are disabled; embedded OCSP responses are still processed. No certificate-profile checks are bypassed.

Each case runs in a separate child process. On macOS, the clock interposer sets only that child's wall clock to its required `validationTime`, leaving monotonic clocks and the system clock unchanged. The runner verifies the epoch reported by the SDK process and fails the case if it differs. It does not silently ignore time-dependent failures.

Requires Python 3 with PyYAML, Rust 1.96, and clang on macOS. From the repository root:

```sh
cargo +1.96.0 build -p c2pa --example conformance_validate --all-features
clang -dynamiclib -Wall -Wextra -Werror -o /private/tmp/c2pa-conformance-clock.dylib sdk/tests/conformance/clock_macos.c
python3 sdk/tests/conformance/run.py \
  --suite /path/to/conformance-504/tests/validation \
  --binary target/debug/examples/conformance_validate \
  --clock-dylib /private/tmp/c2pa-conformance-clock.dylib \
  --revision 9837e21771b546a1d7ce63db5143b92b1b87a90b \
  --output docs/conformance-integration
```

Use `--case <substring>` only for diagnosis, with a different output directory. A complete run writes `results.json` (all raw results and expectation failures) and `REPORT.md`, and exits nonzero if any case fails. Historical clock support here is macOS-specific; other platforms require an equivalent process-local clock.

Passing this suite does not imply full C2PA conformance: its cases are not exhaustive. SDK regression results are recorded separately from the conformance result.

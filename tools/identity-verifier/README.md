# Sealr identity verifier

This workspace tool independently verifies the committed `sealr.identity-conformance.v1` bundle. It does not depend on the Sealr crate, parse ZIP structure through discovery, inflate members, or perform filesystem effects.

Run it from the repository root:

```powershell
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/identity-v1.json
```

Its exact checks and nonclaims are documented in [identity conformance](../../docs/identity-conformance.md).

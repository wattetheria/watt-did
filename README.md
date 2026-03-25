# watt-did

`watt-did` is the shared DID and proof library for the Watt ecosystem.

It is intentionally:

- transport-agnostic
- business-agnostic
- reusable across `wattswarm`, `wattetheria`, `wattswarm-servicenet`, and future sibling projects

## Scope

`watt-did` currently provides:

- DID parsing
  - `did:key`
  - `did:web`
- DID document types and validation
- DID document builder and verification relationship helpers
- JWK public-key import/export helpers
- `did:web` HTTP resolution
- resolver cache and fallback composition helpers
- JOSE EdDSA verification
  - `JWS`
  - `JWT`
  - compact `UCAN`-style envelopes
- agent-to-node binding proof verification
- UCAN-style delegation validation
  - time window checks
  - parent-child attenuation checks

## Non-Goals

`watt-did` does not own:

- network transport
- wallet private-key custody
- service registry semantics
- product-layer identity workflows
- world semantics
- public-agent moderation

Those belong in other Watt projects.

## Relationship To `watt-wallet`

Boundary rule:

- `watt-did` answers:
  - how identifiers, DID documents, and proofs are parsed and verified
- `watt-wallet` will answer:
  - how keys are created, stored, selected, and used for signing

Typical dependency direction:

```text
watt-wallet -> watt-did
wattetheria -> watt-did
wattswarm -> watt-did
wattswarm-servicenet -> watt-did
```

## Library Usage

### Parse a DID

```rust
use watt_did::Did;

let did = Did::parse("did:web:example.com:agents:alice")?;
assert_eq!(did.method(), "web");
# Ok::<(), watt_did::DidError>(())
```

### Build a minimal `did:key` document

```rust
use watt_did::{Did, DidKey};

let did = Did::parse("did:key:z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S")?;
let document = DidKey::from_did(did)?.to_document()?;
assert_eq!(document.authentication, vec!["#key-1"]);
# Ok::<(), watt_did::DidError>(())
```

### Resolve `did:web`

```rust
use watt_did::{Did, DidResolver, DidWebResolver};

let did = Did::parse("did:web:example.com")?;
let resolver = DidWebResolver::default();
let _result = resolver.resolve(&did)?;
# Ok::<(), watt_did::DidError>(())
```

### Verify a compact JOSE proof

```rust
use watt_did::{
    CompactJoseEdDsaVerifier, Did, DidDocument, JoseValidationOptions, ProofAlgorithm,
    ProofEnvelope, ProofVerifier, VerificationMethod,
};

let signer = Did::parse("did:web:example.com:agents:alice")?;
let mut document = DidDocument::new(signer.clone());
document.verification_method.push(VerificationMethod {
    id: "#sig-1".into(),
    method_type: "Multikey".into(),
    controller: signer.to_string(),
    public_key_multibase: Some("z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S".into()),
    public_key_jwk: None,
    blockchain_account_id: None,
});
document.authentication.push("#sig-1".into());

let verifier = CompactJoseEdDsaVerifier::new(JoseValidationOptions {
    expected_issuer: Some(signer.to_string()),
    ..Default::default()
});

let proof = ProofEnvelope {
    algorithm: ProofAlgorithm::Jws,
    value: "header.payload.signature".into(),
    verification_method: Some("#sig-1".into()),
    challenge: None,
    nonce: None,
    created_at: None,
    expires_at: None,
};

let _ = verifier.verify(&proof, &signer, &document);
```

## CLI

A small utility binary is included for local inspection:

```bash
cargo run --bin watt-did -- help
cargo run --bin watt-did -- inspect did:key:z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S
cargo run --bin watt-did -- document did:key:z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S
```

## Current Supported Key Material

- `did:key`
  - `Ed25519`
  - `X25519`
  - `secp256k1` compressed public keys
- JWK public keys
  - `OKP / Ed25519`
  - `OKP / X25519`
  - `EC / P-256`

## Verification Notes

- Compact JOSE signature verification currently supports `EdDSA`
- `JWT` claim checks are available through `JoseValidationOptions`
- `UCAN` verification currently covers:
  - signature proof resolution
  - time window checks
  - issuer/audience chaining
  - capability attenuation

## Development

```bash
cargo fmt --all --check
cargo test
```

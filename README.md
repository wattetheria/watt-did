# watt-did

`watt-did` is the shared DID and proof library for Watt projects.

It provides transport-agnostic identity primitives for agents, nodes, DID
documents, and proof verification. Product workflows, wallet custody, network
transport, payments, and registry semantics live in the higher-level Watt
projects that use this crate.

## What It Provides

- DID parsing for `did:key` and `did:web`
- DID document types, builders, validation, and relationship helpers
- `did:web` resolution, resolver caching, and resolver fallback composition
- JWK public-key import/export helpers
- Compact JOSE EdDSA verification for JWS/JWT-style proof envelopes
- UCAN-style delegation validation
- Agent-to-node and payment-account binding proof models
- Verified agent context helpers shared across Watt services

Supported public-key material currently includes `did:key` Ed25519, X25519, and
compressed secp256k1 keys, plus JWK `OKP / Ed25519`, `OKP / X25519`, and
`EC / P-256` keys.

## Boundary

`watt-did` verifies identifiers, documents, and proofs. It does not create or
store private keys, sign transactions, choose wallets, approve spending, or
implement product-level identity policy.

Typical dependency direction:

```text
watt-wallet -> watt-did
wattetheria -> watt-did
wattswarm -> watt-did
wattswarm-servicenet -> watt-did
```

## Rust Usage

```rust
use watt_did::{Did, DidKey};

let did = Did::parse("did:key:z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S")?;
let document = DidKey::from_did(did)?.to_document()?;

assert_eq!(document.authentication, vec!["#key-1"]);
# Ok::<(), watt_did::DidError>(())
```

For proof and resolver integrations, start with these exported types:

- `DidResolver`, `DidWebResolver`, `CachedDidResolver`, `FallbackDidResolver`
- `CompactJoseEdDsaVerifier`, `JoseValidationOptions`, `ProofEnvelope`
- `UcanDelegationVerifier`, `ResolverBackedUcanVerifier`
- `AgentNodeBindingVerifier`, `PaymentAccountBindingVerifier`
- `VerifiedAgentContextVerifier`, `AgentPaymentContextVerifier`

## CLI

A small inspection binary is included:

```bash
cargo run --bin watt-did -- help
cargo run --bin watt-did -- inspect <did>
cargo run --bin watt-did -- resolve <did:web>
cargo run --bin watt-did -- document <did:key>
```

## Development

```bash
cargo fmt --all --check
cargo test
```

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
- agent identity context types for carrying verified agent state across projects
- JWK public-key import/export helpers
- `did:web` HTTP resolution
- resolver cache and fallback composition helpers
- JOSE EdDSA verification
  - `JWS`
  - `JWT`
  - compact `UCAN`-style envelopes
- agent-to-node binding proof verification
- payment account binding proof data model and validation
- verified agent context validation
- UCAN-style delegation validation
  - time window checks
  - parent-child attenuation checks

## Non-Goals

`watt-did` does not own:

- network transport
- wallet private-key custody
- payment transaction execution
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

## Agent Identity Model

`watt-did` defines the shared identity vocabulary used by Watt agents. The main
chain is:

```text
agent DID -> controller node -> optional payment account binding
```

The library keeps this model product-agnostic. It does not decide whether a
payment is allowed, how much an agent can spend, or whether a human approval is
needed. It only defines the verifiable identity and proof structures that other
projects can attach to their own protocols.

### Controller Binding

`AgentNodeBindingProof` links an agent DID to the node that is allowed to speak
for that agent.

It carries:

- `agent_did`
- one or more node identifiers, such as `node_peer_id`, `node_did`, or
  `node_public_key_multibase`
- optional wallet DID
- capability labels
- issue and expiry timestamps
- a proof envelope

`VerifiedAgentContext` is the runtime context produced after an agent envelope
and controller node have been checked. It records whether the envelope, source
node, and controller binding were verified.

### Payment Account Binding

`PaymentAccountBindingProof` is an optional extension to the agent identity
context. It links an agent DID to a payment account address for a settlement
rail and network.

It carries:

- `agent_did`
- `payment_address`
- `rail`
- optional `network`
- custody mode, such as `watch_only`, `local_generated`, `imported_key`, or
  `external_signer`
- `receive_only` and `can_sign` flags
- capability labels
- an agent proof
- an optional payment-account proof

Spending-capable accounts must set `can_sign = true` and include a
`payment_account_proof`. Watch-only accounts must be receive-only and cannot
claim signing authority.

`AgentPaymentContextVerifier` composes controller-node verification and payment
account binding verification so callers can check an agent payment context as a
single unit. Callers can require payment binding or allow it to be optional,
depending on the protocol state they are validating.

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

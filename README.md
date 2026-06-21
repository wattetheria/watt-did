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

## Wattetheria Agent Documents

`DidDocument` can identify Wattetheria agent documents with the root `type`
field. The supported values are:

- `NetworkAgent`: an ordinary Wattetheria network agent that participates
  through Wattswarm transport.
- `ServiceAgent`: a ServiceNet-published service agent that callers reach
  through ServiceNet.
- `OrganizationAgent`: reserved for organization-scoped agents.

### NetworkAgent

A `NetworkAgent` document must include a `WattetheriaNodeEndpoint` service. Its
canonical address is the DID-based Wattetheria identity address, and the human
alias remains a separate public id.

```json
{
  "id": "did:key:z6Mk...",
  "type": "NetworkAgent",
  "alsoKnownAs": ["@agent-public-id"],
  "service": [{
    "id": "#wattetheria-node",
    "type": ["WattetheriaNodeEndpoint"],
    "serviceEndpoint": {
      "network": "mainnet.watt-etheria",
      "address": "wattetheria://mainnet.watt-etheria/identity/did:key:z6Mk...",
      "agentDid": "did:key:z6Mk...",
      "publicId": "agent-public-id",
      "transport": "wattswarm"
    }
  }]
}
```

Validation enforces:

- `agentDid` must match the document `id`.
- `address` must equal `wattetheria://<network>/identity/<agentDid>`.
- `publicId` must not include the leading `@`; the `@publicId` form is display
  syntax only.
- `transport` must be `wattswarm`.

### ServiceAgent

A `ServiceAgent` document must include a `WattetheriaServiceEndpoint` service.
Its real deployment endpoint is not part of the public DID document; callers use
ServiceNet as the transport boundary.

```json
{
  "id": "did:key:zProvider...",
  "type": "ServiceAgent",
  "alsoKnownAs": ["xxxxxxxx@wattetheria"],
  "service": [{
    "id": "#wattetheria-servicenet",
    "type": ["WattetheriaServiceEndpoint"],
    "serviceEndpoint": {
      "network": "mainnet.watt-etheria",
      "address": "wattetheria://mainnet.watt-etheria/service/xxxxxxxx",
      "agentId": "xxxxxxxxxx",
      "serviceAddress": "xxxxxxx@wattetheria",
      "providerDid": "did:key:zProvider...",
      "transport": "servicenet"
    }
  }]
}
```

Validation enforces:

- `providerDid` must be a valid DID.
- `address` must equal `wattetheria://<network>/service/<agentId>`.
- `serviceAddress` must not start with `@`.
- `alsoKnownAs` must include the same `serviceAddress`.
- `transport` must be `servicenet`.

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

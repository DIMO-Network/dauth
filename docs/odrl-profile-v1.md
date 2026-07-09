# DIMO ODRL Profile v1

Profile IRI: `https://ns.dimo.co/odrl/v1`

New-style SACD grants are CloudEvents of type **`dimo.sacd.odrl`** whose `data`
field is a [W3C ODRL 2.2](https://www.w3.org/TR/odrl-model/) **Agreement**
restricted to this profile. The CloudEvent envelope is unchanged from legacy
SACD documents: the grantor's signature is over the raw `data` bytes, and
consumers dispatch on the envelope `type`.

Version 1 deliberately covers exactly the capabilities of legacy permission
grants — no more:

| Concept | ODRL term | Notes |
|---|---|---|
| Asset / subject | `target` | ERC721 or Ethr DID string |
| Grantor | `assigner` | `did:ethr:<chainId>:<address>` |
| Grantee | `assignee` | `did:ethr:<chainId>:<address>` |
| Valid period | `constraint` | `dateTime` comparisons, conjunctive |
| Named permissions | `permission[].action` | existing `privilege:*` names |

## Example

```json
{
  "specversion": "1.0",
  "id": "2o8kX...",
  "source": "0xGrantorAppAddress",
  "type": "dimo.sacd.odrl",
  "time": "2026-07-09T00:00:00Z",
  "signature": "0x...",
  "data": {
    "@context": ["http://www.w3.org/ns/odrl.jsonld", "https://ns.dimo.co/odrl/v1"],
    "@type": "Agreement",
    "uid": "urn:uuid:6f2f2fd0-6d3f-4b3a-9c39-0f2f4a3f4b3a",
    "profile": "https://ns.dimo.co/odrl/v1",
    "assigner": "did:ethr:137:0x8Ec8B60a10a03fA3225303cA51fD3d3a7ec48c1a",
    "assignee": "did:ethr:137:0x20Ca3bE69a8B95D3093383375F0473A8c6341727",
    "target": "did:erc721:137:0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF:42",
    "constraint": [
      { "leftOperand": "dateTime", "operator": "gteq", "rightOperand": "2026-07-01T00:00:00Z" },
      { "leftOperand": "dateTime", "operator": "lt",   "rightOperand": "2027-07-01T00:00:00Z" }
    ],
    "permission": [
      { "action": "privilege:GetLocationHistory" },
      { "action": "privilege:GetNonLocationHistory" }
    ]
  }
}
```

## Strictness rules

The evaluator is **fail-closed**: a document containing anything outside the
profile vocabulary is rejected in full — never partially honored. Concretely:

- **No JSON-LD processing, ever.** The document is treated as plain JSON. The
  `@context` must be byte-identical to one of the canonical forms
  (`"http://www.w3.org/ns/odrl.jsonld"` alone, or
  `["http://www.w3.org/ns/odrl.jsonld", "https://ns.dimo.co/odrl/v1"]`); it is
  never dereferenced, so a hostile context cannot remap term meanings under
  the grantor's signature.
- **Unknown fields are errors.** `prohibition`, `obligation`, `duty`,
  `inheritFrom`, per-permission `constraint`, refinements — all rejected until
  a future profile version defines their semantics.
- **`@type` must be `Agreement`**; `profile` must be this profile's IRI.
- **Actions** must come from the closed vocabulary of existing DIMO permission
  names (`privilege:GetLocationHistory`, `privilege:GetRawData`, ...). An
  unknown action rejects the whole document so authoring typos fail loudly at
  exchange time rather than silently granting nothing.
- **Constraints** are restricted to `leftOperand: "dateTime"` with operators
  `gteq`, `gt`, `lteq`, `lt` and a plain RFC 3339 `rightOperand` (not a JSON-LD
  `@value` object). Multiple constraints are conjunctive, per the ODRL model.
  An absent `constraint` array means the agreement is unbounded in time.
- **CloudEvent-scoped access is not in profile v1.** A token request carrying
  event filters is refused when the backing grant is an ODRL document.

## Semantics

Evaluation happens at token-exchange time, mirroring the legacy path:

1. The envelope `type` selects the ODRL evaluator.
2. `assignee` must match the requesting address; the envelope `signature` must
   verify over `data` against the `assigner` address.
3. All `constraint` entries must hold at evaluation time.
4. `target` must decode to the same asset DID the token is requested for.
5. Each requested permission must appear among the `permission` actions. The
   minted JWT is identical to one produced from a legacy document granting the
   same permissions — downstream services (dq) cannot tell the difference.

## Extension path

Later profile versions widen the accepted vocabulary; they never change the
meaning of documents valid under v1. Anticipated widenings: CloudEvent-scoped
permissions (action `dimo:ReadCloudEvents` with `refinement` on event
type/source/id), template grants as ODRL `Set` policies, `isAnyOf` operators,
and purpose constraints.

A machine-readable JSON Schema for this profile lives at
[`odrl-profile-v1.schema.json`](./odrl-profile-v1.schema.json).

# DIMO ODRL Profile v1

Profile IRI: `https://ns.dimo.co/odrl/v1`

New-style SACD grants are CloudEvents of type **`dimo.sacd.odrl`** whose `data`
field is a [W3C ODRL 2.2](https://www.w3.org/TR/odrl-model/) **Agreement**
restricted to this profile. The CloudEvent envelope is unchanged from legacy
SACD documents: the grantor's signature is over the raw `data` bytes, and
consumers dispatch on the envelope `type`.

Version 1 covers the capabilities of legacy permission grants plus one
extension beyond them, per-permission data windows:

| Concept | ODRL term | Notes |
|---|---|---|
| Asset / subject | `target` | ERC721 or Ethr DID string |
| Grantor | `assigner` | `did:ethr:<chainId>:<address>` |
| Grantee | `assignee` | `did:ethr:<chainId>:<address>` |
| Valid period | `constraint` | `dateTime` comparisons, conjunctive |
| Named permissions | `permission[].action` | existing `privilege:*` names |
| Data window | `permission[].constraint` | `dimo:recordedAt` comparisons, conjunctive |

The two constraint positions answer different questions and accept disjoint
vocabularies. A **policy-level** constraint (`dateTime`) bounds when the grant
may be *exercised*: it is evaluated once, at token-exchange time, and never
reaches the token. A **per-permission** constraint (`dimo:recordedAt`, defined
by this profile) bounds the *recording timestamps of the data* the permission
may read: it is not evaluated at exchange time but forwarded verbatim into the
minted token for the data services to enforce.

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
      {
        "action": "privilege:GetLocationHistory",
        "constraint": [
          { "leftOperand": "dimo:recordedAt", "operator": "gteq", "rightOperand": "2026-04-01T00:00:00Z" },
          { "leftOperand": "dimo:recordedAt", "operator": "lt",   "rightOperand": "2026-07-01T00:00:00Z" }
        ]
      },
      { "action": "privilege:GetNonLocationHistory" }
    ]
  }
}
```

This agreement grants non-location history for all time, but location history
only for data recorded in Q2 2026.

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
  `inheritFrom`, `refinement` — all rejected until a future profile version
  defines their semantics.
- **`@type` must be `Agreement`**; `profile` must be this profile's IRI.
- **Actions** must come from the closed vocabulary of existing DIMO permission
  names (`privilege:GetLocationHistory`, `privilege:GetRawData`, ...). An
  unknown action rejects the whole document so authoring typos fail loudly at
  exchange time rather than silently granting nothing.
- **Duplicate actions are errors.** Under the ODRL model, two `permission`
  entries naming the same action are independent grants — a union (e.g. two
  disjoint data windows). Profile v1 defines no union semantics; rather than
  silently honoring one entry, the document is rejected. A later version may
  define the union reading.
- **Policy-level constraints** are restricted to `leftOperand: "dateTime"`
  with operators `gteq`, `gt`, `lteq`, `lt` and a plain RFC 3339
  `rightOperand` (not a JSON-LD `@value` object). Multiple constraints are
  conjunctive, per the ODRL model. An absent `constraint` array means the
  agreement is unbounded in time.
- **Per-permission constraints** are restricted to
  `leftOperand: "dimo:recordedAt"` with the same operators and operand format.
  `dateTime` is not accepted on a permission, nor `dimo:recordedAt` at the
  policy level: exercise time and data time never mix positions.
- **CloudEvent-scoped access is not in profile v1.** A token request carrying
  event filters is refused when the backing grant is an ODRL document.

## Semantics

Evaluation happens at token-exchange time, mirroring the legacy path:

1. The envelope `type` selects the ODRL evaluator.
2. `assignee` must match the requesting address; the envelope `signature` must
   verify over `data` against the `assigner` address.
3. All policy-level `constraint` entries must hold at evaluation time.
4. `target` must decode to the same asset DID the token is requested for.
5. Each requested permission must appear among the `permission` actions.
6. A requested permission whose grant carries no per-permission constraints is
   minted into the token's flat `permissions` claim, exactly as from an
   equivalent legacy document. A permission granted **with** constraints is
   minted **only** into the `scoped_permissions` claim, its constraint atoms
   copied verbatim:

   ```json
   "permissions": ["privilege:GetNonLocationHistory"],
   "scoped_permissions": [
     {
       "name": "privilege:GetLocationHistory",
       "constraint": [
         { "leftOperand": "dimo:recordedAt", "operator": "gteq", "rightOperand": "2026-04-01T00:00:00Z" },
         { "leftOperand": "dimo:recordedAt", "operator": "lt",   "rightOperand": "2026-07-01T00:00:00Z" }
       ]
     }
   ]
   ```

   This split is the fail-closed encoding: a consumer that only reads the flat
   claim never sees a constrained permission at all, so it cannot honor the
   grant while ignoring its constraints. Consumers that understand
   `scoped_permissions` must themselves fail closed on any constraint they
   cannot fully interpret (see `tokenclaims.RecordedAtWindow`).

The gRPC `AccessCheck` response cannot express constraints, so it reports
`has_access: false` for any permission granted only under constraints.

## Extension path

Later profile versions widen the accepted vocabulary; they never change the
meaning of documents valid under v1. Anticipated widenings: CloudEvent-scoped
permissions (action `dimo:ReadCloudEvents` with `refinement` on event
type/source/id), template grants as ODRL `Set` policies, `isAnyOf` operators,
purpose constraints, and further per-permission left operands (e.g.
geofences), which existing consumers will automatically refuse until taught.

A machine-readable JSON Schema for this profile lives at
[`odrl-profile-v1.schema.json`](./odrl-profile-v1.schema.json). A design
draft for the next version — union semantics for duplicate actions and
CloudEvent-scoped access — lives at
[`odrl-profile-v2-draft.md`](./odrl-profile-v2-draft.md).

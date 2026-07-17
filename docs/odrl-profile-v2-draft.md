# DIMO ODRL Profile v2 — DRAFT

Profile IRI: `https://ns.dimo.co/odrl/v2`

**Status: design draft. Nothing here is implemented.** Profile v1 evaluators
reject everything this document describes — v2 documents carry the v2 profile
IRI, which v1 evaluators refuse outright, and each v2 construct (duplicate
actions, the `dimo:ReadCloudEvents` action, categorical operands, `isAnyOf`)
is independently outside v1's closed vocabulary. That is the profile's
extension model working as intended: old evaluators fail closed on new
documents; a later version widens the vocabulary but never changes the
meaning of documents valid under an earlier one. Every valid v1 document is a
valid v2 document with identical meaning.

v2 adds exactly two things:

1. **Union semantics for duplicate actions** — a permission may be granted
   under several alternative constraint sets.
2. **CloudEvent-scoped access** — the `dimo:ReadCloudEvents` action with
   categorical constraints on event type/source/id/tag, reaching parity with
   legacy SACD `cloudevent` agreements and composing with data windows.

They are one release because the second forces the first: a grant covering
several event tuples needs several entries of the same action.

## 1. Union semantics for duplicate actions

v1 rejects two `permission` entries naming the same action, explicitly
reserving the shape. v2 defines it, following the ODRL model, where each
permission entry is an independent grant:

> Multiple `permission` entries naming the same action are **alternatives**.
> A request is authorized if **some** entry covers it. Constraints within an
> entry remain conjunctive.

This applies to every action, not just CloudEvents — it retroactively gives
data windows disjoint unions ("the last two weekends"):

```json
"permission": [
  { "action": "privilege:GetLocationHistory",
    "constraint": [
      { "leftOperand": "dimo:recordedAt", "operator": "gteq", "rightOperand": "2026-07-04T00:00:00Z" },
      { "leftOperand": "dimo:recordedAt", "operator": "lt",   "rightOperand": "2026-07-06T00:00:00Z" } ] },
  { "action": "privilege:GetLocationHistory",
    "constraint": [
      { "leftOperand": "dimo:recordedAt", "operator": "gteq", "rightOperand": "2026-07-11T00:00:00Z" },
      { "leftOperand": "dimo:recordedAt", "operator": "lt",   "rightOperand": "2026-07-13T00:00:00Z" } ] }
]
```

Two strictness rules keep unions from degenerating:

- **An unconstrained entry forbids siblings.** If any entry for an action has
  no constraints, duplicate entries for that action are an error — the
  unconstrained entry already grants everything, so siblings can only be
  authoring mistakes.
- **Identical duplicate entries are errors** (same action, same constraint
  set) — they change nothing and indicate a generation bug.

### Claims

`scoped_permissions` may carry **multiple entries with the same name**, one
per alternative, atoms verbatim as in v1. Consumers must treat same-name
entries as alternatives: a read is allowed when some entry's constraints
admit it.

**Consumer skew is deny-biased by construction.** A consumer that considers
only one entry per name (as dq's v1 `scope` helper does — first match)
enforces a *subset* of the union: requests that only a later entry would
admit are wrongly denied, and nothing is wrongly allowed. Lockstep deployment
is a functionality concern, never a security one.

## 2. CloudEvent-scoped access: `dimo:ReadCloudEvents`

A new action, outside the `privilege:*` vocabulary, granting reads of
CloudEvents (attestations, documents, raw payloads) attached to the target
asset. Constraints narrow which events, using new categorical left operands:

| Left operand | Matches against | Operators |
|---|---|---|
| `dimo:eventType` | CloudEvent `type` | `eq`, `isAnyOf` |
| `dimo:eventSource` | CloudEvent `source` | `eq`, `isAnyOf` |
| `dimo:eventID` | CloudEvent `id` | `eq`, `isAnyOf` |
| `dimo:eventTag` | event tags | `eq`, `isAnyOf` |
| `dimo:recordedAt` | CloudEvent `time` | `gteq`, `gt`, `lteq`, `lt` |

- `isAnyOf` takes a JSON **array of strings** as its right operand and is
  satisfied when the matched value is any element. v2 admits `isAnyOf` only
  on the four categorical event operands — `dimo:recordedAt` remains
  comparison-only everywhere.
- An **absent** dimension is unrestricted — the deliberate replacement for
  legacy's magic `"*"` wildcard strings.
- Constraints within an entry are conjunctive; alternative tuples are
  expressed as duplicate entries under §1. A cross-product cannot over-grant:
  "type A from X, or type B from Y" is two entries, not
  `type isAnyOf [A,B] ∧ source isAnyOf [X,Y]`.
- `dimo:recordedAt` composes in the same entry: *"attestations from source X
  recorded in Q2"* is one entry with three atoms. The legacy format cannot
  express this — its per-agreement dates are grant-validity bounds, not data
  bounds.

```json
{ "action": "dimo:ReadCloudEvents",
  "constraint": [
    { "leftOperand": "dimo:eventType",   "operator": "eq",      "rightOperand": "dimo.attestation" },
    { "leftOperand": "dimo:eventSource", "operator": "eq",      "rightOperand": "0xConnectionAddr" },
    { "leftOperand": "dimo:recordedAt",  "operator": "gteq",    "rightOperand": "2026-04-01T00:00:00Z" },
    { "leftOperand": "dimo:recordedAt",  "operator": "lt",      "rightOperand": "2026-07-01T00:00:00Z" } ] }
```

### Exchange semantics

v1's blanket refusal of event filters under ODRL grants is lifted for v2
documents only. A token request carrying `cloudEvents.events` filters is
authorized when each requested filter is covered by some
`dimo:ReadCloudEvents` entry (coverage: every dimension the entry constrains
admits the requested value; a requested wildcard dimension is covered only by
an entry that leaves that dimension unconstrained). The `privilege:*`
evaluation is unchanged.

### Claims

Granted `dimo:ReadCloudEvents` entries are minted into `scoped_permissions`
with their atoms verbatim, exactly like windowed privileges — **not** into
the legacy `cloud_events` claim, whose enforcement history (never enforced in
dq main, enforced for attestations only in telemetry-api) is the case study
in side-channel claims. Note the deliberate difference from the legacy path,
which mints the *requested* filters: v2 forwards the *granted* entries, the
same selection-and-resolution rule as data windows. Consumers enforce
coverage per read; the token is not narrowed to the request.

Fail-closed as always: `dimo:ReadCloudEvents` never appears in the flat
`permissions` claim, and a consumer that does not know the action name or its
operands grants nothing for it (dq's `scope` helpers error on unknown
vocabulary, and errors deny).

### Consumer enforcement (dq)

The fetch surface's gate generalizes from "unscoped raw-data possession" to:

> unscoped raw-data possession **or** a `dimo:ReadCloudEvents` entry covering
> the request (type/source/id/tag coverage; `before`/`after` bounds required
> inside any `dimo:recordedAt` window, per the ranged-queries-reject rule).

This OR shape — enum path unioned with grant coverage, each independent — is
the structure the unmerged `cloud-event-grants` branch already implemented
against the legacy claim; the v2 work re-targets it at constraint atoms.

## Explicitly out of scope for v2

- `refinement`, `prohibition`, `obligation`, `duty` — still rejected.
- Recurring patterns (`dayOfWeek`, e.g. "weekends only") — candidate for a
  later version; until then unions of explicit windows.
- Template grants as ODRL `Set` policies; purpose constraints.
- `isAnyOf` on anything but the four event operands.

## Compatibility summary

| | v1 document | v2 document |
|---|---|---|
| v1 evaluator | ✅ unchanged | ❌ rejected (profile IRI + vocabulary) |
| v2 evaluator | ✅ identical meaning | ✅ |

Token-side: v2 minting introduces (a) same-name `scoped_permissions` entries
and (b) `dimo:ReadCloudEvents` entries. Both are deny-biased under v1-era
consumers (§1 claims; unknown vocabulary grants nothing), so v2 can ship
exchange-first without a security-ordered deploy; consumers upgrade to make
the new grants *work*, not to make them *safe*.

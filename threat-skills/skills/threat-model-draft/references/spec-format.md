# Draft spec format (input for `tdtool.py build` / `extend`)

A spec is plain JSON. `build` turns it into a Threat Dragon v2 model; `extend` adds a delta spec
to an existing model. See `../assets/example.spec.json` for a complete example.

```json
{
  "title": "Order Portal",                     // required for build: model title
  "owner": "Team Phoenix",                     // optional
  "description": "What is modelled, sources",  // optional
  "diagram": "Order placement",                // optional diagram title
  "contributors": ["An", "Binh"],              // optional
  "boundaries": [ { "id": "internet", "name": "Internet", "description": "" } ],
  "elements":   [ { "id": "api", "type": "process", "name": "Order API",
                    "boundary": "dmz", "description": "...", "props": { "isWebApplication": true },
                    "outOfScope": false, "reasonOutOfScope": "" } ],
  "flows":      [ { "id": "f1", "from": "customer", "to": "api", "name": "REST + JWT",
                    "protocol": "HTTPS", "encrypted": true, "publicNetwork": true,
                    "bidirectional": false, "description": "" } ],
  "threats":    [ { "target": "api", "category": "Elevation of privilege", "severity": "High",
                    "title": "...", "description": "...", "mitigation": "...", "score": "" } ]
}
```
(Comments above are for explanation only — real JSON files must not contain them.)

## Fields

**ids** — any short unique string inside the spec (`api`, `f3`). They are only used to wire the
spec together; the script generates Threat Dragon UUIDs.

**elements.type** — `actor` (external entity), `process`, or `store`.

**elements.boundary** — id of a boundary in `boundaries`. Omit for elements outside any boundary.
Each boundary is drawn as a box; elements are laid out in columns, boundaries left to right in the
order listed. List boundaries from least trusted (Internet) to most trusted (internal data) so the
picture reads naturally.

**elements.props** — optional Threat Dragon flags (only these are accepted):
- actor: `providesAuthentication`
- process: `handlesCardPayment`, `handlesGoodsOrServices`, `isWebApplication`, `privilegeLevel` (text)
- store: `isALog`, `isEncrypted`, `isSigned`, `storesCredentials`, `storesInventory`

**flows** — `from`/`to` are element ids. Use `bidirectional: true` for request/response pairs only when
both directions matter for threats; otherwise draw the direction data is sent.

**threats.target** — an element id or a flow id.

**threats.category** — one of `Spoofing`, `Tampering`, `Repudiation`, `Information disclosure`,
`Denial of service`, `Elevation of privilege` (short forms S/T/R/I/D/E, DoS, EoP are accepted).

**threats.severity** — `Low`, `Medium`, `High`, `Critical` (or `TBD`). `Critical` and the extra
statuses below need a recent Threat Dragon 2.x; prefer Low/Medium/High if the team runs an older version.

**threats.status** — leave out (defaults to `Open`). Drafts must not set other statuses.

**threats.score** — optional text (e.g. a CVSS base score); leave empty if unsure.

## Delta specs (update mode, `extend`)

Same shape, every section optional, no `title` needed. Differences:
- `from`, `to` and `target` may be a new id from the delta **or the exact name of an existing
  element/flow** in the model (as shown by `tdtool.py extract`).
- A boundary whose `name` matches an existing box reuses that box; new elements with that
  boundary are placed inside it and the box grows.
- An element whose name already exists is not duplicated (it is reused as a reference).
- A threat whose title already exists on the same target is skipped.
- Existing threats are never modified; new threat numbers continue from the model's highest number.

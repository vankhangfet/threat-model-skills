# Threat check: <branch or MR> → <base>

**Verdict:** <OK | OK with notes | Needs attention>
**Model:** <threat-model/slug.json> (threats: <n open> open / <n mitigated> mitigated) · **Requirements:** <file, last synced date>
**Diff:** <base sha>..<head sha> · <n> files (<list of skimmed-only files, if any>) · uncommitted changes included: <yes/no>

## Findings that violate a pinned ID
Every finding cites the threat and requirement it relates to. No ID, no finding in this section
(put it under Model drift or Security smells instead).
| # | Violates | Severity | Evidence | What to do |
|---|---|---|---|---|
| 1 | T-014 / SR-007 | High | `path/file.py:88` - what was found | Add the ownership check, add test |

## Model integrity (threat IDs between base and this change)
<Output of `tdtool.py diff`, summarised: violations, removed threats, status changes such as
`T-004 Open -> Mitigated`. "None." if the model is untouched.>

## Requirement coverage
| SR | Threats (severity) | Result | Evidence | Test |
|---|---|---|---|---|
| SR-001 | T-001 (High), T-002 (High) | Implemented / Partial / Missing / Regressed / Not verifiable | `path/file.py:42` – what was found | `tests/...` exists ✓ / missing ✗ |

## Model drift
| Change | Evidence | Suggested model update |
|---|---|---|
| New outbound call to <service> | `path:line` | Add actor "<service>", flow "<name>", check I/T threats |

## Security smells (not covered by the model)
- `path:line` (no matching threat) — <issue> — <suggested fix>

## Suggested follow-ups
- Threat status updates to confirm (not applied): `tdtool.py set-status ... --threat T-00x --status Mitigated --note "..."`
- Update the threat model (threat-model-draft, update mode) for: <drift items>
- Missing tests to add: <list>

<!-- If nothing applies in a section, write "None." rather than deleting it. -->

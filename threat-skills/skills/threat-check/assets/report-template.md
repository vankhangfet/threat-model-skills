# Threat check: <branch or MR> → <base>

**Verdict:** <OK | OK with notes | Needs attention>
**Model:** <threat-model/slug.json> (threats: <n open> open / <n mitigated> mitigated) · **Requirements:** <file, last synced date>
**Diff:** <base sha>..<head sha> · <n> files (<list of skimmed-only files, if any>) · uncommitted changes included: <yes/no>

## Requirement coverage
| SR | Threats (severity) | Result | Evidence | Test |
|---|---|---|---|---|
| SR-001 | T-001 (High), T-002 (High) | Implemented / Partial / Missing / Regressed / Not verifiable | `path/file.py:42` – what was found | `tests/...` exists ✓ / missing ✗ |

## Model drift
| Change | Evidence | Suggested model update |
|---|---|---|
| New outbound call to <service> | `path:line` | Add actor "<service>", flow "<name>", check I/T threats |

## Security smells (not covered by the model)
- `path:line` — <issue> — <suggested fix>

## Suggested follow-ups
- Threat status updates to confirm (not applied): `tdtool.py set-status ... --threat T-00x --status Mitigated --note "..."`
- Update the threat model (threat-model-draft, update mode) for: <drift items>
- Missing tests to add: <list>

<!-- If nothing applies in a section, write "None." rather than deleting it. -->

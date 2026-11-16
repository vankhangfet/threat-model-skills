---
name: threat-to-requirements
description: Turn a reviewed OWASP Threat Dragon threat model into traceable, testable security requirements (SECURITY-REQUIREMENTS.md), rules that coding agents follow (AGENTS.md / CLAUDE.md block), and optional backlog items. Use whenever the user wants to convert threats or mitigations into requirements, acceptance criteria, tickets, a security spec, or "rules for the AI to follow when coding", or says the threat model review is done and asks what's next — even if they don't say "requirements".
---

# Threat model → security requirements

A reviewed threat model is only useful if its mitigations reach the code. This skill converts the
team's decisions in Threat Dragon into three things:

1. `SECURITY-REQUIREMENTS.md` — requirements with stable IDs (SR-001…), each linked to threat IDs
   (T-001…), scoped to components, and verifiable.
2. A rules block in the coding-agent instruction files so every agent (Claude Code, OpenCode, Cline,
   Codex, Cursor, Copilot…) reads the requirements before touching security-relevant code.
3. Optionally, backlog items for mitigations that are their own piece of work.

The threat model is the source of truth for **decisions** (which threats are open, accepted, not
applicable). This skill must not change those decisions. If something in the model looks wrong,
say so in your summary instead of working around it.

## Conventions

- Model(s): `threat-model/*.json` (Threat Dragon v2). Ignore `*.draft-log.json` and files in `threat-model/drafts/`.
- Optional config `threat-model/config.json`: `modelDir`, `requirementsFile`
  (default `SECURITY-REQUIREMENTS.md` at repo root), `language`, `agentRulesFiles`, `backlogCsv`.
- Language: requirement text in the configured language, otherwise the user's language. IDs, the
  words MUST/SHOULD, STRIDE categories and statuses stay in English.
- Script: `scripts/tdtool.py` in this skill's folder. Python 3.8+, standard library only.

## Workflow

### 1. Load the model
```bash
python3 <skill-dir>/scripts/tdtool.py validate threat-model/<slug>.json
python3 <skill-dir>/scripts/tdtool.py extract threat-model/<slug>.json --format json
```
If validation reports errors, stop and tell the user (the model needs fixing in Threat Dragon first).
If there are several models, process each, keeping one requirements file with a section per model,
and make T-ids unambiguous by prefixing the model slug when needed (`order-portal/T-003`).

Check the review state: if most threats are still `Open` with untouched draft text and there is a
`threat-model/<slug>.review.md` with unanswered questions, the model may not have been reviewed yet.
Point this out and ask whether to continue.

### 2. Classify threats by status
| Status | What to produce |
|---|---|
| `Open` | A requirement (status **Required**). |
| `Mitigated` | Keep/create the requirement (status **Implemented**) so it stays enforced and tested. |
| `Accepted`, `Transferred`, `Avoided`, `Eliminated` | No requirement. List under *Risk decisions* with the reason found in the mitigation text. |
| `NotApplicable` | No requirement. List under *Risk decisions* as not applicable. |

### 3. Write requirements
Read `references/requirements-guide.md` for wording rules and examples. In short:
- One requirement = one control. Several threats may share it (e.g. one ownership check covers an
  IDOR threat and a prompt-injection threat); one threat may need several requirements.
- Use MUST for what the mitigation requires, SHOULD for defence-in-depth.
- Name **where** it applies: component plus code paths if you can find them in the repo.
- Every requirement has a **Verification** line: a test, a config check, or a review item.
  Prefer automated tests a coding agent can write.
- Do not add requirements that no threat asks for. Generic hardening belongs elsewhere.

### 4. Update `SECURITY-REQUIREMENTS.md`
Use `assets/security-requirements-template.md` for a new file. If the file exists, read it first and:
- **Keep every existing SR id and its wording**; humans may have edited it. Update only the
  *Threats*, *Status* and *Applies to* lines when the model changed.
- New requirements get the next free number. Never reuse or renumber ids.
- If all threats behind a requirement disappeared or became NotApplicable/Accepted, set its status to
  **Retired** with a one-line reason instead of deleting it.
- Regenerate the traceability table (T-id → SR-ids) and the *Risk decisions* section.

### 5. Update agent rules
Insert or refresh the block from `assets/agent-rules-block.md` between its markers in:
- `AGENTS.md` at the repo root (create it if missing; it is read by many agents), and
- any of these that already exist: `CLAUDE.md`, `GEMINI.md`, `.github/copilot-instructions.md`,
  `.cursor/rules/*.mdc` (add a small `security.mdc`), or the files listed in `agentRulesFiles`.
Replace only the text between the markers; leave the rest of each file untouched. Adjust the paths
in the block if the requirements file or model folder are configured differently.

### 6. Backlog (optional)
Only when the user asks for tickets or `backlogCsv` is true: write `threat-model/backlog.csv`
with columns `Summary,Description,Priority,Labels,Requirement,Threats` — one row per **Required**
requirement that needs dedicated work (not ones already covered by an existing ticket the user
mentions). Priority from the highest linked severity: Critical/High→High, Medium→Medium, Low→Low.
Labels: `security,threat-model`. Do not create tickets in an issue tracker unless the user asks and
a tool for it is available.

### 7. Report
Tell the user: number of requirements added/updated/retired, the Required ones linked to High or
Critical threats, risk decisions recorded, files changed, and anything in the model that looked
inconsistent (e.g. a Mitigated threat whose mitigation text is empty). Do not commit unless asked.

---
name: threat-check
description: Check a code change (merge request, pull request, branch or working-tree diff) against the project's OWASP Threat Dragon threat model and SECURITY-REQUIREMENTS.md — are the required mitigations implemented and tested, did the change break a control, and does it add attack surface the model does not cover yet. Use whenever the user asks for a security review of a diff/MR/PR against the threat model, "threat check", "does this change follow the security requirements", "is the threat model still up to date", before merging security-relevant work, or when running as a CI review step.
---

# Threat check (diff ↔ threat model)

Compare a change with the reviewed threat model and the requirements derived from it, and report:

1. **Requirement coverage** — for requirements that apply to the changed code: implemented, partial,
   missing, or regressed, with file:line evidence and whether the verification test exists.
2. **Model drift** — new components, endpoints, data stores, external calls, trust boundaries or
   sensitive data flows that the threat model does not contain yet.
3. **Obvious security smells in the diff** — a short list only; this is not a replacement for SAST,
   dependency scanning or a pentest.

The report informs a human reviewer. It does not approve or block on its own, and it never changes
threat statuses without a person agreeing.

## Conventions

- Model(s): `threat-model/*.json`; requirements: `SECURITY-REQUIREMENTS.md` (or `requirementsFile`
  in `threat-model/config.json`); base branch: `baseBranch` in config, else the remote default branch.
- Language: report in the configured language, otherwise the user's language; ids, statuses and
  STRIDE names stay in English.
- Script: `scripts/tdtool.py` in this skill's folder (Python 3.8+, standard library only).
- **Interactive vs CI.** If running non-interactively (environment variable `CI` is set, or the user
  says this is a pipeline run), do not ask questions and do not modify any file except the report.

## Workflow

### 1. Get the change set
Use what the user specifies (MR/PR number, branch, commit range, pasted diff). Otherwise:
```bash
git fetch origin --quiet || true
BASE=$(git merge-base HEAD origin/<baseBranch>)
git diff --stat $BASE...HEAD
git diff $BASE...HEAD
```
Also include uncommitted changes (`git diff HEAD`) if there are any, and say so in the report.
For very large diffs, read the security-relevant files fully (auth, handlers/controllers, data
access, config, IaC, dependency manifests, agent/tool code) and list the files you only skimmed.

### 2. Load the model and requirements
```bash
python3 <skill-dir>/scripts/tdtool.py extract threat-model/<slug>.json --format json
```
Read `SECURITY-REQUIREMENTS.md`. If there is no threat model, say so and stop with a one-line
suggestion to run the threat-model-draft skill. If there is a model but no requirements file, check
directly against the mitigation text of `Open` and `Mitigated` threats and recommend running
threat-to-requirements.

### 3. Map changed code to model elements
For each changed file, decide which elements and flows it implements, using element names and
descriptions, the *Applies to* lines of the requirements, and the code itself (routes, clients,
queue names, table names, environment variables). Note files that map to **no** element — they are
candidates for drift.

### 4. Check requirements that apply
For each SR whose scope touches the change (and each `Open`/`Mitigated` threat on a touched element):
- **Implemented** — the control is present in the changed code path; quote file:line.
- **Partial** — present on some paths but not others (e.g. one of three endpoints).
- **Missing** — the change touches the scope but the control is absent.
- **Regressed** — the change removes or weakens an existing control (deleted check, broadened
  permission, disabled verification, secret in code/log).
- **Not verifiable** — the control lives outside the diff/repo (gateway config, cloud console); say what to check.
Also check the SR's *Verification*: does the test exist and does it actually exercise the control?
Base every verdict on code you read. If you are not sure, say "Not verifiable" rather than guessing.

### 5. Look for drift and smells
Read `references/drift-signals.md`. Report each drift item with evidence and the threat-model change
it implies (new element/flow/boundary, likely STRIDE threats). Keep the smell list short and concrete.

### 6. Write the report
Use `assets/report-template.md`. Verdict:
- **Needs attention** — any Missing/Regressed control linked to a High or Critical threat, or drift
  that adds a trust boundary, a new external party, or a new kind of sensitive data.
- **OK with notes** — Partial/Missing on Medium/Low, minor drift, or Not verifiable items.
- **OK** — everything in scope is implemented and tested, no drift.

Interactive: print the report and save it to `threat-model/reports/threat-check-<branch>-<YYYYMMDD>.md`
if the user wants a file. CI: write it to the path the pipeline gives (default
`threat-check-report.md`) and print it, so the pipeline can post it as an MR comment.

### 7. Propose follow-ups (do not apply silently)
- Threats whose requirements are now fully implemented **and** tested: list the commands, e.g.
  `python3 <skill-dir>/scripts/tdtool.py set-status threat-model/<slug>.json --threat T-004 --status Mitigated --note "MR !123, tests/test_audit.py"`.
  Run them only if the user explicitly agrees, then suggest re-running threat-to-requirements to
  sync SR statuses. In CI, only list them.
- Drift: suggest running threat-model-draft in update mode with the items you found.

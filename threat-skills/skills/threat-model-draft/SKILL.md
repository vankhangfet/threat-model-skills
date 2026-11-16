---
name: threat-model-draft
description: Draft or update an OWASP Threat Dragon threat model (STRIDE data-flow diagram + threats) from design docs and source code, ready for human review in Threat Dragon. Use whenever the user asks to threat model a feature, system, service, PR or architecture change, to "do threat analysis", "find security threats in the design", "create/update the Threat Dragon model", or mentions STRIDE, DFD, trust boundaries or attack surface for something being built — even if Threat Dragon is not named.
---

# Threat model draft (Threat Dragon)

Produce a **first draft** of a threat model that humans then review in OWASP Threat Dragon.
The draft saves reviewers from a blank page; it never replaces their judgement. So you
identify elements, trust boundaries and plausible threats, but you never accept, close or
downgrade a risk on the team's behalf: every threat you write starts as `Open`.

You do not write Threat Dragon's diagram JSON by hand. You write a small, readable
**spec file**, and the bundled script turns it into a valid Threat Dragon v2 model
(layout, ports, styles, numbering). This keeps the output correct whatever agent or model
runs this skill.

## Conventions

- Model folder: `threat-model/` at the repo root (override in `threat-model/config.json`
  with `"modelDir"`). One model per system or major feature: `threat-model/<slug>.json`.
- Draft specs: `threat-model/drafts/<slug>.spec.json` (build) or `<slug>.delta-<date>.json` (update).
- Review notes: `threat-model/<slug>.review.md`.
- Language: write descriptions, mitigations and notes in the language set in
  `threat-model/config.json` (`"language"`), otherwise in the language the user writes in.
  Keep STRIDE category names, severities and statuses in English — Threat Dragon needs those exact strings.
- Script: `scripts/tdtool.py` inside this skill's folder (next to this SKILL.md). Python 3.8+,
  standard library only. Run it with `python3` (or `python` on Windows) from the repo root.

## Workflow

### 1. Scope
Work out what is being modelled and from which sources: a design doc, an ADR, a ticket,
a folder of code, a PR. If the user gave nothing, look for `docs/design/`, `docs/adr/`,
`README*`, API specs (OpenAPI, proto), IaC (Terraform, k8s, docker-compose) and the
entry points of the code. If scope is still unclear, ask one short question instead of guessing.

Check whether `threat-model/<slug>.json` already exists:
- **No model yet** → build mode (steps 2–5).
- **Model exists** → update mode (step 6). Humans may have edited it in Threat Dragon;
  their edits are the source of truth and must survive.

### 2. Inventory the system
Read the sources and list, with evidence (file paths, doc sections):
- **Actors** (external entities): users, admins, partner systems, third-party APIs, LLM providers.
- **Processes**: services, workers, functions, agents, the frontend app.
- **Stores**: databases, caches, queues/topics, buckets, log stores, vector stores, config/secret stores.
- **Flows**: who sends what to whom, protocol, whether it is encrypted, over a public network,
  and whether it carries credentials or personal data.
- **Trust boundaries**: where the level of trust changes (internet ↔ DMZ, app ↔ DB network,
  company ↔ third party, user input ↔ LLM agent with tools, tenant ↔ tenant).

Aim for the level of detail a reviewer can check in one sitting: usually 5–15 elements.
Merge trivial internals; split a component only when its parts sit on different sides of a boundary
or handle data differently. Record every assumption you had to make.

### 3. Enumerate threats
Read `references/stride-guide.md` for per-element questions and the severity rubric.
If the system contains an LLM, agent, RAG pipeline or model-calling code, also read
`references/ai-system-threats.md`.

What makes a threat worth writing:
- **Specific**: names the element, the attacker action and the impact — "authenticated customer
  changes order id and reads another customer's address", not "unauthorized access".
- **Plausible for this design**: grounded in something you saw (or did not see, e.g. no ownership check).
- **Actionable mitigation**: concrete control a developer can implement and test.

Prefer the few threats that matter over a full matrix of generic ones: typically 1–3 per
element that crosses a trust boundary or holds sensitive data, fewer for internal plumbing.
Do not invent controls that "probably exist"; if you cannot tell, write the threat and say in the
review notes what needs to be confirmed.

### 4. Write the spec and build
Write `threat-model/drafts/<slug>.spec.json` following `references/spec-format.md`
(`assets/example.spec.json` is a complete example). Then run:

```bash
python3 <skill-dir>/scripts/tdtool.py build threat-model/drafts/<slug>.spec.json threat-model/<slug>.json
python3 <skill-dir>/scripts/tdtool.py validate threat-model/<slug>.json
```

`build` also writes `threat-model/<slug>.draft-log.json`, which records which threats were
AI-drafted so the team can later measure how many were kept (`tdtool.py stats`). Commit it with the model.
Fix any `ERROR` and re-run. Treat `note:` lines about STRIDE-per-element as prompts to
double-check, not errors.

### 5. Write review notes
Create `threat-model/<slug>.review.md` using this structure:

```markdown
# Threat model review notes: <title>
Draft generated: <date> · Sources: <files/docs read>
## Summary
<elements / flows / threats count; the 3–5 highest-risk threats by T-id, one line each>
## Assumptions to confirm
- <assumption> — <why it matters / which threat depends on it>
## Open questions for the team
- <question>
## Not covered by this draft
- <areas skipped and why, e.g. infra not in repo, mobile app out of scope>
## How to review
Open threat-model/<slug>.json in Threat Dragon. For each threat: keep (Open), set NotApplicable
with a reason, or record a risk decision (Accepted/Transferred) with who decided. Add threats the
draft missed — business-logic abuse is where drafts are weakest.
```

Then tell the user what was created and the top risks, and remind them the model is a draft
until reviewed. Do not commit or push unless asked.

### 6. Update mode (model already exists)
1. Run `tdtool.py extract threat-model/<slug>.json --format md` to see the current model.
2. Compare it with the changed design/code. Identify only what is **new**: elements, flows,
   boundaries, and threats they introduce. Never rewrite, renumber or re-status existing threats.
3. Write a delta spec `threat-model/drafts/<slug>.delta-<YYYYMMDD>.json`. In a delta, `from`/`to`/`target`
   may reference either new ids in the delta or **names of existing elements/flows** exactly as they
   appear in the model; a boundary whose name matches an existing box puts new elements inside it.
4. Run `tdtool.py extend threat-model/<slug>.json <delta>` then `validate`.
5. Append a dated "Update" section to the review notes listing what was added and why.

If an existing threat now looks wrong because the design changed, do not edit it — list it in the
review notes under "Existing threats to re-check".

## If you cannot run Python
Write the spec file anyway and give the user the exact `build`/`validate` commands to run.
Do not hand-write Threat Dragon JSON unless the user insists; if you must, copy the cell
structure from a model built by the script.

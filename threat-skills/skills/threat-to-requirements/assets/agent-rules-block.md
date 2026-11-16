<!-- threat-model:begin (managed by the threat-to-requirements skill; edit outside these markers) -->
## Security requirements from the threat model

This project has a threat model in `threat-model/` (OWASP Threat Dragon) and derived requirements
in `SECURITY-REQUIREMENTS.md`.

- Before changing code that touches authentication, authorization, user or customer data, payments,
  public APIs, file handling, external integrations, secrets, or LLM/agent tools: read
  `SECURITY-REQUIREMENTS.md` and follow every requirement whose "Applies to" covers that code.
- When you implement or rely on a requirement, mention its id (e.g. `SR-004`) in the commit message
  and the merge request description, and add or update the test named in its "Verification" line.
- If your change adds a new external system, endpoint, data store, queue, trust boundary, or a new
  kind of sensitive data flow, say so explicitly in your summary: the threat model must be updated
  (threat-model-draft skill, update mode). Do not edit threat statuses yourself.
- Never weaken a control required by an SR (e.g. remove an authorization check, disable TLS
  verification, log secrets) to make a test or feature pass; stop and ask instead.
<!-- threat-model:end -->

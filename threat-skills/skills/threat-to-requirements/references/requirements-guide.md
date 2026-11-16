# Writing security requirements from threats

## Shape of one requirement

```markdown
### SR-001 · Enforce order ownership on every order read and update
- **Threats:** T-001 (High, Open) · T-002 (High, Open)
- **Applies to:** Order API — `api/orders/router.py`, `api/orders/service.py`; AI Support Assistant tool `get_order`
- **Requirement:** The service layer MUST check that the order belongs to the caller
  (`order.customer_id == token.sub`) before returning or changing it, and MUST return 404 for
  orders the caller does not own. Tools called by the assistant MUST pass the end user's token so
  the same check applies.
- **Verification:** Integration test per order endpoint calling with another customer's order id
  expects 404; test that the `get_order` tool forwards the user token.
- **Status:** Required
```

## Rules of thumb

- **Testable over aspirational.** "MUST reject requests > 1 MB with 413" beats "MUST handle large
  requests safely". If a value is not known, write the requirement with a placeholder in brackets
  and list it as an open question: `[limit to be agreed with PO]`.
- **Say where, not just what.** Component name plus code paths. Search the repo for the handler,
  config or module; if it does not exist yet, name the component and say "new code".
- **Control, not threat.** The requirement describes the protection; the threat link explains why.
- **One control per SR.** If you write "and" between two unrelated controls, split them.
- **Keep the team's words.** The reviewed mitigation text is the decision; tighten wording, do not
  change intent. If you think the mitigation is insufficient, keep it and add a note under
  *Open questions* in your report.
- **Verification methods**, best first: automated test (unit/integration/e2e), static check in CI
  (lint rule, SAST rule, dependency policy), configuration assertion (IaC check), manual review
  checklist item.

## Common mappings

| Threat pattern | Typical requirement |
|---|---|
| IDOR / missing object-level authorization | Ownership/tenant check in service layer for every object access; 404 for foreign ids; test per endpoint |
| Weak or missing authentication between services | mTLS or signed service tokens with audience check; reject unsigned requests; test |
| Injection | Parameterised queries / safe APIs only; input validated against schema; no string-built commands |
| Sensitive data in logs or prompts | Redaction function applied before logging/prompting; test with sample PII |
| Missing audit trail | Append-only audit event with actor, action, target, time, request id for listed actions |
| Flooding / resource exhaustion | Rate limit (per IP/account), payload size limit, timeouts, pagination cap — with numbers |
| Prompt injection driving tools | Tools use end-user identity; server-side authorization; argument allow-list; confirmation for side effects |
| Secrets exposure | Secrets only from the secret store; none in repo, images, client bundles; CI secret scanning |

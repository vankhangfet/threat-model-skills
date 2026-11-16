# STRIDE guide for drafting threats

## STRIDE per element (what Threat Dragon expects)

| Element | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| Actor (external entity) | ✓ | | ✓ | | | |
| Process | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Store | | ✓ | ✓* | ✓ | ✓ | |
| Flow | | ✓ | | ✓ | ✓ | |

*Repudiation on a store mainly matters for log/audit stores. Outside the table is allowed when the
threat is real (the script prints a `note:`), but check it first.

## Questions per category

**Spoofing** — Can someone pretend to be this user/service? How is identity proven (password, SSO,
mTLS, API key, signed token)? Are tokens validated (signature, audience, expiry)? Can a service
identity be stolen from config, CI, or a container? For webhooks/callbacks: is the sender verified?

**Tampering** — Can data be changed in transit (no TLS, TLS not verified) or at rest (writable
bucket, shared DB user)? Can input change queries/commands (SQL/NoSQL/OS/template injection,
deserialization)? Can messages on a queue be forged or replayed? Can client-side values (price,
role, user id) be trusted by the server?

**Repudiation** — Could a user or admin deny an action that matters (payment, deletion, approval,
permission change)? Are such actions logged with who/what/when/request id? Can the application or
an admin alter or delete those logs?

**Information disclosure** — Where do personal, financial, credential or proprietary data flow
and rest? Are responses over-sharing (full objects, stack traces, verbose errors)? Are secrets in
code, logs, URLs, prompts or client bundles? Can one tenant/user read another's data (IDOR,
missing row-level filter, shared cache keys)? Does data leave the company boundary (third-party
APIs, LLM providers, analytics)?

**Denial of service** — What happens under a flood of requests, huge payloads, expensive queries,
regex backtracking, unbounded pagination, or poison messages that crash a worker? Are there
timeouts, rate limits, quotas, and cost limits (cloud/LLM spend)?

**Elevation of privilege** — Is authorization enforced on the server for every action and object
(not just "is logged in")? Can a normal user reach admin functions or other tenants? Does a
process run with more rights than needed (DB superuser, broad IAM role, root container)? Can an
agent or job be steered to act with its own (higher) privileges on a user's behalf?

## Severity rubric (pick the closest; explain unusual choices in the description)

| Severity | Typical meaning |
|---|---|
| Critical | Remote, unauthenticated or trivially exploitable, leading to full compromise, mass data exposure or financial loss. |
| High | Exploitable by an ordinary authenticated user or an external party with moderate effort; exposes other users' sensitive data, money movement, or admin control. |
| Medium | Needs specific conditions, insider access or chaining; limited data or partial service impact. |
| Low | Hard to exploit or minor impact; defence-in-depth gaps. |

Raise severity when the element handles credentials, payments, personal data at scale, or safety
functions; lower it when a strong control is confirmed in code (and say so).

## Writing good threat text

- **Title**: attacker action + target, ≤ 12 words. "Forged refund messages on the queue".
- **Description**: who (attacker), how (precondition + action), impact (what they gain), and the
  evidence or gap you saw ("handler only checks JWT validity, see api/orders.py:L40").
- **Mitigation**: concrete, implementable, testable. Name the layer (gateway, service, DB) and how
  to verify it (a test, a config check). Several controls are fine; separate them with `;`.

Avoid: duplicates of the same threat on every element; generic OWASP Top 10 lists; threats about
components not in scope; mitigations like "follow best practices" or "use security".

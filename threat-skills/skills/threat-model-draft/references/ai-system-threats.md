# Threats specific to LLM / agent / RAG components

Use this when the system calls a language model, runs an agent with tools, or retrieves documents
for a model (RAG). Model the pieces explicitly: the agent/orchestrator as a **process**, the model
provider as an **actor** (it is outside your control), vector stores and prompt/conversation logs as
**stores**, and tool calls as **flows** from the agent to the systems it can touch. Put a trust
boundary between untrusted text (user input, retrieved documents, web pages, emails, tool output)
and anything that acts on it.

Categories below follow the spirit of the OWASP Top 10 for LLM Applications, mapped to STRIDE so
they fit Threat Dragon.

| Threat | STRIDE | Where to attach | Typical mitigations |
|---|---|---|---|
| Direct prompt injection: user text overrides instructions and makes the agent misuse a tool | Elevation of privilege / Tampering | Agent process | Tools run with the end user's identity and permissions; server-side authorization on every tool action; allow-list tool arguments; confirmation step for destructive actions |
| Indirect prompt injection: instructions hidden in retrieved docs, web pages, emails, file contents or tool output | Tampering / Elevation of privilege | Flow from the data source to the agent | Treat retrieved content as data, never instructions; isolate/label untrusted content; restrict what the agent can do after reading untrusted content; human approval for side effects |
| Excessive agency: agent has broader tools/credentials than the task needs | Elevation of privilege | Agent process, tool flows | Least-privilege tool set per use case; scoped short-lived credentials; no generic "run SQL/shell" tools; rate and spend limits |
| Sensitive data sent to the model provider or stored in prompts/logs | Information disclosure | Flow agent → provider; conversation log store | Data minimisation and masking; approved provider/region with no-training and retention terms; redact secrets/PII before logging; retention policy for conversation logs |
| Model output used unsafely (rendered as HTML, executed, used in SQL/shell, trusted as a decision) | Tampering / Elevation of privilege | Process consuming the output | Treat output as untrusted input: encode/escape, validate against schema, never `eval`; authorization never decided by the model |
| Cross-user/tenant leakage via RAG (retrieval ignores document permissions) | Information disclosure | Vector store; retrieval flow | Store ACL metadata with chunks and filter by the caller's identity at query time; separate indexes per tenant where needed |
| Knowledge-base / RAG poisoning: attacker plants content that will be retrieved | Tampering | Ingestion flow; vector store | Control who can add sources; provenance and review for ingested content; monitor for instruction-like text |
| Hallucinated or typo-squatted packages suggested by coding agents ("slopsquatting") | Tampering (supply chain) | Build/CI process | Lockfiles; allow-listed registries/mirror; dependency review in MR; SCA scanning |
| Unbounded consumption: prompt floods, very long contexts, recursive agent loops driving cost or outage | Denial of service | Agent process; flow to provider | Per-user rate limits and token/spend quotas; max steps per agent run; timeouts; alerting on cost |
| System prompt or tool schema leakage revealing internal logic or secrets | Information disclosure | Agent process | Keep secrets out of prompts; assume prompts are discoverable; enforce rules in code, not in prompt text |
| No audit trail of agent actions | Repudiation | Agent process; audit store | Log each tool call with user id, arguments (redacted), result status and correlation id |

When the agent acts on behalf of a user, the most important question is: **whose permissions does
each tool call use, and where are they enforced?** If the answer is "the agent's service account"
and "in the prompt", there is almost always a High threat to write.

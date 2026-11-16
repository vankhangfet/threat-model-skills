# Signals that a change has drifted from the threat model

Treat each as drift when the model has no matching element, flow or boundary.

## New attack surface
- New HTTP routes/controllers, GraphQL resolvers, gRPC methods, WebSocket handlers, CLI commands
  exposed to users, webhooks/callback endpoints.
- New public exposure in IaC: load balancer, ingress, security group/firewall opening, public
  bucket, API gateway stage, port mapping in docker-compose/k8s Service.
- File upload/download, import/export, URL fetching (SSRF risk), template rendering, archive extraction.

## New parties and data paths
- New outbound clients: SDKs or HTTP calls to third-party APIs, payment, email/SMS, analytics,
  telemetry, LLM providers, other internal services.
- New data stores: tables/collections with personal, financial or credential data, caches holding
  user data, queues/topics, buckets, vector stores, local files.
- New categories of sensitive data in an existing flow (e.g. now sending addresses to analytics).

## Changed trust
- Authentication/authorization changes: new roles, permission checks moved or removed, new
  service accounts or IAM policies, token lifetimes, CORS, CSRF settings, session handling.
- Crypto/transport changes: TLS verification disabled, custom crypto, new keys/certificates,
  plaintext protocols.
- Multi-tenant logic changes: tenant id derivation, shared caches, cross-tenant admin features.

## AI / agent specific
- A new tool given to an agent, broader tool arguments, or a tool that now has side effects.
- New retrieval sources for RAG, new ingestion paths, model provider or region changes.
- Agent now acting with a service identity instead of the user's identity.

## Supply chain and build
- New dependencies (check names carefully for typo-squats), new registries, unpinned versions,
  new CI steps with secrets, new container base images.

## Smells worth flagging in the diff (keep it short)
Hardcoded secrets or tokens; string-built SQL/shell/HTML; `eval`/dynamic code execution on input;
disabled certificate checks; broad exception handlers that swallow auth errors; logging of tokens,
passwords or full personal records; debug endpoints or flags enabled; permissive CORS (`*` with
credentials); missing size/time limits on user-controlled work.

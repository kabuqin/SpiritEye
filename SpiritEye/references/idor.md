---
name: idor
description: IDOR/BOLA testing for object-level authorization failures and cross-account data access
---

# IDOR

Object-level authorization failures (BOLA/IDOR) expose data and permit unauthorized modifications across APIs, web, mobile, and microservice architectures. Every object reference arriving from a client must be considered untrusted until the system confirms it belongs to the requesting principal.

## Where to Look

**Scope**
- Horizontal access: one subject reaches another subject's objects of the same classification
- Vertical access: a lower-privilege actor reaches objects or actions reserved for admins or staff
- Cross-tenant access: isolation boundaries collapse in multi-tenant deployments
- Cross-service access: a token issued for one service is accepted by a different service

**Reference Locations**
- Paths, query params, JSON bodies, form-data, headers, cookies
- JWT claims, GraphQL arguments, WebSocket messages, gRPC messages

**Identifier Forms**
- Integers, UUID/ULID/CUID, Snowflake, slugs
- Composite keys (e.g., `{orgId}:{userId}`)
- Opaque tokens, base64/hex-encoded blobs

**Relationship References**
- parentId, ownerId, accountId, tenantId, organization, teamId, projectId, subscriptionId

**Expansion/Projection Knobs**
- `fields`, `include`, `expand`, `projection`, `with`, `select`, `populate`
- These parameters frequently bypass authorization inside resolvers or serializers

## High-Value Targets

- Exports/backups/reporting endpoints (CSV/PDF/ZIP)
- Messaging/mailbox/notifications, audit logs, activity feeds
- Billing: invoices, payment methods, transactions, credits
- Healthcare/education records, HR documents, PII/PHI/PCI
- Admin/staff tools, impersonation/session management
- File/object storage keys (S3/GCS signed URLs, share links)
- Background jobs: import/export job IDs, task results
- Multi-tenant resources: organizations, workspaces, projects

## Reconnaissance

### Parameter Analysis
- Pagination/cursors: `page[offset]`, `page[limit]`, `cursor`, `nextPageToken` — these often reveal or accept cross-tenant or cross-state identifiers
- Directory/list endpoints as seeders: search/list/suggest/export surfaces frequently leak object IDs that feed secondary exploitation

### Enumeration Techniques
- Alternate types: `{"id":123}` vs `{"id":"123"}`, arrays vs scalars, objects vs scalars
- Edge values: null/empty/0/-1/MAX_INT, scientific notation, overflows
- Duplicate keys/parameter pollution: `id=1&id=2`, JSON duplicate keys `{"id":1,"id":2}` (parser precedence)
- Case/aliasing: userId vs userid vs USER_ID; alternate names like resourceId, targetId, account
- Path traversal-like in virtual file systems: `/files/user_123/../../user_456/report.csv`

### UUID/Opaque ID Sources
- Logs, exports, JS bundles, analytics endpoints, emails, public activity
- Time-based IDs (UUIDv1, ULID) may be predictable within a time window

## Vulnerability Patterns

### Horizontal & Vertical Access

- Swap object IDs between principals while holding the same token to probe horizontal access
- Repeat the same requests with lower-privilege tokens to test vertical access
- Target partial updates (PATCH, JSON Patch/JSON Merge Patch) for silent unauthorized modifications

### Bulk & Batch Operations

- Batch endpoints (bulk update/delete) frequently validate only the first element; insert cross-tenant IDs mid-array to test per-item enforcement
- CSV/JSON imports that reference foreign object IDs (ownerId, orgId) may bypass checks applied at creation time

### Secondary IDOR

- Harvest valid IDs from list/search endpoints, notifications, emails, webhooks, and client-side logs
- Directly fetch or mutate those objects using a different principal's token
- Manipulate pagination cursors to skip tenant filters and retrieve another user's pages

### Job/Task Objects

- Access job/task IDs from one user and attempt to retrieve results belonging to another (`export/{jobId}/download`, `reports/{taskId}`)
- Try cancelling or approving another user's queued jobs by referencing their task IDs

### File/Object Storage

- Test direct object paths or weakly scoped signed URLs
- Attempt key prefix modifications, content-disposition tricks, or reuse of stale signatures across tenant boundaries
- Substitute share tokens with tokens originating from other tenants; try case and URL-encoding variants

### GraphQL

- Enforce checks at the resolver level; a top-level gate is insufficient on its own
- Confirm that field and edge resolvers re-bind the resource to the caller on every traversal hop
- Exploit batching and aliases to pull multiple users' nodes within a single request
- Global node patterns (Relay): decode base64 IDs and swap the raw underlying IDs
- Overfetch through fragments targeting privileged types

```graphql
query IDOR {
  me { id }
  u1: user(id: "VXNlcjo0NTY=") { email billing { last4 } }
  u2: node(id: "VXNlcjo0NTc=") { ... on User { email } }
}
```

### Microservices & Gateways

- Token confusion: a token scoped for Service A is accepted by Service B due to shared JWT verification logic that omits audience or claims checks
- Header trust: reverse proxies or API gateways that inject or blindly trust headers like `X-User-Id`, `X-Organization-Id` — try overriding or removing them
- Context loss: async consumers (queues, workers) re-process requests without re-evaluating authorization

### Multi-Tenant

- Probe tenant scoping through headers, subdomains, and path params (`X-Tenant-ID`, org slug)
- Mix the org associated with a token with a resource belonging to a different org
- Test cross-tenant report rollups, analytics aggregations, and admin views that span multiple tenants

### WebSocket

- Verify per-subscription authorization: channel and topic names must not be guessable (`user_{id}`, `org_{id}`)
- Subscribe/publish enforcement must occur server-side on every message, not only at handshake time
- After subscribing to your own channel, attempt to send messages referencing other users' IDs

### gRPC

- Direct protobuf fields (`owner_id`, `tenant_id`) often circumvent HTTP-layer middleware
- Validate cross-principal references using grpcurl with tokens from distinct principals

### Integrations

- Webhooks and callbacks that reference foreign objects (e.g., `invoice_id`) and process them without verifying the owning principal
- Third-party importers that sync data into the wrong tenant due to missing tenant binding at ingest time

## Evasion Patterns

**Parser & Transport**
- Content-type switching: `application/json` ↔ `application/x-www-form-urlencoded` ↔ `multipart/form-data`
- Method tunneling: `X-HTTP-Method-Override`, `_method=PATCH`; or issuing GET requests to endpoints that incorrectly accept state changes
- JSON duplicate keys or array injection to defeat naive validators

**Parameter Pollution**
- Duplicate parameters in query or body to influence server-side precedence (`id=123&id=456`); test both orderings
- Mix case and alias param names so the gateway and backend disagree on which value applies (userId vs userid)

**Cache & Gateway**
- CDN/proxy key confusion: responses cached without the Authorization or tenant header expose stored objects to different users
- Manipulate Vary and Accept headers to influence cache behavior
- Redirect chains and 304/206 partial-content behaviors can leak resources across tenants

**Race Windows**
- Time-of-check vs time-of-use: alter the referenced ID between validation and execution by sending parallel requests

**Blind Channels**
- Use differential responses (status code, body size, ETag, timing) to infer object existence
- Error shapes typically differ between owned and foreign objects
- HEAD/OPTIONS and conditional requests (`If-None-Match`/`If-Modified-Since`) can confirm existence without exposing full content

## Chaining Attacks

- IDOR + CSRF: compel victims to trigger unauthorized changes on objects you have already identified
- IDOR + Stored XSS: pivot into other sessions through data access obtained via IDOR
- IDOR + SSRF: exfiltrate internal IDs, then access the resources those IDs map to
- IDOR + Race: defeat spot checks by firing simultaneous requests

## Analysis Workflow

1. **Build matrix** - Construct a Subject × Object × Action matrix defining who can perform what operation on which resource
2. **Obtain principals** - Acquire at least two: an owner and a non-owner (plus admin/staff if accessible)
3. **Collect IDs** - Capture at least one valid object ID per principal through list/search/export surfaces
4. **Cross-channel testing** - Exercise every action (R/W/D/Export) while alternating IDs, tokens, and tenants
5. **Transport variation** - Cover web, mobile, API, GraphQL, WebSocket, and gRPC
6. **Consistency check** - The same authorization rule must hold regardless of transport, content-type, serialization format, or gateway path

## Confirming a Finding

1. Demonstrate retrieval of an object not belonging to the requesting principal (content or metadata)
2. Show the identical request fails when authorization is correctly enforced
3. Establish cross-channel consistency: reproduce the unauthorized access through at least two transports (e.g., REST and GraphQL)
4. Document tenant boundary violations where applicable
5. Provide reproducible steps and evidence capturing both the owner and non-owner perspectives

## Common False Alarms

- Resources that are public or anonymous by design
- Soft-private data whose content is already publicly accessible
- Idempotent metadata lookups that expose nothing sensitive
- Properly implemented row-level checks enforced uniformly across all channels

## Business Risk

- Cross-account exposure of PII/PHI/PCI data
- Unauthorized state changes including transfers, role assignments, and cancellations
- Cross-tenant data leakage violating contractual and regulatory obligations
- Regulatory liability (GDPR/HIPAA/PCI), fraud exposure, and reputational harm

## Analyst Notes

1. Start with list/search/export endpoints — they are the richest source of ID material
2. Build a reusable ID corpus from logs, notifications, email content, and compiled client bundles
3. Rotate content-types and transports; authorization middleware behavior often diverges across stack layers
4. In GraphQL, enforce checks at every resolver boundary; parent authorization does not automatically cover child resolvers
5. In multi-tenant applications, vary org headers, subdomains, and path params independently from one another
6. Scrutinize batch/bulk operations and background job endpoints — per-item authorization is routinely absent
7. Inspect gateway configurations for header trust relationships and cache key definitions
8. Treat UUIDs as untrusted; source them through OSINT or leakage and test ownership binding
9. Exploit timing, size, and ETag differentials for blind confirmation when response content is suppressed
10. Demonstrate impact with precise before/after diffs and role-separated request/response evidence

## Core Principle

Authorization must bind the subject, the action, and the specific object on every request, independent of identifier opacity or transport protocol. Any gap in that binding creates a vulnerability.

## Java Source Detection Rules

### TRUE POSITIVE: object lookup without ownership binding
- An object identifier arriving from `@PathVariable`, `@RequestParam`, or a request body is passed directly to repository or service calls such as `findById(id)`, `getById(id)`, `deleteById(id)`, or update operations that select only by `id`.
- No ownership or tenant check tied to the current principal exists on the reachable code path — for example, no comparison of `ownerId`, `accountId`, or `tenantId`, and no filtering by both the object id and the authenticated user.
- The endpoint returns or mutates the object without any visible authorization guard beyond possession of the identifier itself.

### FALSE POSITIVE: admin-only endpoint with enforced role check
- `@PreAuthorize("hasRole('ADMIN')")`, `@Secured("ROLE_ADMIN")`, `@RolesAllowed("ADMIN")`, or equivalent Spring Security configuration explicitly restricts the endpoint or method to privileged roles.
- Repository queries such as `findByIdAndUserId(id, currentUserId)` or explicit guards like `if (!entity.getOwnerId().equals(currentUserId))` demonstrate that access is bound to the authenticated principal.
- Do not flag IDOR when the code shows both authentication-context usage and an authorization check preceding the object return or modification.

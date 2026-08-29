---
name: race-conditions
description: Race condition testing for TOCTOU bugs, double-spend, and concurrent state manipulation
---

# Race Conditions

Concurrency bugs enable duplicate state changes, quota bypass, financial abuse, and privilege errors. Treat every read–modify–write and multi-step workflow as adversarially concurrent.

## Where to Look

**Read-Modify-Write**
- Sequences without atomicity or proper locking

**Multi-Step Operations**
- Check → reserve → commit with gaps between phases

**Cross-Service Workflows**
- Sagas, async jobs with eventual consistency

**Rate Limits and Quotas**
- Controls implemented at the edge only

## High-Value Targets

- Payments: auth/capture/refund/void; credits/loyalty points; gift cards
- Coupons/discounts: single-use codes, stacking checks, per-user limits
- Quotas/limits: API usage, inventory reservations, seat counts, vote limits
- Auth flows: password reset/OTP consumption, session minting, device trust
- File/object storage: multi-part finalize, version writes, share-link generation
- Background jobs: export/import create/finalize endpoints; job cancellation/approve
- GraphQL mutations and batch operations; WebSocket actions

## Reconnaissance

### Identify Race Windows

- Look for explicit sequences: "check balance then deduct", "verify coupon then apply", "check inventory then purchase"
- Watch for optimistic concurrency markers: ETag/If-Match, version fields, updatedAt checks
- Examine idempotency-key support: scope (path vs principal), TTL, and persistence (cache vs DB)
- Map cross-service steps: when is state written vs published, what retries/compensations exist

### Signals

- Sequential request fails but parallel succeeds
- Duplicate rows, negative counters, over-issuance, or inconsistent aggregates
- Distinct response shapes/timings for simultaneous vs sequential requests
- Audit logs out of order; multiple 2xx for the same intent; missing or duplicate correlation IDs

## Vulnerability Patterns

### Request Synchronization

- HTTP/2 multiplexing for tight concurrency; send many requests on warmed connections
- Last-byte synchronization: hold requests open and release final byte simultaneously
- Connection warming: pre-establish sessions, cookies, and TLS to remove jitter

### Idempotency and Dedup Bypass

- Reuse the same idempotency key across different principals/paths if scope is inadequate
- Hit the endpoint before the idempotency store is written (cache-before-commit windows)
- App-level dedup drops only the response while side effects (emails/credits) still occur

### Atomicity Gaps

- Lost update: read-modify-write increments without atomic DB statements
- Partial two-phase workflows: success committed before validation completes
- Unique checks done outside a unique index/upsert: create duplicates under load

### Cross-Service Races

- Saga/compensation timing gaps: execute compensation without preventing the original success path
- Eventual consistency windows: act in Service B before Service A's write is visible
- Retry storms: duplicate side effects due to at-least-once delivery without idempotent consumers

### Rate Limits and Quotas

- Per-IP or per-connection enforcement: bypass with multiple IPs/sessions
- Counter updates not atomic or sharded inconsistently; send bursts before counters propagate

### Optimistic Concurrency Evasion

- Omit If-Match/ETag where optional; supply stale versions if server ignores them
- Version fields accepted but not validated across all code paths (e.g., GraphQL vs REST)

### Database Isolation

- Exploit READ COMMITTED/REPEATABLE READ anomalies: phantoms, non-serializable sequences
- Upsert races: use unique indexes with proper ON CONFLICT/UPSERT or exploit naive existence checks
- Lock granularity issues: row vs table; application locks held only in-process

### Distributed Locks

- Redis locks without NX/EX or fencing tokens allow multiple winners
- Locks stored in memory on a single node; bypass by hitting other nodes/regions

## Evasion Patterns

- Distribute across IPs, sessions, and user accounts to evade per-entity throttles
- Switch methods/content-types/endpoints that trigger the same state change via different code paths
- Intentionally trigger timeouts to provoke retries that cause duplicate side effects
- Degrade the target (large payloads, slow endpoints) to widen race windows

## Special Contexts

### GraphQL

- Parallel mutations and batched operations may bypass per-mutation guards
- Ensure resolver-level idempotency and atomicity
- Persisted queries and aliases can hide multiple state changes in one request

### WebSocket

- Per-message authorization and idempotency must hold
- Concurrent emits can create duplicates if only the handshake is checked

### Files and Storage

- Parallel finalize/complete on multi-part uploads can create duplicate or corrupted objects
- Re-use pre-signed URLs concurrently

### Auth Flows

- Concurrent consumption of one-time tokens (reset codes, magic links) to mint multiple sessions
- Verify consume is atomic

## Chaining Attacks

- Race + Business logic: violate invariants (double-refund, limit slicing)
- Race + IDOR: modify or read others' resources before ownership checks complete
- Race + CSRF: trigger parallel actions from a victim to amplify effects
- Race + Caching: stale caches re-serve privileged states after concurrent changes

## Analysis Workflow

1. **Model invariants** - Conservation of value, uniqueness, maximums for each workflow
2. **Identify reads/writes** - Where they occur (service, DB, cache)
3. **Baseline** - Single requests to establish expected behavior
4. **Concurrent requests** - Issue parallel requests with identical inputs; observe deltas
5. **Scale and synchronize** - Ramp up parallelism, use HTTP/2, align timing (last-byte sync)
6. **Cross-channel** - Test across web, API, GraphQL, WebSocket
7. **Confirm durability** - Verify state changes persist and are reproducible

## Confirming a Finding

1. Single request denied; N concurrent requests succeed where only 1 should
2. Durable state change proven (ledger entries, inventory counts, role/flag changes)
3. Reproducible under controlled synchronization (HTTP/2, last-byte sync) across multiple runs
4. Evidence across channels (e.g., REST and GraphQL) if applicable
5. Include before/after state and exact request set used

## Common False Alarms

- Truly idempotent operations with enforced ETag/version checks or unique constraints
- Serializable transactions or correct advisory locks/queues
- Visual-only glitches without durable state change
- Rate limits that reject excess with atomic counters

## Business Risk

- Financial loss (double spend, over-issuance of credits/refunds)
- Policy/limit bypass (quotas, single-use tokens, seat counts)
- Data integrity corruption and audit trail inconsistencies
- Privilege or role errors due to concurrent updates

## Analyst Notes

1. Favor HTTP/2 with warmed connections; add last-byte sync for precision
2. Start small (N=5–20), then scale; too much noise can mask the window
3. Target read–modify–write code paths and endpoints with idempotency keys
4. Compare REST vs GraphQL vs WebSocket; protections often differ
5. Look for cross-service gaps (queues, jobs, webhooks) and retry semantics
6. Check unique constraints and upsert usage; avoid relying on pre-insert checks
7. Use correlation IDs and logs to prove concurrent interleaving
8. Widen windows by adding server load or slow backend dependencies
9. Validate on production-like latency; some races only appear under real load
10. Document minimal, repeatable request sets that demonstrate durable impact

## Core Principle

Concurrency safety is a property of every path that mutates state. If any path lacks atomicity, proper isolation, or idempotency, parallel requests will eventually break invariants.

## Java Source Detection Rules

### TRUE POSITIVE: Spring controller singleton with mutable instance field (CWE-362)
- Spring `@Controller`, `@RestController`, and `@Service` beans are **singleton-scoped by default**. Any mutable instance field written per-request is shared across all concurrent requests.
- Pattern: a field declared at class level (e.g., `User user = new User();`) is written inside a request handler method (`user.setId(...)`, `user.setName(...)`) — CONFIRM as CWE-362.
- The fix is always to use a local variable inside the method, not a class-level field.
- Concurrent requests will interleave writes to the shared field, corrupting data.

### FALSE POSITIVE
- `static final` constants — immutable, not a race condition.
- Fields annotated with `@Autowired`, `@Inject`, or Spring-managed dependencies — these are injected once and are effectively immutable references (though their internal state may still be mutable).
- Fields only read, never written per-request.

## Python/JS/PHP Source Detection Rules

### Python (Flask / Django)
- **VULN**: check-then-act without database-level lock:
  ```python
  balance = db.query(User).get(user_id).balance
  if balance >= amount:
      # race window here
      db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, user_id))
  ```
- **VULN**: Financial operations without `SELECT FOR UPDATE`
- **VULN**: File operations: `if not os.path.exists(path): open(path, 'w').write(...)`
- **SAFE**: Django `F()` expressions, `select_for_update()`, `@transaction.atomic`

### JavaScript (Node.js)
- **VULN**: async check-then-act without DB-level lock:
  ```js
  const user = await User.findById(id);
  if (user.credits > 0) {
    await User.updateOne({_id: id}, {$inc: {credits: -1}});
  }
  ```
- **SAFE**: MongoDB atomic operators: `User.findOneAndUpdate({_id: id, credits: {$gt: 0}}, {$inc: {credits: -1}})`

### PHP
- **VULN**: `if ($balance >= $amount) { /* no lock */ $balance -= $amount; }`
- **SAFE**: `SELECT ... FOR UPDATE` inside a transaction before modifying balance
- In `JavaSecLab` payment demos, replay/double-submit and delayed balance updates under `logic/pay` should preserve benchmark tag `concurrency` when concurrent interleaving is the intended flaw.
- FALSE POSITIVE guard: do not emit `race_conditions` as a separate tag when the benchmark taxonomy already collapses the same evidence into `concurrency`.

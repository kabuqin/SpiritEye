---
name: business-logic
description: Business logic testing for workflow bypass, state manipulation, and domain invariant violations
---

# Business Logic Flaws

Business logic flaws exploit intended functionality to violate domain invariants: move money without paying, exceed limits, retain privileges, or bypass reviews. They require a model of the business, not just payloads.

## Where to Look

- Financial logic: pricing, discounts, payments, refunds, credits, chargebacks
- Account lifecycle: signup, upgrade/downgrade, trial, suspension, deletion
- Authorization-by-logic: feature gates, role transitions, approval workflows
- Quotas/limits: rate/usage limits, inventory, entitlements, seat licensing
- Multi-tenant isolation: cross-organization data or action bleed
- Event-driven flows: jobs, webhooks, sagas, compensations, idempotency

## High-Value Targets

- Pricing/cart: price locks, quote to order, tax/shipping computation
- Discount engines: stacking, mutual exclusivity, scope (cart vs item), once-per-user enforcement
- Payments: auth/capture/void/refund sequences, partials, split tenders, chargebacks, idempotency keys
- Credits/gift cards/vouchers: issuance, redemption, reversal, expiry, transferability
- Subscriptions: proration, upgrade/downgrade, trial extension, seat counts, meter reporting
- Refunds/returns/RMAs: multi-item partials, restocking fees, return window edges
- Admin/staff operations: impersonation, manual adjustments, credit/refund issuance, account flags
- Quotas/limits: daily/monthly usage, inventory reservations, feature usage counters

## Reconnaissance

### Workflow Mapping

- Derive endpoints from the UI and proxy/network logs; map hidden/undocumented API calls, especially finalize/confirm endpoints
- Identify tokens/flags: stepToken, paymentIntentId, orderStatus, reviewState, approvalId; test reuse across users/sessions
- Document invariants: conservation of value (ledger balance), uniqueness (idempotency), monotonicity (non-decreasing counters), exclusivity (one active subscription)

### Input Surface

- Hidden fields and client-computed totals; server must recompute on trusted sources
- Alternate encodings and shapes: arrays instead of scalars, objects with unexpected keys, null/empty/0/negative, scientific notation
- Business selectors: currency, locale, timezone, tax region; vary to trigger rounding and ruleset changes

### State and Time Axes

- Replays: resubmit stale finalize/confirm requests
- Out-of-order: call finalize before verify; refund before capture; cancel after ship
- Time windows: end-of-day/month cutovers, daylight saving, grace periods, trial expiry edges

## Vulnerability Patterns

### State Machine Abuse

- Skip or reorder steps via direct API calls; verify server enforces preconditions on each transition
- Replay prior steps with altered parameters (e.g., swap price after approval but before capture)
- Split a single constrained action into many sub-actions under the threshold (limit slicing)

### Concurrency and Idempotency

- Parallelize identical operations to bypass atomic checks (create, apply, redeem, transfer)
- Abuse idempotency: key scoped to path but not principal → reuse other users' keys; or idempotency stored only in cache
- Message reprocessing: queue workers re-run tasks on retry without idempotent guards; cause duplicate fulfillment/refund

### Numeric and Currency

- Floating point vs decimal rounding; rounding/truncation favoring attacker at boundaries
- Cross-currency arbitrage: buy in currency A, refund in B at stale rates; tax rounding per-item vs per-order
- Negative amounts, zero-price, free shipping thresholds, minimum/maximum guardrails

### Quotas, Limits, and Inventory

- Off-by-one and time-bound resets (UTC vs local); pre-warm at T-1s and post-fire at T+1s
- Reservation/hold leaks: reserve multiple, complete one, release not enforced; backorder logic inconsistencies
- Distributed counters without strong consistency enabling double-consumption

### Refunds and Chargebacks

- Double-refund: refund via UI and support tool; refund partials summing above captured amount
- Refund after benefits consumed (downloaded digital goods, shipped items) due to missing post-consumption checks

### Feature Gates and Roles

- Feature flags enforced client-side or at edge but not in core services; toggle names guessed or fallback to default-enabled
- Role transitions leaving stale capabilities (retain premium after downgrade; retain admin endpoints after demotion)

## Advanced Techniques

### Event-Driven Sagas

- Saga/compensation gaps: trigger compensation without original success; or execute success twice without compensation
- Outbox/Inbox patterns missing idempotency → duplicate downstream side effects
- Cron/backfill jobs operating outside request-time authorization; mutate state broadly

### Microservices Boundaries

- Cross-service assumption mismatch: one service validates total, another trusts line items; alter between calls
- Header trust: internal services trusting X-Role or X-User-Id from untrusted edges
- Partial failure windows: two-phase actions where phase 1 commits without phase 2, leaving exploitable intermediate state

### Multi-Tenant Isolation

- Tenant-scoped counters and credits updated without tenant key in the where-clause; leak across orgs
- Admin aggregate views allowing actions that impact other tenants due to missing per-tenant enforcement

## Evasion Patterns

- Content-type switching (JSON/form/multipart) to hit different code paths
- Method alternation (GET performing state change; overrides via X-HTTP-Method-Override)
- Client recomputation: totals, taxes, discounts computed on client and accepted by server
- Cache/gateway differentials: stale decisions from CDN/APIM that are not identity-aware

## Special Contexts

### E-commerce

- Stack incompatible discounts via parallel apply; remove qualifying item after discount applied; retain free shipping after cart changes
- Modify shipping tier post-quote; abuse returns to keep product and refund

### Banking/Fintech

- Split transfers to bypass per-transaction threshold; schedule vs instant path inconsistencies
- Exploit grace periods on holds/authorizations to withdraw again before settlement

### SaaS/B2B

- Seat licensing: race seat assignment to exceed purchased seats; stale license checks in background tasks
- Usage metering: report late or duplicate usage to avoid billing or to over-consume

## Chaining Attacks

- Business logic + race: duplicate benefits before state updates
- Business logic + IDOR: operate on others' resources once a workflow leak reveals IDs
- Business logic + CSRF: force a victim to complete a sensitive step sequence

## Analysis Workflow

1. **Enumerate state machine** - Per critical workflow (states, transitions, pre/post-conditions); note invariants
2. **Build Actor × Action × Resource matrix** - Unauth, basic user, premium, staff/admin; identify actions per role
3. **Test transitions** - Step skipping, repetition, reordering, late mutation
4. **Introduce variance** - Time, concurrency, channel (mobile/web/API/GraphQL), content-types
5. **Validate persistence boundaries** - All services, queues, and jobs re-enforce invariants

## Confirming a Finding

1. Show an invariant violation (e.g., two refunds for one charge, negative inventory, exceeding quotas)
2. Provide side-by-side evidence for intended vs abused flows with the same principal
3. Demonstrate durability: the undesired state persists and is observable in authoritative sources (ledger, emails, admin views)
4. Quantify impact per action and at scale (unit loss × feasible repetitions)

## Common False Alarms

- Promotional behavior explicitly allowed by policy (documented free trials, goodwill credits)
- Visual-only inconsistencies with no durable or exploitable state change
- Admin-only operations with proper audit and approvals

## Business Risk

- Direct financial loss (fraud, arbitrage, over-refunds, unpaid consumption)
- Regulatory/contractual violations (billing accuracy, consumer protection)
- Denial of inventory/services to legitimate users through resource exhaustion
- Privilege retention or unauthorized access to premium features

## Analyst Notes

1. Start from invariants and ledgers, not UI—prove conservation of value breaks
2. Test with time and concurrency; many bugs only appear under pressure
3. Recompute totals server-side; never accept client math—flag when you observe otherwise
4. Treat idempotency and retries as first-class: verify key scope and persistence
5. Probe background workers and webhooks separately; they often skip auth and rule checks
6. Validate role/feature gates at the service that mutates state, not only at the edge
7. Explore end-of-period edges (month-end, trial end, DST) for rounding and window issues
8. Use minimal, auditable PoCs that demonstrate durable state change and exact loss
9. Chain with authorization tests (IDOR/Function-level access) to magnify impact
10. When in doubt, map the state machine; gaps appear where transitions lack server-side guards

## Core Principle

Business logic security is the enforcement of domain invariants under adversarial sequencing, timing, and inputs. If any step trusts the client or prior steps, expect abuse.

## Static Analysis Heuristics for Business Logic Flaws

Business logic flaws are notoriously hard to detect statically, but the following code patterns are strong indicators:

### 1. Client-Side-Only Enforcement
When security-critical decisions are enforced only in JavaScript/HTML but not validated server-side:
```python
# VULN: hidden form field controls admin access — no server-side check
# HTML: <input type="hidden" name="isAdmin" value="0">
if request.form.get('isAdmin') == '1':
    grant_admin_access()
```
```php
// VULN: client-side role check, server trusts whatever arrives
if ($_POST['role'] === 'admin') {
    $_SESSION['role'] = 'admin';  // no verification against DB
}
```

### 2. Type Juggling / Loose Comparison Auth Bypass
When authentication or authorization uses loose comparison that can be tricked:
```php
// VULN: strcmp returns NULL on type juggling (array input), NULL == 0 is true
if (strcmp($_POST['password'], $stored_password) == 0) { login(); }

// VULN: MD5 magic hash — '0e...' == '0e...' is true in loose comparison
if (md5($_POST['password']) == $stored_hash) { login(); }
```

### 3. Hardcoded Verification / 2FA Codes
```python
# VULN: 2FA code is hardcoded, not generated per-session
if request.form['2fa_code'] == '1234':
    session['2fa_verified'] = True
```

### 4. Missing Server-Side Price/Amount Validation
When the server accepts client-computed values for financial transactions:
```python
# VULN: total comes from client, not recomputed from item prices
total = request.form['total']
charge_payment(total)
```

### 5. State Machine Violations
When critical workflow steps can be skipped or reordered:
```python
# VULN: no check that step 1 (verification) was completed before step 2 (action)
@app.route('/transfer', methods=['POST'])
def transfer():
    # missing: if not session.get('verified'): abort(403)
    do_transfer(request.form['amount'], request.form['to'])
```

### 6. HTTP Method Tampering
When access control checks apply only to certain HTTP methods:
```python
# VULN: POST is protected but GET/PUT/DELETE bypass the check
@app.route('/admin/action', methods=['GET', 'POST', 'PUT', 'DELETE'])
def admin_action():
    if request.method == 'POST':
        if not current_user.is_admin:
            abort(403)
    # GET/PUT/DELETE reach here without admin check
    perform_action()
```
```
# .htaccess — VULN: only protects GET and POST
<Limit GET POST>
    Require valid-user
</Limit>
# PUT, DELETE, PATCH bypass authentication entirely
```

### 7. Insufficient Rate Limiting on Sensitive Operations
When brute-forceable operations lack rate limiting:
```python
# VULN: no rate limit on password reset / OTP verification
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    if request.form['otp'] == session['otp']:  # 4-digit = 10000 attempts
        reset_password()
```

### When to Tag Business Logic
- The vulnerability **cannot be described by a more specific injection or access control class**
- The flaw is in the **application's domain rules**, not in generic input handling
- The exploit involves **abusing intended functionality** rather than injecting payloads
- Client-side-only enforcement of critical business rules
- HTTP method tampering that bypasses access controls
- Type juggling or loose comparison that breaks authentication logic

### Relationship to Concurrency

| Signal | Tag | Rationale |
|--------|-----|-----------|
| Race condition on shared resource (double-spend, TOCTOU) | `race_conditions` | Primary exploit is timing/concurrency |
| Business rule bypass that uses parallel requests as the mechanism | `business_logic` | Primary exploit is domain invariant violation; concurrency is only the vehicle |
| Idempotency key reuse across users | `business_logic` | Domain-level key scoping flaw, not a raw concurrency bug |
| Thread-pool exhaustion via unbounded parallel requests | `denial_of_service` | Resource exhaustion, not a business rule |

When both concurrency AND business logic are present, prefer the tag that describes the **primary exploit primitive**. If the attacker must violate a domain invariant (price, quota, state machine) to achieve impact, tag `business_logic` even if concurrency is the delivery mechanism.

### Tag Precision in Benchmark Mode

To reduce false positives, apply the following guardrails when tagging `business_logic`:

- Do NOT emit `business_logic` when a more specific tag fully describes the vulnerability (e.g., `csrf`, `idor`, `race_conditions`, `brute_force`)
- Do NOT emit `business_logic` for missing input validation that is better described as an injection class (SQLi, XSS, etc.)
- Do NOT emit `business_logic` for generic missing authorization -- prefer `privilege_escalation` or `idor`
- Emit `business_logic` only when the flaw is in the **application's domain rules** and cannot be reduced to a standard vulnerability class

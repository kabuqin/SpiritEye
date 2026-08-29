---
name: authentication-jwt
description: JWT and OIDC security testing covering token forgery, algorithm confusion, and claim manipulation
---

# Authentication / JWT / OIDC

Weaknesses in JWT and OIDC implementations frequently allow token forgery, cross-context token acceptance, service confusion, and durable account takeover. Headers, claims, and token opacity must never be trusted without strict validation that binds the token to the correct issuer, audience, key, and client context.

## Where to Look

- Web, mobile, and API authentication built on JWT (JWS/JWE) and OIDC/OAuth2
- Access tokens, ID tokens, refresh tokens, device code flows, PKCE, and Backchannel flows
- First-party and microservice verification logic, API gateways, and JWKS distribution endpoints

## Reconnaissance

### Endpoints

- Well-known: `/.well-known/openid-configuration`, `/oauth2/.well-known/openid-configuration`
- Keys: `/jwks.json`, rotating key endpoints, tenant-specific JWKS URLs
- Auth: `/authorize`, `/token`, `/introspect`, `/revoke`, `/logout`, device code endpoints
- App: `/login`, `/callback`, `/refresh`, `/me`, `/session`, `/impersonate`

### Token Features

- Headers: `{"alg":"RS256","kid":"...","typ":"JWT","jku":"...","x5u":"...","jwk":{...}}`
- Claims: `{"iss":"...","aud":"...","azp":"...","sub":"user","scope":"...","exp":...,"nbf":...,"iat":...}`
- Formats: JWS (signed), JWE (encrypted). Note the unencoded payload option (`"b64":false`) and critical headers (`"crit"`)

## Vulnerability Patterns

### Signature Verification

- RS256→HS256 confusion: change alg to HS256 and use the RSA public key as the HMAC secret when algorithm pinning is absent
- "none" algorithm acceptance: set `"alg":"none"` and omit the signature if libraries process it without rejection
- ECDSA malleability/misuse: weak verification settings that accept non-canonical signatures

### Header Manipulation

- **kid injection**: path traversal `../../../../keys/prod.key`, SQL/command/template injection in key lookup, or references to world-readable files
- **jku/x5u abuse**: host attacker-controlled JWKS/X509 chain; if not pinned or whitelisted, the server fetches and trusts attacker keys
- **jwk header injection**: embed attacker JWK directly in the token header; certain libraries prefer the inline JWK over server-configured keys
- **SSRF via remote key fetch**: exploit the JWKS URL retrieval mechanism to reach internal hosts

### Key and Cache Issues

- JWKS caching TTL and key rollover: accepting obsolete keys, racing key rotation windows, and missing kid pinning that causes any matching kty/alg to be accepted
- Mixed environments: identical secrets shared across dev/stage/prod; keys reused across tenants or unrelated services
- Fallbacks: verification logic that succeeds when kid is not found by cycling through all keys or skipping verification entirely (implementation bugs)

### Claims Validation Gaps

- iss/aud/azp not enforced: cross-service token reuse; tokens from any issuer or the wrong audience are accepted
- scope/roles fully trusted from token: the server does not re-derive authorization; privilege inflation via claim manipulation when signature checks are weak
- exp/nbf/iat not enforced or excessively broad clock skew tolerance; long-expired or not-yet-valid tokens are accepted
- typ/cty not enforced: ID tokens accepted where access tokens are required (token confusion)

### Token Confusion and OIDC

- Access vs ID token swap: use an ID token against APIs that verify the signature but not the audience or typ
- OIDC mix-up: redirect_uri and client mix-ups causing tokens minted for Client A to be redeemed at Client B
- PKCE downgrades: missing S256 enforcement; plain or absent code_verifier accepted
- State/nonce weaknesses: predictable or absent values leading to CSRF or logical interception of the login flow
- Device/Backchannel flows: codes and tokens accepted by unintended clients or services

### Refresh and Session

- Refresh token rotation not enforced: old refresh tokens reusable indefinitely with no reuse detection
- Long-lived JWTs with no revocation mechanism: access persists after logout
- Session fixation: new tokens bound to attacker-controlled session identifiers or cookies

### Transport and Storage

- Token in localStorage/sessionStorage: vulnerable to XSS-based exfiltration; cookie vs header trade-offs with SameSite and CSRF
- Insecure CORS: wildcard origins combined with credentialed requests expose tokens and protected responses
- TLS and cookie flags: missing Secure/HttpOnly; absence of mTLS or DPoP/"cnf" binding allows token replay from a different device

## Advanced Techniques

- **Microservice audience mismatch**: internal services verify signature but ignore aud, accepting tokens destined for other services
- **Gateway header trust**: edge injects X-User-Id; backend trusts it over actual token claims
- **JWS edge cases**: unencoded payload (b64=false) mishandling; nested JWT verification order errors
- **Mobile**: deep-link/redirect bugs leak codes/tokens; insecure WebView bridges; plaintext token storage
- **SSO federation**: stale metadata or obsolete keys cause acceptance of foreign tokens

## Chaining Attacks

- XSS → token theft → replay across services with weak audience enforcement
- SSRF → fetch private JWKS → sign tokens accepted by internal services
- Host header poisoning → OIDC redirect_uri poisoning → authorization code capture

## Analysis Workflow

1. **Inventory issuers/consumers** - Identity providers, API gateways, services, and mobile/web clients
2. **Capture tokens** - Obtain access and ID tokens for multiple roles; examine headers, claims, and signatures
3. **Map verification endpoints** - `/.well-known`, `/jwks.json`
4. **Build matrix** - Token Type × Audience × Service; attempt cross-context use
5. **Mutate components** - Headers (alg, kid, jku/x5u/jwk), claims (iss/aud/azp/sub/exp), and signatures
6. **Verify enforcement** - Determine what is actually validated versus assumed

## Confirming a Finding

1. Demonstrate acceptance of a forged or cross-context token (wrong algorithm, wrong audience/issuer, or attacker-signed JWKS)
2. Show access token vs ID token confusion at an API endpoint
3. Prove refresh token reuse succeeds without rotation detection or revocation
4. Confirm header abuse (kid/jku/x5u/jwk) that places key selection under attacker control
5. Provide evidence from both owner and non-owner contexts using requests that differ only in token content

## Common False Alarms

- Token rejected due to strict audience and issuer enforcement
- Key pinning with a JWKS whitelist and TLS validation in place
- Short-lived tokens with rotation and revocation triggered on logout
- ID tokens not accepted by APIs that require access tokens
- Missing-auth observations based solely on absent framework security configuration are insufficient without a concrete sensitive endpoint or action
- Hardcoded credentials in sample, tutorial, demo, or example applications must not be treated as production authentication flaws unless they are clearly deployed defaults

## Business Risk

- Account takeover and persistence of durable attacker sessions
- Privilege escalation through claim manipulation or cross-service token acceptance
- Cross-tenant or cross-application data access
- Token minting controlled by attacker-held keys or endpoints

## Analyst Notes

1. Test RS256→HS256 and "none" first only when algorithm pinning is unclear; otherwise focus on header-based key control (kid/jku/x5u/jwk)
2. Replay tokens across all services — many backends check signature only, skipping audience and typ
3. Validate every acceptance path: gateway, service, background worker, WebSocket, and gRPC
4. Treat the refresh token surface independently: verify rotation, reuse detection, and audience scoping
5. Exercise OIDC flows with PKCE, state, and nonce variations across mixed clients

## Core Principle

Verification must bind the token to the correct issuer, audience, key, and client context on every acceptance path. Any missing binding enables forgery or confusion.

## Source Detection Rules

### Python (PyJWT / python-jose)
- **VULN**: `jwt.decode(token, key, algorithms=["none"])` — accepts none algorithm
- **VULN**: `jwt.decode(token, options={"verify_signature": False})` — skips signature verification
- **VULN**: `jwt.decode(token, key, algorithms=jwt.get_unverified_header(token)['alg'])` — algorithm confusion
- **SAFE**: `jwt.decode(token, SECRET_KEY, algorithms=["HS256"])` — fixed algorithm
- **Pattern**: Any `verify=False` or `options={"verify_*": False}` = HIGH RISK

### JavaScript (jsonwebtoken)
- **VULN**: `jwt.verify(token, secret, { algorithms: ['none'] })`
- **VULN**: `jwt.decode(token)` used for authorization decisions (decodes without verification)
- **VULN**: Algorithm taken from token header and passed directly to verify
- **SAFE**: `jwt.verify(token, SECRET, { algorithms: ['HS256'] })`

### PHP
- **VULN**: `JWT::decode($token, null, ['none'])` — Firebase JWT with null key and none algorithm
- **VULN**: Base64-decoding claims and using them without signature verification
- **Pattern**: Any `alg: none` acceptance = CRITICAL

## FALSE POSITIVE Rules

- Do NOT emit `jwt` or `authentication_jwt` when the project already has an `authentication` tag for the same auth weakness — use the more precise tag. Emit `jwt` only when the vulnerability is specifically in JWT implementation (algorithm confusion, weak signing key, missing validation), not general authentication bypass.
- Do NOT emit for JWT libraries used correctly with proper algorithm pinning, key management, and claim validation — even if the signing key is hardcoded in a demo/test context.
- Cookie flag issues alone are not `authentication_jwt` unless a JWT validation or token-trust flaw is present.
- Emit `jwt` only when an attacker-supplied token from a header, cookie, or parameter is actually verified or accepted by a mapped vulnerable route. Helper classes, token-generation demos, and storage-only examples are insufficient alone.

## Session Fixation Detection

See dedicated `references/session_fixation.md` for CWE-384 detection rules, Java Servlet patterns, and Spring Security configuration checks.

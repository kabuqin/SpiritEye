---
name: session_fixation
description: Session fixation detection — session ID not regenerated on authentication state change
---

# Session Fixation

Session fixation occurs when a web application does not issue a new session identifier after a successful authentication event. An attacker who can set or predict the pre-authentication session ID retains access to the authenticated session, resulting in full account takeover (CWE-384).

## Overview

The attack works in three steps: (1) the attacker obtains or forces a known session ID onto the victim's browser (via URL parameter, cookie injection, or a subdomain cookie), (2) the victim authenticates using that session, and (3) because the server never rotates the session ID, the attacker's copy of the ID is now bound to the victim's authenticated context.

## Where to Look

- **Login handlers** — servlet `doPost` methods, Spring `@PostMapping("/login")`, custom authentication filters
- **Authentication success callbacks** — Spring Security `AuthenticationSuccessHandler`, custom post-login redirects
- **Session management configuration** — `SecurityFilterChain` or `WebSecurityConfigurerAdapter` beans, `<session-management>` XML
- **Password reset and identity change flows** — any endpoint that elevates privilege or switches the bound user identity
- **OAuth/OIDC callback handlers** — code-exchange endpoints that establish a server-side session after token validation
- **Multi-step authentication** — flows where the session survives across challenge steps without regeneration

## Vulnerability Patterns

### Java / Spring

- Login controller calls `request.getSession()` to read user data but never calls `session.invalidate()` or `request.changeSessionId()` before or after storing authenticated attributes
- Spring Security config omits `sessionManagement()` entirely **and** uses a custom authentication flow that bypasses the default filter chain
- Explicit `sessionFixation().none()` in the security config — disables all session ID rotation
- Manual session attribute copying (e.g., `Utils.setSessionUserName(session, user)`) without first invalidating the old session

### PHP

- `$_SESSION['user'] = $username;` after `session_start()` without calling `session_regenerate_id(true)` on successful login
- Custom login scripts that set session variables directly without regeneration

### Node.js / Express

- `req.session.user = authenticatedUser;` without calling `req.session.regenerate()` first
- Passport.js default `serializeUser` without session regeneration middleware

### Python / Django

- Django's built-in auth views call `login()` which rotates the session key by default — manual login flows that skip `django.contrib.auth.login()` and directly set `request.session['user']` are vulnerable
- Flask: `session['user'] = username` without regenerating the session via `session.regenerate()` or equivalent

## Java / Spring Detection Rules

### TRUE POSITIVE

- **No `session.invalidate()` on login**: a login handler sets session attributes (e.g., user identity, roles) after authentication succeeds but does not call `session.invalidate()` followed by `request.getSession(true)`, nor `request.changeSessionId()`, anywhere in the login path.
- **`sessionFixation().none()`**: Spring Security configuration explicitly disables session fixation protection.
- **Custom auth filter without regeneration**: a filter extending `UsernamePasswordAuthenticationFilter` or `OncePerRequestFilter` that authenticates the user and populates `SecurityContextHolder` without triggering session ID rotation.
- **Identity switch without session reset**: code that changes the session-bound user identity (e.g., via a helper like `setSessionUserName()`) without invalidating and re-creating the session — the old session ID remains valid under the new identity.

### FALSE POSITIVE

- **Spring Security default config**: since Spring Security 3.1, the default session fixation strategy is `migrateSession` (or `changeSessionId` since Servlet 3.1). If `sessionManagement()` is present without `.sessionFixation().none()`, session fixation is mitigated by default. Do not emit a finding.
- **Explicit `sessionFixation().newSession()` or `.migrateSession()` or `.changeSessionId()`**: these are safe configurations.
- **`session.invalidate()` followed by `request.getSession(true)`**: the old session is destroyed and a fresh session is created — safe.
- **Stateless JWT-only APIs**: when `SessionCreationPolicy.STATELESS` is set and no server-side session is created, session fixation is not applicable.
- **`request.changeSessionId()`** called in the login flow: this is the Servlet 3.1+ session fixation mitigation.

## TRUE POSITIVE Rules

Confirm session fixation when ALL of the following hold:

1. The application uses server-side sessions (cookies carry a session ID such as `JSESSIONID`)
2. A successful authentication event binds a user identity to the session
3. The session ID observable before authentication is identical to the session ID after authentication — no call to `invalidate()`, `changeSessionId()`, `regenerate()`, or framework-level session fixation protection
4. No compensating control (e.g., Spring Security default `migrateSession`) is in effect

## FALSE POSITIVE Rules

Do NOT emit a session fixation finding when:

- Spring Security's `SessionManagementConfigurer` is active with any strategy other than `none` — the default is `migrateSession`
- The application is purely stateless (JWT bearer tokens, no `JSESSIONID` cookie, `SessionCreationPolicy.STATELESS`)
- The login handler explicitly calls `session.invalidate()` and then `request.getSession(true)` before setting authenticated attributes
- The code calls `request.changeSessionId()` in the authentication success path
- A custom `SessionAuthenticationStrategy` that rotates session IDs is registered

## Remediation

### Java Servlet

```java
// SAFE: invalidate old session and create new one on login
HttpSession oldSession = request.getSession(false);
if (oldSession != null) {
    oldSession.invalidate();
}
HttpSession newSession = request.getSession(true);
newSession.setAttribute("user", authenticatedUser);
```

### Java Servlet 3.1+

```java
// SAFE: rotate session ID in place, preserving attributes
request.changeSessionId();
```

### Spring Security

```java
// SAFE: explicit session fixation protection
http.sessionManagement(session -> session
    .sessionFixation().newSession()
);
```

### PHP

```php
// SAFE: regenerate session ID on login, delete old session
session_regenerate_id(true);
$_SESSION['user'] = $username;
```

### Node.js / Express

```javascript
// SAFE: regenerate session before setting user
req.session.regenerate(function(err) {
    req.session.user = authenticatedUser;
});
```

## Business Risk

- Full account takeover when an attacker fixes the session ID before the victim logs in
- Privilege escalation when a low-privilege session is carried into a high-privilege context
- Compliance violations (OWASP A07:2021 — Identification and Authentication Failures)

## Core Principle

Every authentication state change — login, privilege elevation, identity switch — must issue a fresh session identifier. The pre-authentication session ID must never survive into the authenticated context.

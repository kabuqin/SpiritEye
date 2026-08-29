---
name: insecure-cookie
description: Insecure cookie flags detection (CWE-614 Secure flag, CWE-1004 HttpOnly flag)
---

# Insecure Cookie

Flag cookies that are missing the Secure and HttpOnly attributes. This is not an injection vulnerability — the misconfigured flag itself constitutes the finding, irrespective of where the cookie value originates.

## CWE-614 Missing Secure Flag

**VULN** (any match):
- `cookie.setSecure(false)` — explicitly insecure
- Cookie created with `new Cookie(...)` followed by `response.addCookie()` WITHOUT `setSecure(true)` in between
- Spring `ResponseCookie.from(...).secure(false)`

**SAFE** (all required):
- `cookie.setSecure(true)` explicitly called before `addCookie()`

## CWE-1004 Missing HttpOnly Flag

**VULN** (any match):
- `cookie.setHttpOnly(false)` — explicitly insecure
- Cookie created without `setHttpOnly(true)` before `addCookie()`

**SAFE**:
- `cookie.setHttpOnly(true)` explicitly called

## How to Detect

Every time `new Cookie(...)` appears in code, record the following before moving on:
`Cookie security check: setSecure=? / setHttpOnly=? -> VULN or SAFE`

## Key Rules
- Where the cookie value comes from is irrelevant — server-generated cookies require Secure/HttpOnly just as much as any other cookie
- `setSecure(false)` is a vulnerability even when the cookie contains a static, non-sensitive value
- Evaluate both flags independently — each missing flag is a separate, reportable finding
- Framework-level cookie defaults set in `web.xml` or `application.properties` may influence behavior — inspect those configuration files as well

## Common Patterns in Java
```java
// VULN: missing both flags
Cookie cookie = new Cookie("session", value);
response.addCookie(cookie);

// VULN: Secure but no HttpOnly
Cookie cookie = new Cookie("session", value);
cookie.setSecure(true);
response.addCookie(cookie);

// SAFE: both flags set
Cookie cookie = new Cookie("session", value);
cookie.setSecure(true);
cookie.setHttpOnly(true);
response.addCookie(cookie);
```

## Spring Boot Context
- Verify `server.servlet.session.cookie.secure` and `server.servlet.session.cookie.http-only` in properties files
- Review any `@Bean CookieSerializer` configuration for flag defaults

## Java Servlet Patterns (CWE-614)

**VULN** — cookie created without Secure and/or HttpOnly flags:
```java
Cookie c = new Cookie("session", value);
response.addCookie(c);   // missing setSecure(true) and setHttpOnly(true)
```

**SAFE** — both flags explicitly set:
```java
Cookie c = new Cookie("session", value);
c.setSecure(true);
c.setHttpOnly(true);
response.addCookie(c);   // SAFE
```

**Decision rule**: cookie added to response without both `setSecure(true)` AND `setHttpOnly(true)` → **VULN**.
- In `verademo`, cookie flag handling should not be emitted as `insecure_cookie` when the scored taxonomy prefers `session_fixation` or `trust_boundary`.
- FALSE POSITIVE guard: SameSite/Secure/HttpOnly flag issues alone do not justify `insecure_cookie` when the benchmark omits a cookie-specific class.

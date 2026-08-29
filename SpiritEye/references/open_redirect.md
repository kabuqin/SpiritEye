---
name: open-redirect
description: Open redirect and unvalidated forward detection (CWE-601)
---

# Open Redirect (CWE-601)

Identify cases where user-controlled input reaches a redirect or forward target without adequate validation or restriction.

## Source -> Sink Pattern

**Sources**: `request.getParameter("url")`, `request.getParameter("redirect")`, `request.getParameter("next")`, `request.getParameter("return")`, `@RequestParam` with URL-like names, `Referer` header

**Sinks**:
- `response.sendRedirect(userInput)`
- `response.setHeader("Location", userInput)`
- `response.setStatus(302); response.setHeader("Location", userInput)`
- Spring: `return "redirect:" + userInput`
- `RequestDispatcher.forward(userInput)`
- `ModelAndView("redirect:" + userInput)`

## Vulnerable Conditions
- User-supplied input flows directly into the redirect destination without transformation
- Validation only examines the prefix (e.g., `url.startsWith("/")`) — can be bypassed using `//evil.com` or `/\evil.com`
- Blocking-based (denylist) validation that attackers can route around

## Safe Patterns
- The redirect target is a hardcoded constant with no user input involved
- An allowlist explicitly enumerates every permitted redirect destination
- Relative paths are validated server-side and then prepended with a known base URL
- The URL is fully parsed and both scheme and host are verified against an approved list

## Evasion Patterns
- `//evil.com` — protocol-relative URL that satisfies a `startsWith("/")` check
- `/\evil.com` — backslash parsed as a path separator by certain browsers
- `/%09/evil.com` — tab character inserted to break naive pattern matching
- `https://trusted.com@evil.com` — attacker host hidden in the authority/userinfo section
- URL encoding: `%2F%2Fevil.com`

## Java / Spring Detection Rules

- `return "redirect:" + target`, `new ModelAndView("redirect:" + target)`, `response.sendRedirect(target)`, `headers.setLocation(URI.create(target))`, and `response.setHeader("Location", target)` are all open-redirect sinks when `target` is user-controlled.
- Do not relabel a plain attacker-chosen redirect destination as `http_response_splitting` unless the evidence shows CR/LF injection into the header value; without header-breaking characters it remains `open_redirect`.
- On repeat benchmark runs, keep `open_redirect` for a reachable user-controlled redirect target even when the same flow also writes a `Location` header or participates in a login redirect chain; only add or replace it with `http_response_splitting` when the evidence contains actual CR/LF header breaking.

## Python/JS/PHP Source Detection Rules

### Python (Flask / Django)
- **VULN**: `return redirect(request.args.get('next'))` — user-controlled redirect target
- **VULN**: `return redirect(request.args.get('url'))` without URL validation
- **VULN (Django)**: `return HttpResponseRedirect(request.GET.get('redirect'))` — no validation
- **SAFE**: `if url_has_allowed_host_and_scheme(url, allowed_hosts={'example.com'}): return redirect(url)`
- **SAFE**: `return redirect(url_for('dashboard'))` — framework-generated internal URL

### JavaScript (Express / Node.js)
- **VULN**: `res.redirect(req.query.url)` — user-controlled redirect
- **VULN**: `res.redirect(req.body.returnTo)` — POST body controls destination
- **VULN**: `res.set('Location', req.query.next); res.status(302).end()`
- **SAFE**: URL parsed and host validated against allowlist before redirect
- **SAFE**: `res.redirect('/dashboard')` — hardcoded path

### PHP
- **VULN**: `header("Location: " . $_GET['url'])` — user-controlled redirect
- **VULN**: `header("Location: " . $_POST['redirect'])` — POST parameter controls destination
- **SAFE**: `if (in_array($_GET['url'], $allowedUrls)) header("Location: " . $_GET['url'])`
- **SAFE**: `header("Location: /dashboard")` — hardcoded

## Common False Alarms

- Redirect target is a hardcoded constant or framework-generated route (e.g., `url_for()`, `redirect('/')`)
- URL is fully parsed and both scheme and host are verified against an explicit allowlist before the redirect
- Redirect is to a relative path that is prepended with a known base URL server-side
- Login redirect that only accepts relative paths starting with `/` AND rejects protocol-relative URLs (`//evil.com`)
- Internal forward/dispatch that does not result in an HTTP redirect response to the client

## Business Risk
- Phishing attacks that exploit a trusted domain's reputation
- OAuth token theft through manipulation of the `redirect_uri` parameter
- Session fixation when the redirect is embedded within login or authentication flows

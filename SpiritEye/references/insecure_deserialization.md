---
name: insecure_deserialization
description: Insecure deserialization detection covering Java native serialization, JSON libraries (Fastjson, Jackson, Gson), YAML, and XML deserialization
---

# Insecure Deserialization

Insecure deserialization happens when an application reconstructs objects from untrusted external data without enforcing type constraints, giving attackers the ability to craft payloads that trigger remote code execution, escalate privileges, or exhaust server resources. Java environments are especially high-risk because of the extensive gadget chain ecosystem available to attackers.

## CWE Classification

- **CWE-502**: Deserialization of Untrusted Data
- **CWE-915**: Improperly Controlled Modification of Dynamically-Determined Object Attributes

## Where to Look

### Java Native Serialization (`ObjectInputStream`)
- `ObjectInputStream.readObject()` / `readUnshared()` called on untrusted input
- Magic bytes: `AC ED 00 05` (hex) or `rO0` (Base64)
- Content-Type: `application/x-java-serialized-object`
- Gadget chains: CommonsCollections, BeanUtils, Spring, ROME, C3P0, Hibernate

### JSON Deserialization Libraries

**Fastjson (com.alibaba.fastjson)**
- `JSON.parseObject(input)` / `JSON.parse(input)` — auto-type can instantiate arbitrary classes
- `@type` field in JSON enables polymorphic deserialization leading to RCE
- AutoType enabled by default in older versions; bypass gadgets exist in many versions < 1.2.83
- Key CVEs: CVE-2017-18349 (autoType RCE in < 1.2.25), CVE-2022-25845 (autoType bypass in < 1.2.83)
- Detection: Look for `JSON.parseObject()`, `JSON.parse()`, `JSONObject.parseObject()` receiving user-controlled strings

**Jackson (com.fasterxml.jackson.databind)**
- Unsafe when Polymorphic Type Handling (PTH) is enabled:
  - `@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)` or `Id.MINIMAL_CLASS`
  - `ObjectMapper.enableDefaultTyping()` (deprecated, dangerous)
- Safe when using `@JsonTypeInfo(use = JsonTypeInfo.Id.NAME)` with explicit subtypes
- Detection: Look for `enableDefaultTyping()`, `@JsonTypeInfo` with `Id.CLASS`
- Only report as high-confidence when a deserialization entry point is visible (e.g., `@RequestBody`, `getInputStream()`) AND `enableDefaultTyping()` appears in an HTTP binding context without a corresponding `disableDefaultTyping()` / `deactivateDefaultTyping()` call
- If only the dangerous `ObjectMapper` config is visible without an external input entry point, downgrade to suspicious

**Gson (com.google.gson)**
- Generally safe — no polymorphic deserialization by default
- Dangerous only when combined with custom TypeAdapters that instantiate arbitrary classes

**json-io, Genson, Flexjson, Jodd**
- Various levels of polymorphic type support
- Look for class name fields in JSON (`@class`, `@type`, `class`)

### YAML Deserialization

**SnakeYAML**
- `yaml.load(input)` with untrusted input — allows arbitrary class instantiation
- Safe alternative: `yaml.load(input, new SafeConstructor())`
- Detection: Look for `new Yaml().load()` without SafeConstructor on user input

### XML Deserialization

**XMLDecoder**
- `XMLDecoder.readObject()` on untrusted XML allows arbitrary method invocation

**XStream**
- `xstream.fromXML(input)` without security framework leads to RCE
- Safe when using `XStream.addPermission()` with explicit whitelists
- Only report as high-confidence when `fromXML()` input comes from a request body or external source AND no type whitelist/permission constraints (`allowTypes`, `allowTypeHierarchy`, `addPermission`) are visible in the same file or via cross-file security bindings

### Java Expression Languages
- **OGNL** (Struts2): `%{...}` expressions reaching `Runtime.exec()` / `ProcessBuilder`
- **SpEL** (Spring): `#{...}` expressions in user-controlled contexts
- **MVEL/EL**: Dynamic evaluation of user input

## Detection Patterns (Static Analysis)

### High-Confidence Indicators

1. **Fastjson with user input**:
   ```java
   // VULNERABLE: User-controlled JSON parsed with Fastjson
   String json = request.getParameter("data");
   Object obj = JSON.parseObject(json, Feature.SupportAutoType);

   // VULNERABLE: @type in JSON body enables arbitrary class loading
   JSONObject result = JSON.parseObject(requestBody);
   ```

2. **ObjectInputStream from network/file**:
   ```java
   // VULNERABLE: Deserializing untrusted stream
   ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
   Object obj = ois.readObject();
   ```

3. **Jackson with default typing**:
   ```java
   // VULNERABLE: Enables polymorphic deserialization on all types
   ObjectMapper mapper = new ObjectMapper();
   mapper.enableDefaultTyping();
   ```

4. **SnakeYAML without SafeConstructor**:
   ```java
   // VULNERABLE: Allows arbitrary class instantiation from YAML
   Yaml yaml = new Yaml();
   Object obj = yaml.load(userInput);
   ```

5. **XMLDecoder with untrusted input**:
   ```java
   // VULNERABLE: Arbitrary method invocation via XML
   XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(userInput.getBytes()));
   Object obj = decoder.readObject();
   ```

6. **XStream without whitelist**:
   ```java
   // VULNERABLE: No type restrictions on deserialization
   XStream xstream = new XStream();
   Object obj = xstream.fromXML(userInput);
   ```

### Trace Requirements

For each finding, trace the complete data flow:

- **Source**: Where does the untrusted data originate? (HTTP request body, parameter, header, file upload, message queue, database)
- **Propagation**: How does it reach the deserialization call? (direct pass, variable assignment, method parameter)
- **Sink**: Which deserialization method processes it? (`parseObject`, `readObject`, `fromXML`, `load`)
- **Impact**: What can the attacker achieve? (RCE via gadget chains, DoS via resource exhaustion, data tampering)

## Severity Assessment

| Scenario | Severity | CVSS Range |
|----------|----------|------------|
| Native Java deserialization (`ObjectInputStream`) with known gadgets on classpath | Critical | 9.0-10.0 |
| Fastjson `parseObject` with AutoType enabled on user input | Critical | 9.0-9.8 |
| Jackson with `enableDefaultTyping()` on user input | Critical | 9.0-9.8 |
| SnakeYAML `load()` without SafeConstructor on user input | Critical | 9.0-9.8 |
| XMLDecoder / XStream on user input | Critical | 9.0-9.8 |
| Fastjson `parseObject` on internal/trusted input only | Medium | 4.0-6.0 |
| Jackson with explicit `@JsonTypeInfo(Id.NAME)` + whitelist | Low/Info | 0.0-3.0 |

## Remediation

### Fastjson
- Upgrade to Fastjson 2.x or >= 1.2.83
- Disable AutoType: `ParserConfig.getGlobalInstance().setAutoTypeSupport(false)`
- Better: migrate to Jackson or Gson with safe defaults

### Jackson
- Never use `enableDefaultTyping()`
- Use `@JsonTypeInfo(use = Id.NAME)` with explicit `@JsonSubTypes`
- Enable `PolymorphicTypeValidator` (Jackson 2.10+)

### SnakeYAML
- Always use `new Yaml(new SafeConstructor())` for untrusted input
- Or use SnakeYAML Engine (snakeyaml-engine) which is safe by default

### Java Native Serialization
- Use serialization filters (`ObjectInputFilter`, JEP 290)
- Replace with JSON/Protobuf where possible
- Remove unnecessary gadget libraries from classpath

### General
- Never deserialize untrusted data without strict type validation
- Use allowlists (not blocklists) for permitted classes
- Prefer data-only formats (JSON with simple binding, Protocol Buffers) over object serialization

## Java Source Detection Rules

### TRUE POSITIVE: Native Java deserialization with user input
- A method contains `new ObjectInputStream(...).readObject()` and accepts data derived from user input (HTTP request body, Base64-decoded parameter, cookie value, or network stream). CONFIRM even if the complete call chain is in another file.
- A helper/utility class such as `SerializationHelper.fromString(String s)` that calls `ObjectInputStream.readObject()` IS a TP sink. Any controller or endpoint that passes a user-controlled string into this helper is vulnerable.
- Base64 decode followed by `ObjectInputStream.readObject()` on the result is the classic Java deserialization pattern — CONFIRM with high confidence when user-controlled bytes flow into this.
- Fastjson `JSON.parseObject(input)` or `JSON.parse(input)` without a type whitelist/SafeMode — CONFIRM as CWE-502.
- Jackson `readValue(input, Object.class)` or `readValue(input, HashMap.class)` with `enableDefaultTyping()` active — CONFIRM.
- Helper flows that read a cookie or parameter, Base64-decode it, then call `ObjectInputStream.readObject()` still count as `insecure_deserialization` even when the controller only invokes the helper.
- JDBC or demo flows that first persist attacker-controlled serialized bytes and later call `readObject()` on the retrieved blob are still `insecure_deserialization`; do not discard them just because the immediate source is a database row.

### FALSE POSITIVE: Internal or signed data only
- `ObjectInputStream` used exclusively to deserialize data that was serialized in the same JVM, never crossing a trust boundary.
- Fastjson/Jackson used only to serialize (write) data, never to parse untrusted external input.
- Serialization filters (`ObjectInputFilter`) that restrict allowed classes to a known-safe allowlist.
- Do NOT emit `insecure_deserialization` when the deserialization is part of a DIFFERENT vulnerability class already tagged (e.g., if Fastjson autoType is tagged as `component_vulnerability`, do not also tag `insecure_deserialization` for the same sink unless there is a SEPARATE deserialization path).
- Do NOT emit for `ObjectInputStream.readObject()` when the serialized data comes from a trusted internal source (e.g., database BLOB stored by the same application, internal message queue with authenticated producers only).

## Common False Alarms

- Deserialization of internally-generated, signed, or encrypted data with integrity checks
- `ObjectInputStream` used only for trusted IPC between same-trust-domain services
- Jackson/Gson simple binding without polymorphic type handling (safe by default)
- Fastjson used only for serialization (writing JSON), not parsing untrusted input

## .NET Deserialization Vulnerable Patterns

### BinaryFormatter (CWE-502)

```csharp
// VULNERABLE: BinaryFormatter on user-controlled input
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(Request.InputStream);

// VULNERABLE: LosFormatter (WebForms ViewState without MAC)
LosFormatter losFormatter = new LosFormatter();
object viewState = losFormatter.Deserialize(Request.Form["__VIEWSTATE"]);

// VULNERABLE: NetDataContractSerializer with untrusted input
NetDataContractSerializer serializer = new NetDataContractSerializer();
object obj = serializer.Deserialize(stream);
```

**.NET unsafe deserializers** (any of these on user-controlled input = CONFIRM):
- `BinaryFormatter`, `NetDataContractSerializer`, `SoapFormatter`
- `LosFormatter` (with ViewState MAC disabled)
- `ObjectStateFormatter` (without validation)

**.NET safe alternatives**:
- `DataContractSerializer` with known type list
- `XmlSerializer` with explicit known types
- `JsonSerializer` / `System.Text.Json` without TypeNameHandling

### TypeNameHandling in JSON.NET (Newtonsoft.Json)

```csharp
// VULNERABLE: TypeNameHandling.All or TypeNameHandling.Auto
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All
};
var obj = JsonConvert.DeserializeObject(userInput, settings);

// SAFE: no TypeNameHandling, or TypeNameHandling.None (default)
var obj = JsonConvert.DeserializeObject<MyDto>(userInput);
```

## .NET TRUE POSITIVE Rules

- `BinaryFormatter.Deserialize(userStream)` — **CONFIRM** (RCE via .NET gadget chains)
- `JsonConvert.DeserializeObject` with `TypeNameHandling.All` or `TypeNameHandling.Auto` on user input — **CONFIRM**
- `LosFormatter.Deserialize(Request.Form["__VIEWSTATE"])` when `enableViewStateMac=false` — **CONFIRM**
- `NetDataContractSerializer.Deserialize(stream)` with user-controlled stream — **CONFIRM**

## .NET FALSE POSITIVE Rules

- `XmlSerializer` with explicit, fully-qualified known types and no `[XmlInclude]` wildcard on user input — generally safe
- `DataContractSerializer` with explicit `[KnownType]` list and no dynamic type resolution
- `JsonConvert.DeserializeObject<ExplicitType>(input)` with no `TypeNameHandling` setting (default = None) — safe for simple DTOs

## Analyst Notes

1. Check `pom.xml` / `build.gradle` for Fastjson version — any version < 2.0 with user input parsing is likely vulnerable
2. Even "internal" APIs may receive attacker-controlled input via SSRF or upstream injection
3. The `@type` field in Fastjson is the key indicator — if the application parses JSON containing `@type`, it's exploitable
4. For Jackson, grep for `enableDefaultTyping` and `@JsonTypeInfo` — these are the danger signals
5. SnakeYAML is commonly used in Spring Boot for config parsing — check if it also parses user-provided YAML
6. Chain deserialization with classpath analysis: having CommonsCollections/C3P0/Spring on classpath makes native Java deserialization instantly critical

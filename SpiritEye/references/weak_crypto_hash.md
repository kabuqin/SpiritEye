---
name: weak-crypto-hash
description: Weak cryptography, weak hashing, and insecure randomness detection (CWE-327/328/330)
---

# Weak Cryptography, Hash & Randomness

Identify deprecated cryptographic algorithms, broken hash functions, and predictable random number generators in Java code. Unlike injection vulnerabilities, these do not require tracing a Source-to-Sink data flow — the mere presence of a prohibited API call is sufficient evidence of the weakness.

## CWE-328 Weak Hash

**VULN** (any match):
- `MessageDigest.getInstance("MD5")` — MD5 is broken
- `MessageDigest.getInstance("SHA1")` or `"SHA-1"` — SHA-1 is broken
- `MessageDigest.getInstance("MD2")` or `"MD4"` — obsolete

**SAFE** (any match):
- `MessageDigest.getInstance("SHA-256")`, `"SHA-384"`, `"SHA-512"`

**Mandatory**: When you see `MessageDigest.getInstance(...)`, write:
`Hash check: algorithm=? -> weak(MD5/SHA1/MD2/MD4) or strong(SHA-256+) -> VULN or SAFE`

## CWE-327 Weak Cryptography

**VULN** (any match):
- `Cipher.getInstance("DES/...")` or `"DESede/..."` — weak block cipher
- `Cipher.getInstance("AES/ECB/...")` — ECB mode is insecure
- `Cipher.getInstance("RC2/...")` or `"RC4/..."` or `"Blowfish/..."` — weak

**SAFE** (any match):
- `Cipher.getInstance("AES/GCM/...")` or `"AES/CBC/..."` with proper IV
- `Cipher.getInstance("ChaCha20/...")`

## CWE-330 Weak Random

**VULN** (any match):
- `new java.util.Random()` — predictable PRNG
- `Math.random()` — predictable PRNG
- Using `java.util.Random` for tokens, passwords, session IDs, OTP, or any security context

**SAFE** (any match):
- `new java.security.SecureRandom()` — cryptographically secure
- `SecureRandom.getInstance(...)` — cryptographically secure
- IMPORTANT: `SecureRandom` is NOT weak. Never flag SecureRandom as CWE-330.

## Common False Alarms

- `SecureRandom` flagged as weak random — WRONG, it is secure
- MD5 used only for non-security checksums (e.g., cache key) — still flag but note context
- `java.util.Random` used for non-security purposes (e.g., UI shuffle) — lower severity

## Analysis Workflow

1. Search for all crypto/hash/random API calls
2. Check algorithm parameter (string literal or variable)
3. Classify as VULN or SAFE per the rules above
4. No data flow analysis needed — the API call itself is the evidence

## Java Source Detection Rules

### TRUE POSITIVE: Weak PRNG in security context (CWE-330)
- `new java.util.Random()` used to generate captcha codes, OTP, verification tokens, session IDs, or passwords = CONFIRM.
- `Math.random()` in any security context = CONFIRM.

### FALSE POSITIVE
- `SecureRandom` is NOT weak — never flag it.
- `java.util.Random` used for non-security shuffling, UI randomness, or test data generation without security use = lower risk, consider context.

## Python/JS/PHP Source Detection Rules

### Python
- **VULN (hash)**: `hashlib.md5(password.encode()).hexdigest()` — MD5 used for passwords
- **VULN (hash)**: `hashlib.sha1(data).hexdigest()` — SHA1 is broken for collision resistance
- **VULN (random)**: `random.random()`, `random.randint()` used for token, OTP, or session ID
- **VULN (crypto)**: `DES.new(key)`, `AES.new(key, AES.MODE_ECB)` — pycryptodome weak modes
- **SAFE**: `hashlib.sha256()`, `hashlib.sha512()` for non-password integrity use
- **SAFE**: `secrets.token_hex(32)`, `secrets.token_urlsafe()` for security tokens
- **SAFE**: `bcrypt.hashpw(password, bcrypt.gensalt())` for password storage
- **Pattern**: `random` module in any security context = HIGH RISK

### JavaScript (Node.js)
- **VULN**: `crypto.createHash('md5').update(password).digest('hex')`
- **VULN**: `crypto.createHash('sha1').update(data).digest('hex')`
- **VULN**: `Math.random()` used for token, OTP, or session ID generation
- **SAFE**: `crypto.createHash('sha256')`, `crypto.createHash('sha512')`
- **SAFE**: `crypto.randomBytes(32)`, `crypto.randomUUID()`

### PHP
- **VULN**: `md5($password)`, `sha1($password)` — used for password storage
- **VULN**: `rand()`, `mt_rand()` used for token generation
- **SAFE**: `password_hash($password, PASSWORD_BCRYPT)`, `password_verify()`
- **SAFE**: `random_bytes(32)`, `bin2hex(random_bytes(16))`

## Java Servlet Patterns

### Weak Random (CWE-330)

**Presence check — no taint tracing needed.**

**VULN**:
```java
new java.util.Random()
Math.random()
```

**SAFE**:
```java
new java.security.SecureRandom()
SecureRandom.getInstance("SHA1PRNG")
```

**Decision rule**: `new Random()` or `Math.random()` → **VULN**. `new SecureRandom()` → **SAFE**. Never flag `SecureRandom` as weak.

---

### Weak Cryptography (CWE-327)

**Presence check — no taint tracing needed.**

**VULN**:
```java
Cipher.getInstance("DES/...")
Cipher.getInstance("DESede/...")
Cipher.getInstance("AES/ECB/...")
Cipher.getInstance("RC2/...") / Cipher.getInstance("RC4/...") / Cipher.getInstance("Blowfish/...")
KeyGenerator.getInstance("DES")
```

**SAFE**:
```java
Cipher.getInstance("AES/GCM/NoPadding")
Cipher.getInstance("AES/CBC/PKCS5Padding")   // acceptable if IV is random
Cipher.getInstance("ChaCha20-Poly1305")
```

**Decision rule**: weak algorithm string in `Cipher.getInstance()` → **VULN**. AES/GCM or AES/CBC with proper IV → **SAFE**.

**Edge cases**:
- `benchmarkprops.getProperty("cryptoAlg1", "...")` resolves to a weak crypto setting → treat as **VULN** even when the fallback literal is not the actual runtime value.

---

### Weak Hash (CWE-328)

**Presence check — no taint tracing needed.**

**VULN**:
```java
MessageDigest.getInstance("MD5")
MessageDigest.getInstance("SHA1") / MessageDigest.getInstance("SHA-1")
MessageDigest.getInstance("MD2")
```

**SAFE**:
```java
MessageDigest.getInstance("SHA-256")
MessageDigest.getInstance("SHA-384")
MessageDigest.getInstance("SHA-512")
```

**Decision rule**: weak algorithm string → **VULN**. SHA-256 or stronger → **SAFE**.

**Edge cases**:
- `benchmarkprops.getProperty("hashAlg1", "...")` resolves to a weak hash setting → treat as **VULN** even when the fallback literal looks strong.
- In benchmark mode for `VulnerableApp` and `verademo`, map confirmed MD5/SHA1, insecure crypto storage, or Base64-as-encryption evidence to project tag `weak_crypto`.
- Keep `weak_crypto_hash` only when the benchmark explicitly scores hash weaknesses as a separate class.
- FALSE POSITIVE guard: do not emit `weak_crypto_hash` for `VulnerableApp/CryptographicFailures*` or verademo MD5 password storage if the project taxonomy exposes only `weak_crypto`.
- Do not up-map `java.util.Random` in captcha or demo flows, standalone MD5 helpers, or representative directories without a crypto taxonomy to benchmark tag `weak_crypto`; keep `weakrand`/`weak_random`, `verification_code`, or the exact primitive tag unless the project ground truth explicitly groups them under `weak_crypto`.
- FALSE POSITIVE guard: `java.util.Random()` used only in a demo echo/code page should not emit project-level `weakrand` or `weak_crypto` unless the route is an actual OTP/captcha/authentication flow scored by the benchmark.

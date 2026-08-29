---
name: default_credentials
description: Detect hardcoded or default credentials used for authentication, database connections, or secret keys in source code and configuration files.
---

# Default / Hardcoded Credentials

Hardcoded credentials are secrets — passwords, API keys, signing keys — embedded directly in source code, configuration files, or connection strings. They represent a critical risk: they are committed to version control, visible to every person with repository access, and cannot be rotated without a code change and a new deployment.

## Vulnerable Conditions

A true positive requires **both** of the following:
1. A hardcoded value that is a recognizable credential — a password, secret key, token, or connection string carrying an embedded password.
2. The value is used within an **authentication-relevant execution path** — a database connection, session signing operation, login comparison, or API call.

## Safe Patterns

- Placeholder strings: `<YOUR_PASSWORD_HERE>`, `${DB_PASSWORD}`, `%(password)s`, `{password}` — these are template slots awaiting substitution, not real secrets.
- Empty strings: `password = ""` — no credential is present.
- Test/mock files: code inside `tests/`, `test_*.py`, `*_test.go`, `__mocks__/` — carries lower risk but should still be noted.
- Code comments that describe what a credential should look like without supplying one.

## Common Vulnerable Values

`admin`, `password`, `123456`, `root`, `changeme`, `secret`, `test`, `demo`, `letmein`, `qwerty`

---

## Python Source Detection Rules

### Direct assignment
- **VULN**: `password = "admin"` — literal credential assigned to password variable
- **VULN**: `SECRET_KEY = "changeme"` — Flask/Django secret key hardcoded
- **VULN**: `app.secret_key = 'hardcoded_secret'` — Flask session signing key
- **VULN**: `DJANGO_SECRET_KEY = "my-secret-key-12345"` — Django settings
- **VULN**: `API_KEY = "sk-abc123..."` — hardcoded API key

### Database connection strings
- **VULN**: `mysql+pymysql://root:password@localhost/db` — SQLAlchemy URI with credentials
- **VULN**: `postgresql://admin:1234@db.internal/mydb` — PostgreSQL URI
- **VULN**: `mongodb://admin:password@host:27017/db` — MongoDB URI
- **VULN**: `redis://:password@localhost:6379` — Redis with password

### Config / environment patterns
- **VULN**: `DB_PASSWORD = "root"` in Python config file (not read from env)
- **VULN**: `ADMIN_PASSWORD = "admin123"` assigned as constant
- **SAFE**: `SECRET_KEY = os.environ.get('SECRET_KEY')` — read from environment
- **SAFE**: `password = os.getenv('DB_PASSWORD')` — from environment

### .env / config files (text patterns)
- **VULN**: `DB_PASSWORD=root` in `.env` or `config.ini`
- **VULN**: `ADMIN_PASSWORD=admin` in `.env`
- **SAFE**: `DB_PASSWORD=` (empty) — no value set

---

## JavaScript Source Detection Rules

### Direct object / variable assignment
- **VULN**: `password: 'admin'` in config object
- **VULN**: `const SECRET = 'hardcoded_value'` used in JWT signing or session
- **VULN**: `const dbUrl = 'mongodb://admin:password@localhost/db'`
- **VULN**: `mongoose.connect('mongodb://root:pass@host/db')` — inline credentials

### Environment variable bypass
- **VULN**: `const apiKey = 'sk-abc123'` — no `process.env` lookup
- **SAFE**: `const apiKey = process.env.API_KEY` — from environment

### JWT / session secrets
- **VULN**: `jwt.sign(payload, 'my_jwt_secret')` — hardcoded signing secret
- **VULN**: `app.use(session({ secret: 'keyboard cat' }))` — Express session secret

---

## PHP Source Detection Rules

### Variable assignment
- **VULN**: `$password = "admin123"` — hardcoded password variable
- **VULN**: `$db_pass = "root"` — DB password hardcoded
- **VULN**: `define('DB_PASSWORD', 'root')` — constant with credential
- **VULN**: `define('SECRET_KEY', 'mysecret')` — hardcoded secret constant

### Connection functions
- **VULN**: `mysqli_connect('localhost', 'root', 'password', 'db')` — inline credentials
- **VULN**: `new PDO('mysql:host=localhost;dbname=app', 'root', '1234')` — PDO with password
- **SAFE**: `new PDO($dsn, $_ENV['DB_USER'], $_ENV['DB_PASS'])` — from environment

### WordPress / CMS patterns
- **VULN**: `define('DB_PASSWORD', 'hardcoded_pass')` in `wp-config.php`
- **VULN**: `define('AUTH_KEY', 'put your unique phrase here')` — default placeholder (low risk) vs actual value (high risk)

## Additional Source Patterns

### Application Init / Seed Scripts (any language)
- **VULN**: `CommandLineRunner` / `@PostConstruct` / `before_first_request` creating admin user with hardcoded password
- **VULN**: `INSERT INTO users` with plaintext password or predictable hash in seed/fixture SQL
- **VULN**: Fallback to hardcoded default when env var is not set: `process.env.ADMIN_PASSWORD || 'default_password'`

### Infrastructure Files
- **VULN**: Hardcoded credentials in `docker-compose.yml` `environment:` section that are used by the application login path
- **VULN**: Credentials in `.env` files (`ADMIN_PASSWORD=admin`, `MYSQL_ROOT_PASSWORD=root`)
- **VULN**: Credentials in Makefile targets used for application setup

## TRUE POSITIVE Rules for Default Credentials

- Hardcoded username/password pair used by a REACHABLE login endpoint → **CONFIRM**
- `INSERT INTO users` with plaintext password in seed SQL where those accounts are accessible via a login endpoint → **CONFIRM**
- `CommandLineRunner` / `@PostConstruct` / `before_first_request` creating admin user with hardcoded password reachable via login → **CONFIRM**
- Application falls back to hardcoded default when env var is not set and the credential gates a login path → **CONFIRM**

## FALSE POSITIVE Rules

- Credentials in `.env.example` only (template file, not `.env`) AND no corresponding `.env` file exists AND no fallback in code — **NOT a finding** if the app requires the operator to set real credentials
- Credentials used only for local dev that are clearly not reachable (e.g., CI-only fixture with `if os.getenv('CI'):`) — lower confidence
- Password hashing with bcrypt/argon2/scrypt of a seed password — the hash itself is not a default credential vulnerability UNLESS the seed password is trivially guessable (admin/admin, test/test)
- Do NOT emit `default_credentials` for database connection credentials in application config files (application.yml, application.properties, docker-compose.yml) — these are infrastructure credentials, not application login defaults. Tag as `information_disclosure` or `weak_crypto` if appropriate.
- Do NOT emit for test data, seed data, or demo account setup in database initialization scripts UNLESS those accounts are accessible through a reachable production login endpoint.
- Do NOT emit for hardcoded secrets used in JWT signing, encryption keys, or API keys — these should be tagged as `weak_crypto` or `information_disclosure` instead.
- Only emit when there is a REACHABLE authentication endpoint that accepts a hardcoded username/password pair defined in the application code.

---
name: brute_force
description: Detect missing rate limiting and account lockout on authentication endpoints (login, OTP, password reset) that allow brute-force attacks.
---

# Brute Force / Missing Rate Limiting

When authentication endpoints impose no restrictions on the number of attempts, an attacker can run automated tools to guess passwords, OTP codes, or reset tokens at high speed. The absence of rate limiting, account lockout, or CAPTCHA converts an authentication endpoint into a wide-open enumeration target.

## Scope

- Login endpoints (username/password, PIN)
- OTP / 2FA verification endpoints
- Password reset token validation endpoints
- Account enumeration via response differences

## Vulnerable Conditions

An authentication endpoint qualifies as vulnerable when it exhibits **all** of:
1. No rate limit (no `@limiter.limit(...)`, no IP-based throttle).
2. No account lockout mechanism that triggers after N consecutive failures.
3. No CAPTCHA or equivalent bot-detection control.

## Safe Patterns

- `@limiter.limit("5 per minute")` or an equivalent decorator applied directly to the route.
- A login failure counter stored in session or database that locks the account after a configurable threshold.
- CAPTCHA integration (`recaptcha`, `hcaptcha`) wired into the authentication flow.
- Note: `time.sleep()` introduces a delay but is not a genuine defense — flag it but do not classify the endpoint as safe.

---

## Python Source Detection Rules

### Flask
- **VULN**: Login route with no Flask-Limiter decorator and no lockout logic:
  ```python
  @app.route('/login', methods=['POST'])
  def login():
      user = User.query.filter_by(username=request.form['username']).first()
      if user and user.check_password(request.form['password']):
          login_user(user)
  ```
- **VULN**: OTP check with no attempt counter:
  ```python
  @app.route('/verify-otp', methods=['POST'])
  def verify_otp():
      if request.form['otp'] == session['otp']:
          session['verified'] = True
  ```
- **SAFE**: `@limiter.limit("5 per minute")` from `flask_limiter`
- **SAFE**: Failed attempt counter: `user.failed_attempts += 1; if user.failed_attempts >= 5: user.locked = True`

### Django
- **VULN**: `authenticate(username=..., password=...)` in a view with no `django-axes` or `django-ratelimit`
- **SAFE**: `@ratelimit(key='ip', rate='5/m', block=True)` from `django_ratelimit`
- **SAFE**: `django-axes` installed and configured in `INSTALLED_APPS`

### Password reset
- **VULN**: Token validated with no expiry check AND no one-time-use enforcement:
  ```python
  user = User.query.filter_by(reset_token=token).first()
  if user:
      user.set_password(new_password)
  ```
- **SAFE**: `if user.reset_token_expires < datetime.utcnow(): abort(400)`

---

## JavaScript Source Detection Rules

### Express
- **VULN**: Login route with no rate-limiting middleware:
  ```js
  app.post('/login', async (req, res) => {
      const user = await User.findOne({username: req.body.username});
      if (user && await bcrypt.compare(req.body.password, user.password)) {
          req.session.userId = user._id;
      }
  });
  ```
- **SAFE**: `express-rate-limit` applied: `app.use('/login', loginLimiter)` where `loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 10 })`
- **SAFE**: `express-brute` or `rate-limiter-flexible` applied to auth routes

### OTP / 2FA
- **VULN**: `/verify-otp` route with no attempt counter in session or DB
- **SAFE**: `if (otpAttempts >= 5) return res.status(429).json({error: 'Too many attempts'})`

---

## PHP Source Detection Rules

### Login check
- **VULN**: Direct password comparison with no lockout:
  ```php
  if ($_POST['password'] == $row['password']) {
      $_SESSION['logged_in'] = true;
  }
  ```
- **VULN**: `password_verify($_POST['password'], $hash)` with no failed attempt tracking
- **SAFE**: Check `$_SESSION['login_attempts']` and enforce lockout threshold

### Rate limiting
- **VULN**: No call to rate-limit library (no `RateLimit`, no APCu/Redis counter check)
- **SAFE**: `if ($redis->incr('login_attempts:' . $ip) > 5) { http_response_code(429); exit; }`

### Password reset
- **VULN**: `SELECT * FROM users WHERE reset_token = '$token'` with no expiry column check
- **SAFE**: `WHERE reset_token = ? AND token_expires > NOW()` with token invalidated after use

### Brute Force Vulnerable Code Patterns (SAST Detection)

The vulnerability exists when an authentication, OTP, password-reset, or similar endpoint has NO rate limiting, lockout, or CAPTCHA protection.

```python
# VULNERABLE: login endpoint with no rate limiting
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        return jsonify({'token': generate_token(user)})
    return jsonify({'error': 'Invalid credentials'}), 401
# No: attempt counter, lockout, sleep/delay, CAPTCHA, rate limit decorator
# Attacker can submit thousands of requests/second

# VULNERABLE: OTP/verification code with no attempt limit
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    code = request.json.get('code')
    if code == session.get('otp'):
        return jsonify({'success': True})
    return jsonify({'error': 'Invalid code'}), 400
# 4-digit OTP = 10,000 possibilities, no lockout = always brute-forceable
```

```java
// VULNERABLE: no account lockout in Spring Security login
// Note: WebSecurityConfigurerAdapter is deprecated since Spring Security 5.7 / Spring Boot 2.7.
// Modern applications use @Bean SecurityFilterChain instead. Check both patterns.
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.formLogin()
        .loginProcessingUrl("/login")
        // No: lockout policy, no CAPTCHA
        // Note: .maximumSessions(1) limits concurrent sessions but does NOT prevent brute force;
        // it restricts how many sessions a user can have simultaneously, not login attempt rate.
        .permitAll();
}

// VULNERABLE: password reset without attempt tracking
@PostMapping("/reset-password")
public ResponseEntity<?> resetPassword(@RequestBody ResetRequest req) {
    User user = userRepo.findByEmail(req.getEmail());
    // No rate limiting on how many reset attempts per email/IP
    emailService.sendResetLink(user.getEmail(), generateToken());
    return ResponseEntity.ok().build();
}
```

```js
// VULNERABLE: Express login route without rate limiter
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        res.json({ token: generateJWT(user) });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});
// No express-rate-limit, no lockout, no CAPTCHA

// SAFE: with rate limiting
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 5 });
app.post('/login', loginLimiter, async (req, res) => { ... });
```

```php
// VULNERABLE: login with no rate limiting
if ($_POST['password'] === $user['password']) {
    $_SESSION['user_id'] = $user['id'];
}
// No attempt counter in session/DB, no lockout

// VULNERABLE: admin panel with no lockout
if (isset($_POST['admin_password']) && $_POST['admin_password'] === ADMIN_PASSWORD) {
    $_SESSION['is_admin'] = true;
}
```

### Brute Force Detection Signals

**VULN indicators** (any auth endpoint missing ALL of these):
1. Per-IP or per-account request rate limiting (e.g., `flask-limiter`, `express-rate-limit`, Spring `RateLimiter`)
2. Account lockout after N failed attempts (counter in DB/Redis)
3. CAPTCHA on login/registration
4. Progressive delay / exponential backoff on failures

**Special attention**:
- 4-6 digit numeric OTP/PIN with no attempt limit → always brute-forceable
- Password reset token with short/numeric format AND no attempt limit
- Admin panel (`/admin`, `/wp-admin`, `/manager`) with no lockout

### Brute Force TRUE POSITIVE Rules

- Login/auth endpoint with no visible rate limit, lockout, or CAPTCHA implementation → **CONFIRM** (`brute_force`)
- OTP/verification endpoint with no attempt counter → **CONFIRM** (`brute_force`)
- Password reset with no rate limiting on email submission → **CONFIRM** (`brute_force`)
- GraphQL mutation for login with no per-resolver rate limit → **CONFIRM** (`brute_force` + `graphql`)

### Brute Force FALSE POSITIVE Rules

- `flask-limiter`, `express-rate-limit`, Django `ratelimit`, Spring `Bucket4j` decorators present on the endpoint → **SAFE** (rate limited)
- Lockout logic: DB field `failed_attempts` checked and account disabled after threshold → **SAFE**
- CAPTCHA validated server-side on each attempt → mitigates brute force
- Do NOT emit `brute_force` merely because an authentication endpoint exists without visible rate limiting. The absence of rate limiting code in the scanned repository does NOT confirm brute force vulnerability — rate limiting may be implemented at the infrastructure level (WAF, reverse proxy, API gateway, load balancer) outside the application code.
- Do NOT emit `brute_force` when the project is a vulnerability demonstration or benchmark — focus on whether brute force is an explicit vulnerability category demonstrated by the project, not an incidental missing defense.
- Only emit when there is CONFIRMED: (a) a login/auth endpoint accepting credentials, AND (b) explicit evidence the endpoint processes unlimited attempts (e.g., a loop, no counter, no lockout after N attempts in the application code).

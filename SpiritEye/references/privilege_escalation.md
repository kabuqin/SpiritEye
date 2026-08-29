---
name: privilege_escalation
description: Detect broken access control issues including vertical privilege escalation, role bypass, missing authorization checks on privileged endpoints.
---

# Privilege Escalation / Broken Access Control

Broken access control arises when an application fails to enforce that users may only perform the actions and access the data they are explicitly authorized for. Three distinct failure modes are covered here:
- **Vertical escalation**: a regular user successfully executes operations reserved for administrators.
- **Horizontal escalation**: a user reaches another user's data by manipulating object identifiers.
- **Role bypass**: the role or permission level originates from client-supplied input and is accepted by the server without independent verification.

## Vulnerable Conditions

- A privileged operation (admin action, data modification, or sensitive read) executes without confirming the requesting user holds the necessary role or permission.
- Role or admin status is read directly from client-supplied input — such as a request body field, query parameter, or cookie — without a corresponding server-side lookup.

## Safe Patterns

- The endpoint is decorated with `@login_required`, `@admin_required`, or `@permission_required('...')`.
- The code calls `check_permission(user, action)`, `user.has_perm(...)`, or explicitly branches on `if not user.is_admin: abort(403)`.
- RBAC middleware is registered at the router or framework level and executes before the handler is reached.

---

## Python Source Detection Rules

### Flask missing decorators
- **VULN**: Admin route with no `@login_required` or role check:
  ```python
  @app.route('/admin/delete_user', methods=['POST'])
  def delete_user():
      user_id = request.form['user_id']
      User.query.filter_by(id=user_id).delete()
  ```
- **VULN**: `@app.route('/admin/...')` handler body has no `current_user.is_admin` check or `abort(403)`

### Client-supplied role
- **VULN**: `role = request.json.get('role')` then used to set permissions without server-side validation
- **VULN**: `user.role = request.form['role']` — role assigned directly from form input
- **VULN**: `is_admin = request.args.get('admin', False)` — admin flag from query string
- **SAFE**: Role fetched from database using authenticated user's ID: `user = db.query(User).get(current_user.id)`

### Django missing permission checks
- **VULN**: View missing `@permission_required` or `@staff_member_required` for admin operations
- **VULN**: `if request.user.is_authenticated:` only (no `is_staff` or `is_superuser` check) for admin action
- **SAFE**: `@permission_required('app.delete_user')`, `@staff_member_required`

### Horizontal → vertical escalation
- **VULN**: Only `user_id` validated, not ownership or role:
  ```python
  target_user = User.query.get(request.form['target_id'])
  target_user.is_admin = True
  ```

---

## JavaScript Source Detection Rules

### Express missing middleware
- **VULN**: Admin router/route without `isAdmin` or `requireRole` middleware:
  ```js
  app.delete('/admin/users/:id', (req, res) => { /* no auth check */ })
  ```
- **VULN**: Route handler reads role from request: `const role = req.body.role` then grants access
- **SAFE**: `router.use('/admin', requireAdmin)` — middleware applied to entire admin namespace

### JWT claims from client
- **VULN**: `const isAdmin = req.body.isAdmin` — client claims admin status
- **VULN**: `if (decoded.role === 'admin')` where `decoded` comes from untrusted token with unverified signature
- **SAFE**: Role read from verified JWT with fixed algorithm and server-side secret

### MongoDB / Mongoose
- **VULN**: `User.findByIdAndUpdate(req.body.userId, { role: req.body.role })` — role from client
- **SAFE**: Server looks up requesting user's role from DB before allowing the update

---

## PHP Source Detection Rules

### Session-based role bypass
- **VULN**: `$_SESSION['role'] = $_POST['role']` — session role set from POST without server validation
- **VULN**: `$_SESSION['is_admin'] = $_GET['admin']` — admin flag from query string
- **SAFE**: Role set only after DB lookup: `$_SESSION['role'] = $user['role']` from database query

### Missing authorization checks
- **VULN**: Admin function with no `checkAdmin()` or session role check:
  ```php
  function deleteUser($id) {
      $db->query("DELETE FROM users WHERE id = ?", [$id]);
  }
  ```
- **VULN**: `if ($_SESSION['logged_in'])` only — no role/admin check for privileged action

### Laravel / Symfony
- **VULN**: Route or controller method missing `middleware('admin')` or `$this->authorize(...)`
- **SAFE**: `$this->authorize('delete', $user)`, `Gate::allows('admin')`, `middleware('can:manage-users')`

---

## IDOR → Privilege Escalation Chain

Privilege escalation often occurs when an IDOR vulnerability allows accessing a higher-privileged user's resources or actions. Flag `privilege_escalation` in addition to `idor` when:

```python
# VULNERABLE: IDOR on user ID allows accessing admin account data
@app.route('/api/users/<int:user_id>/profile')
def get_profile(user_id):
    user = User.query.get(user_id)
    return jsonify(user.to_dict())   # no ownership check — accessing user_id=1 (admin) reveals admin data
# privilege_escalation: if admin profile contains credentials, tokens, or admin-only data
```

```java
// VULNERABLE: IDOR on account allows horizontal → vertical escalation
@GetMapping("/accounts/{accountId}/details")
public AccountDetails getDetails(@PathVariable Long accountId) {
    return accountService.findById(accountId);   // no principal ownership check
    // If accountId=1 is admin → returns admin details → privilege escalation
}
```

## Role/Permission Parameter Tampering

```python
# VULNERABLE: role passed in request body and trusted without server validation
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    user = User(
        username=data['username'],
        password=hash_password(data['password']),
        role=data.get('role', 'user')   # attacker supplies role='admin'
    )
    db.session.add(user)
```

```java
// VULNERABLE: user-controlled role assignment
@PostMapping("/api/users")
public User createUser(@RequestBody UserDTO dto) {
    User user = new User();
    user.setUsername(dto.getUsername());
    user.setRole(dto.getRole());   // role comes from request body — attacker supplies "ADMIN"
    return userRepository.save(user);
}
```

```js
// VULNERABLE: mass assignment allows role escalation in Node.js
app.put('/api/users/:id', authenticate, (req, res) => {
    User.findByIdAndUpdate(req.params.id, req.body, ...)   // req.body may include {role: 'admin'}
});
```

## JWT Claim Manipulation → Privilege Escalation

```python
# VULNERABLE: JWT payload trusted without server-side role validation
@app.route('/admin')
def admin_panel():
    token = request.headers.get('Authorization').split(' ')[1]
    payload = jwt.decode(token, SECRET, algorithms=['HS256'])
    if payload.get('role') == 'admin':    # role from JWT — if JWT forgeable, escalation possible
        return render_admin()

# VULNERABLE: alg=none bypass or weak secret → attacker forges JWT with role=admin
```

## Missing Function-Level Access Control

```python
# VULNERABLE: admin endpoints without role verification
@app.route('/admin/users')
@login_required    # only checks logged in, not admin role
def list_all_users():
    return jsonify([u.to_dict() for u in User.query.all()])

# SAFE:
@app.route('/admin/users')
@login_required
@requires_role('admin')
def list_all_users():
    ...
```

```java
// VULNERABLE: admin endpoint protected only by URL pattern, not method-level check
@GetMapping("/admin/deleteUser/{id}")
public ResponseEntity<?> deleteUser(@PathVariable Long id) {
    // No @PreAuthorize, no role check — any authenticated user can reach this
    userRepository.deleteById(id);
    return ResponseEntity.ok().build();
}

// SAFE: method-level security
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/deleteUser/{id}")
public ResponseEntity<?> deleteUser(@PathVariable Long id) { ... }
```

## Insecure Direct Reference to Privileged Operations

```php
// VULNERABLE: action parameter determines privileged operation
$action = $_GET['action'];
if ($action === 'deleteUser') {
    // No admin check — any user can trigger admin actions by guessing action names
    delete_user($_GET['user_id']);
}

// VULNERABLE: hidden admin toggle via parameter
if ($_POST['is_admin'] == '1') {
    $user->setAdmin(true);   // client-side field controls server-side privilege
}
```

## Detection Rules

### TRUE POSITIVE: Privilege Escalation

- IDOR on user/account objects where accessing another user's record reveals elevated capabilities or admin account details → **CONFIRM** (`idor` + `privilege_escalation`)
- `role` or `is_admin` field accepted from request body/params without server-side authority validation → **CONFIRM**
- Admin endpoint reachable by any authenticated user (missing `@PreAuthorize`, `@Secured`, role decorator) → **CONFIRM**
- JWT with role claim where the role is trusted from the token payload without server-side cross-check → **CONFIRM** (especially if JWT secret is weak/default)
- Mass assignment (`req.body` or `request.json` passed directly to ORM update) where `role`/`admin` fields are not excluded → **CONFIRM**

### FALSE POSITIVE: Not Privilege Escalation

- IDOR on non-sensitive data where all users have equal access (e.g., public posts, product listings) — **IDOR** only, not `privilege_escalation`
- Role check present but insufficiently strict (e.g., checks for any authenticated user) — flag as broken access control / `idor`, not `privilege_escalation` unless admin-level actions are reachable
- Admin role correctly enforced via `@PreAuthorize("hasRole('ADMIN')")` or equivalent — **SAFE**
- Reflection- or command-dispatch flaws such as dynamic `Class.forName(... + command + ...)` are not `privilege_escalation` by themselves; keep `unsafe_reflection` or `command_injection` unless the code also reaches an admin-only action or changes roles or permissions.
- `authentication`, `idor`, or generic broken-access-control findings should only be upgraded to `privilege_escalation` when a lower-privilege user can reach admin-only data, role changes, or privileged operations.
- In `vulhub`, representative Spring Security or auth-bypass CVE directories should preserve `privilege_escalation` when the exploit grants access to protected or admin routes by changing authentication state or bypassing route protection.

## Privilege Escalation as a Secondary / Companion Finding

Privilege escalation is frequently a **consequence** of another primary vulnerability. When analyzing code, always ask: "Does this vulnerability allow a lower-privileged user to gain higher-privileged access?" If yes, tag privilege escalation **in addition to** the primary vulnerability.

### Patterns That Almost Always Imply Privilege Escalation

1. **IDOR on user modification endpoints**: If an IDOR allows changing another user's password, role, or profile — and the target could be an admin — this is IDOR + privilege escalation.
   ```python
   # IDOR + privilege_escalation: change ANY user's password including admin
   @app.route('/change_password', methods=['POST'])
   def change_password():
       user_id = request.form['userId']  # attacker controls userId
       new_pass = request.form['password']
       User.query.get(user_id).password = hash(new_pass)
   ```

2. **JWT with weak/no verification**: If JWT signature is not verified (`verify=False`, `algorithms=['none']`, weak secret like `secret`), an attacker can forge tokens with `role=admin` → privilege escalation.
   ```python
   # jwt + privilege_escalation
   payload = jwt.decode(token, options={"verify_signature": False})
   ```

3. **X-Forwarded-For / X-Real-IP trust for access control**: If the application trusts client-supplied headers to determine admin access (e.g., "if IP == 127.0.0.1 then admin"), the header is spoofable → privilege escalation.
   ```python
   # privilege_escalation via header spoofing
   if request.headers.get('X-Forwarded-For') == '127.0.0.1':
       return admin_panel()
   ```

4. **Mass assignment allowing role/admin field**: When user-submitted form data or JSON directly sets `is_admin`, `role`, or permission fields without server-side filtering.
   ```python
   # privilege_escalation via mass assignment
   user.update(**request.json)  # request.json could include {"is_admin": true}
   ```

5. **Commented-out or missing authorization checks**: When a route handler has authorization logic commented out, deleted, or never implemented — especially on endpoints that modify user roles or access sensitive data.

6. **Session/cookie manipulation for role**: When role or admin status is stored in a client-side cookie (even if encoded/encrypted with weak crypto) and can be tampered with.

7. **Type juggling / loose comparison on auth**: PHP `==` comparisons or `strcmp()` returning NULL on type confusion, bypassing password checks to gain admin access.
   ```php
   // privilege_escalation via type juggling
   if (strcmp($_POST['password'], $admin_password) == 0) { // NULL == 0 is true
       $_SESSION['is_admin'] = true;
   }
   ```

8. **Hardcoded 2FA / verification codes**: When 2FA or verification codes are hardcoded (e.g., `if code == '1234'`), allowing bypass of multi-factor auth to reach admin functions.

### When NOT to Tag Privilege Escalation
- IDOR that only reads non-sensitive, equal-privilege data (e.g., viewing another regular user's public profile)
- Information disclosure that reveals data but does not grant elevated access
- XSS or CSRF alone (unless the XSS/CSRF specifically targets admin functionality)
- Default credentials alone — tag as `default_credentials`; only add `privilege_escalation` if the credentials grant admin-level access AND there is a separate mechanism (not just "login as admin with known password")

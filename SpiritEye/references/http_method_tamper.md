---
name: http_method_tamper
description: Detect HTTP method tampering vulnerabilities where GET requests trigger state-changing operations or method override headers/fields are accepted without restriction.
---

# HTTP Method Tampering

HTTP method tampering arises in two distinct scenarios:
1. **GET requests perform state-changing operations** (write, delete, update) — violates HTTP semantics and bypasses CSRF protections.
2. **Method override is accepted without restriction** — `_method` form field or `X-HTTP-Method-Override` header allows an attacker to turn a GET/POST into DELETE/PUT.

## How to Detect

- CSRF: GET-triggered mutations bypass SameSite cookie protection and CSRF tokens.
- Method override abuse: An attacker crafts a form/request that performs DELETE or PATCH through a POST channel.

## TRUE POSITIVE Criteria

- GET route performs a database write, delete, or other state-changing action.
- `X-HTTP-Method-Override` or `_method` field is accepted and overrides the HTTP method without restriction.

## FALSE POSITIVE Criteria

- REST APIs correctly using DELETE, PUT, PATCH via proper HTTP methods with CSRF protection.
- Method override only enabled in a controlled, authenticated context with CSRF token validation.

---

## Python Source Detection Rules

### Flask — GET triggers mutation
- **VULN**: `@app.route('/delete/<int:id>', methods=['GET', 'POST'])` where DELETE logic runs on GET
- **VULN**: `@app.route('/delete', methods=['GET'])` with `db.session.delete(obj)` in the handler
- **VULN**: `@app.route('/activate-user')` with no method restriction executing a DB update
- **SAFE**: `@app.route('/delete/<id>', methods=['POST', 'DELETE'])` with CSRF token validation

### Method override in Flask
- **VULN**: Custom middleware that reads `request.form.get('_method')` and overrides `request.method` without CSRF check
- **VULN**: `X-HTTP-Method-Override` header processed by a middleware and trusted unconditionally

### Django — unsafe methods
- **VULN**: `def delete_view(request):` without `if request.method == 'POST':` guard, accessible via GET
- **SAFE**: `@require_POST` or `@require_http_methods(["POST", "DELETE"])` decorator

---

## JavaScript Source Detection Rules

### Express — GET triggers mutation
- **VULN**: `app.get('/delete/:id', async (req, res) => { await Item.findByIdAndDelete(req.params.id) })`
- **VULN**: `router.get('/users/:id/ban', ...)` with DB mutation in handler
- **SAFE**: `app.delete('/users/:id', ...)` using correct HTTP verb

### Method override (method-override package)
- **VULN**: `app.use(methodOverride('_method'))` with no CSRF protection or restriction
- **VULN**: `app.use(methodOverride('X-HTTP-Method-Override'))` without authentication guard
- **SAFE**: method-override applied only after authentication middleware and with CSRF token validation

### Next.js / Express API routes
- **VULN**: API handler does not check `req.method` before executing mutation:
  ```js
  export default function handler(req, res) {
      // runs delete regardless of method
      await prisma.user.delete({ where: { id: req.query.id } });
  }
  ```

---

## PHP Source Detection Rules

### GET-triggered mutations
- **VULN**: `if (isset($_GET['delete_id'])) { $db->query("DELETE FROM items WHERE id = " . $_GET['delete_id']); }`
- **VULN**: Script performs INSERT/UPDATE/DELETE based on `$_GET` parameters without POST method check
- **SAFE**: `if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); exit; }`

### Laravel method spoofing
- **VULN**: `method_field('DELETE')` form submitted without CSRF token verification
- **VULN**: Route accessible via both GET and POST where the POST route performs deletion without CSRF check
- **SAFE**: Laravel's built-in CSRF middleware (`VerifyCsrfToken`) active for all state-changing routes

### Method override header
- **VULN**: `$method = $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] ?? $_SERVER['REQUEST_METHOD']` — override header trusted
- **SAFE**: Only trust override header after authentication and CSRF validation

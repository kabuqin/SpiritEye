---
name: nosql_injection
description: Detect NoSQL injection vulnerabilities where user-controlled data is passed directly into MongoDB or other NoSQL query operators without type validation.
---

# NoSQL Injection

NoSQL injection arises when user-supplied data is incorporated directly into a NoSQL query document. Unlike SQL injection, the payload exploits the database's native query operators (e.g., MongoDB `$gt`, `$where`, `$regex`) to alter query logic rather than breaking out of a SQL statement.

## Canonical Example

```python
# VULN — if username is {"$gt": ""} instead of a string, matches all users
collection.find({"username": request.json['username']})
```

The attacker sends: `{"username": {"$gt": ""}, "password": {"$gt": ""}}` to bypass authentication.

## TRUE POSITIVE Criteria

- User input is inserted directly as a MongoDB query value without any type validation.
- The input could be a dict/object (rather than a plain string) that MongoDB would treat as an operator expression.

## FALSE POSITIVE Criteria

- Type validation is performed before the query: `if isinstance(username, str):` or `typeof username === 'string'`.
- ORM-level type enforcement automatically rejects non-string values.
- MongoDB `$where` is not used with any user-controlled input.

---

## Python Source Detection Rules

### pymongo
- **VULN**: `collection.find({"username": request.json['username']})` — no isinstance check
- **VULN**: `collection.find({"email": request.form.get('email')})` — form value unvalidated
- **VULN**: `collection.find_one({"$where": f"this.username == '{username}'"})` — JS injection
- **VULN**: `collection.find(request.json)` — entire JSON body used as query document
- **SAFE**:
  ```python
  username = request.json.get('username')
  if not isinstance(username, str):
      abort(400)
  collection.find({"username": username})
  ```

### MongoEngine
- **VULN**: `User.objects(**request.json)` — arbitrary query kwargs sourced from user input
- **VULN**: `User.objects(raw_query=request.json)` — raw query document supplied by user

### Source identifiers
`request.json`, `request.json.get`, `request.form.get`, `request.args.get`, `request.data`

---

## JavaScript Source Detection Rules

### mongoose
- **VULN**: `User.find({username: req.body.username})` — if `req.body.username` is an object `{$gt: ""}`, injection succeeds
- **VULN**: `User.findOne({email: req.body.email, password: req.body.password})` — both fields are injectable
- **VULN**: `db.collection('users').find(req.body.query)` — entire query sourced from request body
- **SAFE**:
  ```js
  if (typeof req.body.username !== 'string') return res.status(400).json({error: 'Invalid input'});
  User.find({username: req.body.username})
  ```
- **SAFE**: Use mongoose-sanitize or express-mongo-sanitize middleware

### $where operator
- **VULN**: `User.find({$where: `this.username == '${req.body.username}'`})` — JS code injection
- All `$where` usage with any user input is HIGH RISK (allows arbitrary JS execution inside MongoDB)

### Source identifiers
`req.body`, `req.query`, `req.params`

---

## PHP Source Detection Rules

### MongoDB PHP driver
- **VULN**: `$collection->find(['username' => $_POST['username']])` — POST value could be an array
- **VULN**: `$collection->find(['email' => $_GET['email']])` — GET value unvalidated
- **VULN**: `$collection->find(json_decode($_POST['filter'], true))` — JSON body used as query document
- **SAFE**:
  ```php
  $username = (string)$_POST['username']; // cast to string
  $collection->find(['username' => $username]);
  ```

### Type validation patterns
- **VULN**: No `(string)` cast or `is_string()` check before using input in a MongoDB query
- **SAFE**: `if (!is_string($_POST['username'])) { http_response_code(400); exit; }`

### Laravel MongoDB (jenssegers/laravel-mongodb)
- **VULN**: `User::where('username', request('username'))->first()` — no type validation in middleware
- **VULN**: `User::where(request()->all())->first()` — entire request object used as query

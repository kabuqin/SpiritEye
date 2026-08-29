---
name: graphql_injection
description: Detect GraphQL security issues including introspection exposure, SQL injection in resolvers, missing depth/complexity limits, and unauthenticated endpoints.
---

# GraphQL Security Issues

GraphQL APIs present a distinct attack surface that differs significantly from REST. The primary risk categories are:

1. **Introspection enabled in production** — exposes the complete schema to any caller.
2. **Injection in resolvers** — GraphQL arguments passed into SQL/NoSQL queries without parameterization.
3. **No query complexity/depth limits** — opens the door to DoS through deeply nested or batched queries.
4. **Unauthenticated GraphQL endpoint** — no auth middleware guarding the `/graphql` route.

## TRUE POSITIVE Criteria

- A resolver concatenates GraphQL arguments directly into a raw database query string.
- Introspection is active with no environment guard (`if DEBUG` / `if NODE_ENV !== 'production'`).
- The `/graphql` endpoint is reachable without any authentication or authorization middleware.

## FALSE POSITIVE Criteria

- The resolver uses parameterized queries: `db.execute("SELECT * FROM users WHERE id = ?", [args['id']])`.
- Introspection is disabled outside development environments.
- Authentication middleware is applied before the GraphQL handler.

---

## Python Source Detection Rules

### graphene / strawberry
- **VULN (SQL in resolver)**:
  ```python
  def resolve_user(root, info, id):
      return db.execute(f"SELECT * FROM users WHERE id = {id}").fetchone()
  ```
- **VULN**: `db.execute("SELECT * FROM users WHERE name = '" + args['name'] + "'")` in any resolver
- **SAFE**: `db.execute("SELECT * FROM users WHERE id = %s", (id,))` — parameterized
- **SAFE**: SQLAlchemy ORM: `User.query.filter_by(id=id).first()`

### Flask-GraphQL introspection
- **VULN**: `GraphQLView.as_view('graphql', schema=schema)` with no introspection guard
- **VULN**: `graphene.Schema(query=Query)` served at `/graphql` with no auth decorator
- **SAFE**: Introspection disabled: `GraphQLView.as_view('graphql', schema=schema, graphiql=False)` + validation rule

### No depth limit
- **VULN**: Schema served without `query_depth_limit` or `query_complexity_limit` middleware
- **Pattern**: `from graphql_server` or `from graphene_django` with no depth limit import

---

## JavaScript Source Detection Rules

### graphql-js / Apollo Server
- **VULN (SQL in resolver)**:
  ```js
  resolve: (parent, args) => db.query(`SELECT * FROM users WHERE id = ${args.id}`)
  ```
- **VULN**: Template literal or string concatenation in any resolver's database call
- **SAFE**: `db.query('SELECT * FROM users WHERE id = $1', [args.id])` — pg parameterized

### Introspection in production
- **VULN**: `new ApolloServer({ schema })` with no `introspection: false` for production
- **VULN**: Apollo Server v2: no `playground: false` for production
- **SAFE**: `introspection: process.env.NODE_ENV === 'development'`

### No depth/complexity limits
- **VULN**: Apollo Server without `validationRules: [depthLimit(5)]` or similar
- **Pattern**: Missing `graphql-depth-limit` or `graphql-query-complexity` imports

### Unauthenticated endpoint
- **VULN**: `app.use('/graphql', graphqlHTTP({ schema }))` — no auth middleware before graphqlHTTP
- **SAFE**: `app.use('/graphql', authenticate, graphqlHTTP({ schema }))`

---

## PHP Source Detection Rules

### Webonyx / graphql-php
- **VULN (SQL in resolver)**:
  ```php
  'resolve' => function($root, $args) use ($db) {
      return $db->query("SELECT * FROM users WHERE id = " . $args['id']);
  }
  ```
- **VULN**: String concatenation or interpolation of GraphQL args into raw SQL queries
- **SAFE**: PDO prepared statements: `$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$args['id']])`

### Introspection
- **VULN**: `$server = new StandardServer(['schema' => $schema])` with introspection not disabled in production
- **SAFE**: Check for environment-based introspection toggle

### Unauthenticated endpoint
- **VULN**: `/graphql` route handler with no session or token authentication check before processing the query

### GraphQL Vulnerable Code Patterns (SAST Detection)

```python
# VULNERABLE: GraphQL query string built from user input (injection)
@app.route('/graphql', methods=['POST'])
def graphql_endpoint():
    query = request.json.get('query')
    result = schema.execute(query)   # user-controlled query executed directly — introspection + injection
    return jsonify(result.data)

# VULNERABLE: no depth/complexity limiting
schema = graphene.Schema(query=Query)
# Without query depth limit: attacker sends deeply nested query → DoS/resource exhaustion
```

```js
// VULNERABLE: GraphQL with introspection enabled in production
const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: true,   // exposes full schema — should be false in production
    playground: true       // developer UI enabled in production
});

// VULNERABLE: no query complexity/depth limit
const server = new ApolloServer({
    typeDefs,
    resolvers,
    // No validationRules: [depthLimit(5), createComplexityLimitRule(1000)]
});
```

```java
// VULNERABLE: GraphQL resolver with unsanitized variable used in SQL/LDAP
@QueryMapping
public List<User> users(@Argument String filter) {
    return em.createQuery("SELECT u FROM User u WHERE u.name = '" + filter + "'").getResultList();
    // GraphQL variable → SQL injection
}

// VULNERABLE: batch query / alias attack (no rate limiting on aliases)
// query { a: user(id:1){...} b: user(id:2){...} ... z: user(id:26){...} }
// Allows bulk data extraction through a single GraphQL request
```

### GraphQL-Specific Vulnerability Classes

1. **Introspection exposure** — schema structure leaked via `__schema`/`__type` queries
2. **SQL/NoSQL injection via resolver** — GraphQL variable reaches DB query without parameterization
3. **Batch query / alias enumeration** — multiple aliased queries in one request bypass rate limits
4. **Broken object-level authorization** — resolver doesn't check if requesting user owns the object
5. **No query depth/complexity limit** — deeply nested queries cause DoS

### GraphQL TRUE POSITIVE Rules

- GraphQL endpoint accepting user-controlled query string without schema validation → **CONFIRM** (`graphql`)
- Resolver using string concatenation with GraphQL argument in SQL/NoSQL query → **CONFIRM** (`graphql` + `sqli`)
- `introspection: true` in production Apollo/Graphene config → **CONFIRM** (`graphql` + `information_disclosure`)
- No depth limit + no complexity limit on public GraphQL endpoint → **CONFIRM** (`graphql`)
- GraphQL resolver accessing object by ID without ownership check → **CONFIRM** (`graphql` + `idor`)

### GraphQL FALSE POSITIVE Rules

- Introspection disabled (`introspection: false`) AND depth/complexity limits enforced — lower risk
- Parameterized resolver: `WHERE id = $1` with bound variable, no string concatenation — **NOT injection**

### Tag Convention

- **Default tag**: `graphql_injection` — use this in all general scans and most benchmark projects
- **Short form**: `graphql` — use only when the benchmark ground truth (`xben/`) explicitly expects the short-form tag
- When a GraphQL vulnerability involves a secondary class (e.g., SQL injection in a resolver), emit both tags: `graphql_injection` + `sql_injection`

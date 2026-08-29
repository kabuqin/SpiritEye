---
name: expression_language_injection
description: Expression Language injection detection for OGNL, SpEL, MVEL, EL, Groovy — vulnerable code patterns where user input reaches EL evaluation sinks
---

# Expression Language Injection

> **Precedence note**: This file is the primary reference for all expression language injection vulnerabilities (SpEL, OGNL, MVEL, Jakarta EL, Groovy). When an EL injection finding overlaps with content in `rce.md` (which also covers EL/SpEL/OGNL sinks), the detection rules and tag guidance in THIS file take precedence. Use `rce.md` only for EL-related content that is not covered here (e.g., EL-to-command-chain classification).

EL injection occurs when user-controlled input is passed into an expression language evaluator without sanitization, allowing arbitrary code execution. This covers OGNL (Struts2), SpEL (Spring), MVEL, Jakarta EL, Groovy `GroovyShell`, and similar dynamic evaluation APIs.

## CWE Classification

- **CWE-94**: Improper Control of Generation of Code (Code Injection)
- **CWE-917**: Improper Neutralization of Special Elements Used in an Expression Language Statement

## Source → Sink Pattern

**Sources**: `request.getParameter()`, `@RequestParam`, `@PathVariable`, `@RequestBody`, HTTP headers, cookies

**Sinks**:
- OGNL: `Ognl.getValue(userInput, context, root)`
- SpEL: `parser.parseExpression(userInput).getValue(...)`
- MVEL: `MVEL.eval(userInput, vars)`
- EL: `ELProcessor.eval(userInput)`, `ExpressionFactory.createValueExpression(ctx, userInput, ...)`
- Groovy: `new GroovyShell().evaluate(userInput)`, `Eval.me(userInput)`
- Scripting: `ScriptEngine.eval(userInput)`, `new ScriptEngineManager().getEngineByName("groovy").eval(userInput)`

## Vulnerable Code Patterns

### OGNL (Struts2 / Apache Commons OGNL)

```java
// VULNERABLE: user input evaluated as OGNL expression
String expr = request.getParameter("expression");
Object result = Ognl.getValue(expr, context, root);

// VULNERABLE: Struts2 tag with user-controlled value attribute
// In JSP: <s:property value="%{request.getParameter('name')}"/>
// OGNL evaluation of request params via ValueStack
```

**VULN indicator**: `Ognl.getValue(...)` or `Ognl.parseExpression(...)` where the expression string is derived from HTTP input.

**Struts2 OGNL RCE condition**:
- `struts2-core` present in `pom.xml` at vulnerable version
- AND `struts.xml` contains `<action>` mapping that reaches the vulnerable code path
- Without both conditions, do NOT flag as high-confidence TP

### SpEL (Spring Expression Language)

```java
// VULNERABLE: user input as SpEL expression
String input = request.getParameter("query");
ExpressionParser parser = new SpelExpressionParser();
Expression expr = parser.parseExpression(input);  // RCE if input = "T(Runtime).getRuntime().exec('id')"
Object result = expr.getValue();

// VULNERABLE: SpEL in @Value annotation with user-controlled property
@Value("#{systemProperties['user.home'] + '/' + userInput}")

// VULNERABLE: SpEL template with user input
TemplateParserContext ctx = new TemplateParserContext();
Expression expr = parser.parseExpression(userInput, ctx);

// SAFE: SpEL with SimpleEvaluationContext (no method invocations)
EvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
parser.parseExpression(input).getValue(ctx);
```

**VULN indicator**: `SpelExpressionParser` + `parseExpression(userInput)` with `StandardEvaluationContext` (default) or no context restriction.

**FALSE POSITIVE**: `SimpleEvaluationContext` blocks method invocations and type access — NOT exploitable for RCE.

### MVEL

```java
// VULNERABLE: MVEL evaluates user input directly
String userExpr = request.getParameter("filter");
Object result = MVEL.eval(userExpr, vars);          // arbitrary Java execution

// VULNERABLE: MVEL.executeExpression(compiledExpr, vars) where compiledExpr built from user input
Serializable compiled = MVEL.compileExpression(request.getParameter("expr"));
MVEL.executeExpression(compiled, context);
```

### Jakarta EE / JSF EL

```java
// VULNERABLE: user input embedded in EL expression string
String name = request.getParameter("name");
FacesContext fc = FacesContext.getCurrentInstance();
ELContext elCtx = fc.getELContext();
ExpressionFactory ef = fc.getApplication().getExpressionFactory();
ValueExpression ve = ef.createValueExpression(elCtx, "${" + name + "}", Object.class);
// If name = "facesContext.externalContext.request" etc — information disclosure
// If name = "''['class'].forName('java.lang.Runtime')" — RCE in some EL implementations

// VULNERABLE: JSP EL with unescaped user input in template
// <%-- JSP: user data rendered as: ${param.name} in EL context --%>
```

### Groovy Script Execution

```java
// VULNERABLE: user input executed as Groovy script
String script = request.getParameter("script");
GroovyShell shell = new GroovyShell();
Object result = shell.evaluate(script);             // full RCE

// VULNERABLE: ScriptEngine with Groovy
ScriptEngine engine = new ScriptEngineManager().getEngineByName("groovy");
engine.eval(request.getParameter("code"));

// VULNERABLE: Groovy's Eval.me()
Object val = Eval.me(request.getParameter("expr"));
```

### Thymeleaf SSTI / SpEL context

```java
// VULNERABLE: Thymeleaf template with user-controlled fragment selector
// URL: /__/fragments/section :: (${T(java.lang.Runtime).getRuntime().exec('id')})
// When controller passes user input directly as fragment expression:
String template = "fragments/" + request.getParameter("page");
return template;  // if Thymeleaf processes the path as a fragment expression, SSTI possible
```

## Java Source Detection Rules

### TRUE POSITIVE

- `SpelExpressionParser().parseExpression(userInput)` with default `StandardEvaluationContext` or no context → **CONFIRM** (RCE possible via `T(java.lang.Runtime)`)
- `Ognl.getValue(userInput, ...)` where `userInput` is HTTP request data → **CONFIRM**
- `MVEL.eval(userInput, ...)` where `userInput` is HTTP request data → **CONFIRM**
- `GroovyShell().evaluate(userInput)` or `ScriptEngine.eval(userInput)` → **CONFIRM** (full RCE)
- `ELProcessor.eval(userInput)` where EL implementation supports method invocations → **CONFIRM**

### FALSE POSITIVE

- `SimpleEvaluationContext` used with SpEL — blocks `T(...)` type references and method invocations
- SpEL used only with property paths on trusted bean objects with no user-controlled expression string
- OGNL in Struts2 param binding where no version vulnerability applies and OGNL sandbox is in effect (Struts >= 2.5.31 with `struts.ognl.excludedClasses`)
- EL in JSP rendering where user data is passed as a value binding argument (the *value*, not the *expression itself*)

## PHP/Python/Node.js EL-Equivalent Patterns

### PHP

```php
// VULNERABLE: eval() with user input
eval($_GET['code']);
eval('$result = ' . $_POST['expr'] . ';');

// VULNERABLE: create_function() (deprecated but still present)
$fn = create_function('', $_GET['body']);
$fn();

// VULNERABLE: preg_replace with /e modifier (PHP < 7.0)
preg_replace('/' . $_GET['pattern'] . '/e', $_GET['replacement'], $subject);
```

### Python

```python
# VULNERABLE: eval/exec with user input
result = eval(request.args['expr'])
exec(request.form['code'])

# VULNERABLE: Jinja2 render with user-controlled template string
from jinja2 import Template
Template(user_input).render()   # SSTI — should use Environment.from_string on sandboxed env
```

### Node.js

```js
// VULNERABLE: vm.runInThisContext with user input
const vm = require('vm');
vm.runInThisContext(req.body.code);     // full access to Node globals

// VULNERABLE: eval() in request handler
app.get('/calc', (req, res) => { res.send(eval(req.query.expr)); });

// VULNERABLE: Function constructor
const fn = new Function(req.body.code);
fn();
```

## Severity

| Pattern | Severity |
|---------|----------|
| GroovyShell/ScriptEngine eval with user input | Critical |
| SpEL with StandardEvaluationContext | Critical |
| OGNL eval with user input | Critical |
| MVEL eval with user input | Critical |
| EL eval in JEE with method support | High |
| PHP eval() with user input | Critical |
| Python eval()/exec() with user input | Critical |
| Thymeleaf fragment expression injection | High |

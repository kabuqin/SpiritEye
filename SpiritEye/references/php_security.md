---
name: php_security
description: PHP-specific vulnerability detection — dangerous functions, type juggling, file inclusion, object injection, framework sinks, and configuration weaknesses
---

# PHP Security

PHP has numerous language-specific vulnerability patterns beyond the common OWASP categories. This reference covers PHP-specific sinks, type juggling exploits, object injection via `unserialize()`, dynamic code execution, dangerous configuration settings, and framework-specific patterns (Laravel, Symfony, CodeIgniter, WordPress).

## CWE Classification

- **CWE-78**: OS Command Injection
- **CWE-94**: Code Injection
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-22**: Path Traversal
- **CWE-843**: Type Confusion (via type juggling)

## PHP Dangerous Function Sinks

### Code/Command Execution Sinks

```php
// CRITICAL: any user input reaching these functions
eval($_GET['code']);
eval('$var = ' . $_POST['value'] . ';');
assert($_GET['assertion']);                    // PHP < 8: assert() can execute code strings
preg_replace('/' . $_GET['pattern'] . '/e', $_GET['replacement'], $subject);  // /e modifier (PHP < 7)

exec($_GET['cmd'], $output);
system($_GET['cmd']);
passthru($_GET['cmd']);
shell_exec($_GET['cmd']);
`{$_GET['cmd']}`;                             // backtick operator
popen($_GET['cmd'], 'r');
proc_open($_GET['cmd'], $desc, $pipes);

// VULN indicator: user-controlled variable reaching any of the above
```

### Dynamic Include / Require

```php
// VULNERABLE: LFI / RFI via dynamic include
include($_GET['page']);
require($_GET['page']);
include_once($_GET['template']);
require_once($_GET['module']);

// VULNERABLE: with partial control (may still be LFI)
include('templates/' . $_GET['theme'] . '.php');
include($_GET['lang'] . '/messages.php');
// Bypasses: null byte (%00 in PHP < 5.3.4), wrappers (php://filter, zip://)

// VULN indicator: any $_GET/$_POST/$_COOKIE/$_REQUEST in include/require argument
```

### File Operations

```php
// VULNERABLE: path traversal in file ops
file_get_contents($_GET['file']);
file_put_contents($_GET['file'], $data);
readfile($_GET['path']);
fopen($_GET['filename'], 'r');
copy($_FILES['upload']['tmp_name'], $_GET['destination']);

// VULNERABLE: SSRF via file_get_contents with URL
$data = file_get_contents($_GET['url']);    // supports http://, ftp://
```

## PHP Type Juggling Vulnerabilities

### Loose Comparison (`==`) Exploits

```php
// VULNERABLE: loose comparison with magic hash values
$token = md5($user_input);
if ($token == "0") { ... }         // any MD5 starting with "0e" + digits == 0 in PHP
if ($token == 0) { ... }           // "0e..." == 0 is TRUE

// VULNERABLE: authentication bypass via type juggling
$hash = hash('md5', $_POST['password']);
if ($hash == $_SESSION['stored_hash']) {  // "0e..." == "0e..." even if different
    // authenticated
}

// VULNERABLE: JSON type confusion
$data = json_decode($_POST['data']);
if ($data->token == $expected_token) {    // if $data->token is integer 0 and $expected_token is "0e..."
    // bypass
}

// SAFE: use strict === comparison
if ($hash === $expected_hash) { ... }
```

**Magic hash values** (MD5 hashes starting with `0e` + digits):
- `240610708` → MD5 = `0e462097431906509019562988736854`
- `QNKCDZO` → MD5 = `0e830400451993494058024219903391`
- `s878926199a` → SHA1 = `0e545993274517709034328855841020`

### Type Juggling in Switch/in_array

```php
// VULNERABLE: in_array without strict mode
$roles = ['admin', 'user', 'guest'];
if (in_array($_POST['role'], $roles)) { ... }
// Attacker sends role=0 → in_array(0, ['admin','user','guest']) === TRUE (0 == 'admin' in loose mode)

// SAFE:
if (in_array($_POST['role'], $roles, true)) { ... }  // third param true = strict

// VULNERABLE: switch uses loose comparison
switch ($_GET['status']) {
    case 1: grantAdmin(); break;    // status=true or status="1abc" may match
}
```

## PHP Object Injection (Deserialization)

```php
// VULNERABLE: unserialize() on user-controlled input
$data = unserialize($_COOKIE['user']);
$obj = unserialize(base64_decode($_GET['data']));
$obj = unserialize(file_get_contents($_POST['serialized_file']));

// IMPACT: If the application has classes with __wakeup(), __destruct(),
//         __toString() magic methods that perform dangerous operations:
class FileLogger {
    public $logFile;
    public function __destruct() {
        file_put_contents($this->logFile, "destroyed");  // arbitrary file write
    }
}
// Attacker crafts: O:10:"FileLogger":1:{s:7:"logFile";s:15:"/var/www/evil.php";}

// VULN indicator: unserialize() accepting any $_GET/$_POST/$_COOKIE/$_REQUEST/$_SERVER data
// ALSO check: __wakeup, __destruct, __toString magic methods doing file/exec/eval operations
```

## PHP Framework-Specific Patterns

### Laravel

```php
// VULNERABLE: raw query with user input (SQL injection)
DB::select("SELECT * FROM users WHERE name = '" . $request->name . "'");
DB::statement("DELETE FROM logs WHERE id = " . $request->id);

// VULNERABLE: Mass assignment without $guarded/$fillable protection
User::create($request->all());             // if $fillable not defined, all fields assignable
// Attacker can set is_admin=1 if no $guarded = ['is_admin']

// VULNERABLE: Blade template with raw output (XSS)
{!! $user_input !!}                        // unescaped output
// SAFE:
{{ $user_input }}                          // escaped by default

// VULNERABLE: deserialization in cookie/session (HMAC bypass not considered)
// Laravel signed cookies use app key — if app key is leaked, cookie forgery enables deserialization

// VULNERABLE: eval in Blade custom directives
Blade::directive('inject', function ($expression) {
    return "<?php eval({$expression}); ?>";   // dangerous custom directive
});
```

### Symfony

```php
// VULNERABLE: createQuery with user-controlled DQL
$query = $em->createQuery("SELECT u FROM User u WHERE u.name = '" . $_GET['name'] . "'");
// SAFE: use setParameter()
$query = $em->createQuery('SELECT u FROM User u WHERE u.name = :name')
            ->setParameter('name', $_GET['name']);

// VULNERABLE: Symfony YAML unsafe parsing
$data = Yaml::parse($userInput, Yaml::PARSE_OBJECT);
// SAFE: Yaml::parse($userInput) — no PARSE_OBJECT flag
```

### WordPress

```php
// VULNERABLE: direct DB query without $wpdb->prepare()
$results = $wpdb->get_results("SELECT * FROM {$wpdb->posts} WHERE post_title = '" . $_GET['title'] . "'");
// SAFE:
$results = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE post_title = %s", $_GET['title']));

// VULNERABLE: add_action with eval (plugin code injection)
add_action('wp_ajax_run_code', function() {
    eval($_POST['code']);   // arbitrary PHP execution
});

// VULNERABLE: update_option with unvalidated user data
update_option('admin_email', $_POST['email']);  // may allow option injection

// VULNERABLE: file path construction from request
$template = get_template_directory() . '/' . $_GET['template'] . '.php';
include($template);   // path traversal in template param
```

### CodeIgniter

```php
// VULNERABLE: direct query without query builder
$this->db->query("SELECT * FROM users WHERE id = " . $this->input->get('id'));
// SAFE: use query bindings
$this->db->query("SELECT * FROM users WHERE id = ?", [$this->input->get('id')]);
```

## PHP Configuration Weaknesses (php.ini)

| Setting | Dangerous Value | Risk |
|---------|----------------|------|
| `allow_url_include` | `On` | RFI via include/require with http:// URLs |
| `allow_url_fopen` | `On` | SSRF via file_get_contents on URLs |
| `display_errors` | `On` in production | Information disclosure (paths, DB errors) |
| `register_globals` | `On` (PHP < 5.4) | Variable injection — `$_GET` populates globals |
| `magic_quotes_gpc` | off + no escaping | SQL injection facilitated |
| `session.use_strict_mode` | `0` | Session fixation attacks |
| `disable_functions` | missing exec/system | OS command execution enabled |

## PHP Superglobal Sources

All of the following are attacker-controlled sources:
- `$_GET['x']`, `$_POST['x']`, `$_COOKIE['x']`, `$_REQUEST['x']`
- `$_FILES['x']['name']`, `$_FILES['x']['type']` (MIME type — client-controlled)
- `$_SERVER['HTTP_HOST']`, `$_SERVER['HTTP_REFERER']`, `$_SERVER['HTTP_USER_AGENT']`
- `$_SERVER['QUERY_STRING']`, `$_SERVER['REQUEST_URI']`, `$_SERVER['PHP_SELF']`
- `getallheaders()`, `apache_request_headers()`
- `file_get_contents('php://input')`, `fopen('php://input', 'r')`

**Note**: `$_SERVER['PHP_SELF']` is often used in HTML forms and is XSS-injectable.

## PHP-Specific Detection Rules

### TRUE POSITIVE

- `eval(` + any superglobal or user-derived variable → **CONFIRM** (RCE)
- `include/require` + `$_GET/$_POST/$_COOKIE` → **CONFIRM** (LFI / RFI)
- `unserialize(` + superglobal or decoded cookie → **CONFIRM** + check for magic method gadgets
- `==` (loose) comparison in authentication/token validation → **CONFIRM** (type juggling bypass)
- `in_array($input, $list)` without `true` third argument in access control → **CONFIRM** (type juggling)
- `exec/system/passthru/shell_exec(` + user input → **CONFIRM** (OS command injection)
- `file_get_contents($_GET['url'])` or similar → **CONFIRM** (SSRF or LFI)
- `DB::select("...'" . $request->x . "'...")` in Laravel → **CONFIRM** (SQL injection)

### FALSE POSITIVE

- `unserialize()` used exclusively on server-generated, HMAC-signed data where the signature is validated *before* unserialize
- `include` with `basename()` applied to user input AND only static extension appended AND `allow_url_include=Off`
- `eval()` inside a template engine's own codebase (e.g., Smarty's compiled templates) — not a direct user-input path

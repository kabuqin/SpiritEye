---
name: mobile_security
description: Mobile security detection for Android and iOS — vulnerable code patterns for insecure data storage, intent injection, WebView RCE, insecure IPC, and crypto misuse
---

# Mobile Security (Android / iOS)

Identify cases where mobile application code stores sensitive data insecurely, exposes components to untrusted callers, passes user-controlled input to dangerous APIs without validation, or applies weak or static cryptographic material.

## Source -> Sink Pattern

**Android Sources**
- `getIntent().getStringExtra(...)` / `getIntent().getData()`
- `ContentResolver` query parameters passed through `Uri` or cursor data
- `Bundle` values from `getArguments()` in Fragment
- Deep-link parameters extracted from `Intent.ACTION_VIEW` data
- IPC data received via `Messenger`, `AIDL`, or `BroadcastReceiver.onReceive(context, intent)`

**iOS Sources**
- URL scheme parameters: `url.host`, `url.path`, `URLComponents(url:).queryItems`
- Universal Link / deep-link payload in `application(_:open:options:)`
- Push notification payload: `userInfo["url"]` or arbitrary `userInfo` keys
- Clipboard: `UIPasteboard.general.string`
- `WKScriptMessage.body` from JavaScript message handlers

**Android Sinks**
- `SharedPreferences.Editor.putString(key, sensitiveValue)` with `MODE_WORLD_READABLE`
- `SQLiteDatabase.execSQL(rawQuery)` / `rawQuery(query, null)` where query contains untrusted data
- `Log.d/i/v/w/e(TAG, sensitiveValue)`
- `new FileOutputStream(new File(Environment.getExternalStorageDirectory(), filename))`
- `WebView.loadUrl(userControlledUrl)`
- `WebView.addJavascriptInterface(object, name)`
- `startActivity(intentFromIPC)` / `startService(intentFromIPC)`
- `Cipher.getInstance("AES/ECB/...")` / `Cipher.getInstance("DES/...")`

**iOS Sinks**
- `UserDefaults.standard.set(sensitiveValue, forKey: key)`
- `FileManager.default.createFile(atPath: docPath, contents: sensitiveData, attributes: nil)` without `NSFileProtectionComplete`
- `print(sensitiveValue)` / `NSLog(@"%@", sensitiveValue)`
- `WKWebView.load(URLRequest(url: unvalidatedURL))`
- `UIApplication.shared.open(unvalidatedURL)`
- `CCCrypt` with `kCCAlgorithmDES` or key length < 16
- `SecItemAdd` / `SecItemUpdate` storing cleartext passwords outside the keychain

---

## Android Vulnerable Patterns

### Insecure Data Storage

#### SharedPreferences with Sensitive Data

**VULN** — world-readable preference file exposing credentials:
```java
SharedPreferences prefs = getSharedPreferences("creds", MODE_WORLD_READABLE);
prefs.edit().putString("password", userPassword).apply();
```

**VULN** — storing auth token in default (unencrypted) SharedPreferences:
```java
getSharedPreferences("app_prefs", MODE_PRIVATE)
    .edit().putString("auth_token", token).apply();
// MODE_PRIVATE is filesystem-private but still plaintext on the device
```

**SAFE** — using `EncryptedSharedPreferences` from Jetpack Security:
```java
SharedPreferences encPrefs = EncryptedSharedPreferences.create(
    "secret_prefs", masterKeyAlias, context,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
encPrefs.edit().putString("auth_token", token).apply();
```

**TRUE POSITIVE**: `putString` / `putInt` / `putLong` writing a value whose variable name or assignment origin contains tokens such as `password`, `token`, `secret`, `key`, `credential`, `ssn`, `pin`, or `cvv`.

**FALSE POSITIVE**: `putString("theme", userSelectedTheme)` — non-sensitive UI preference. Do not flag when the stored value demonstrably carries no authentication or personal-data semantics.

---

#### Logging Sensitive Data

**VULN**:
```java
Log.d(TAG, "User password: " + password);
Log.i(TAG, "Auth token=" + authToken);
Log.e(TAG, "Login failed for user: " + email + " pwd=" + pwd);
```

**SAFE** — sanitized log message:
```java
Log.d(TAG, "Login attempt for user: " + userId);  // no credential value
```

**TRUE POSITIVE**: `Log.d/i/v/w/e` where the concatenated or formatted string contains a variable whose name matches `password`, `passwd`, `token`, `secret`, `key`, `credential`, `pin`, `cvv`, `ssn`, or `dob`.

**FALSE POSITIVE**: `Log.d(TAG, "Request URL: " + url)` where `url` is a non-sensitive endpoint. Evaluate the variable name and assignment chain, not the presence of `Log` alone.

---

#### External Storage Writes with Sensitive Data

**VULN**:
```java
File file = new File(Environment.getExternalStorageDirectory(), "user_data.json");
FileOutputStream fos = new FileOutputStream(file);
fos.write(sensitiveJson.getBytes());
```

**SAFE** — internal storage:
```java
FileOutputStream fos = openFileOutput("user_data.json", Context.MODE_PRIVATE);
fos.write(encryptedData);
```

**TRUE POSITIVE**: `getExternalStorageDirectory()` or `getExternalFilesDir()` combined with a write operation whose data originates from a sensitive variable or network response containing credentials/PII.

**FALSE POSITIVE**: Writing a cached image, log file, or media file to external storage where the content carries no sensitive semantics.

---

#### Hardcoded Credentials / Keys

**VULN**:
```java
private static final String API_KEY = "AIzaSyD-EXAMPLE-KEY-12345";
private static final String DB_PASSWORD = "Sup3rS3cr3t!";
String jwt = signJWT(payload, "hardcoded_secret_key");
```

**TRUE POSITIVE**: String literal assigned to a variable named `key`, `secret`, `password`, `token`, `apiKey`, `privateKey`, or `credential` — particularly when the literal length and entropy are consistent with a real credential (e.g., > 16 characters with mixed case and digits).

**FALSE POSITIVE**: Placeholder strings such as `"YOUR_KEY_HERE"`, `"TODO"`, or `"REPLACE_ME"` in configuration templates. Also do not flag localization strings, error message literals, or display labels even when they appear in a field named `key`.

---

### Intent Injection / Exported Components

#### Exported Activity / Service / Receiver Without Permission Check

**VULN** — exported with no `android:permission`:
```xml
<activity android:name=".DeepLinkActivity" android:exported="true" />
<service android:name=".SyncService" android:exported="true" />
<receiver android:name=".TokenReceiver" android:exported="true" />
```

```java
// Inside DeepLinkActivity.onCreate — no caller identity check
String target = getIntent().getStringExtra("redirect");
startActivity(new Intent(this, InternalActivity.class).putExtra("url", target));
```

**SAFE** — permission-gated export:
```xml
<activity android:name=".AdminActivity"
          android:exported="true"
          android:permission="com.example.permission.ADMIN" />
```

**TRUE POSITIVE**: `android:exported="true"` on a component that reads intent extras and uses them in a sensitive operation (file access, SQL query, `startActivity`, `loadUrl`) without validating the caller via `checkCallingPermission` or an explicit allowlist.

**FALSE POSITIVE**: Launcher Activity with `<intent-filter><action android:name="android.intent.action.MAIN"/>` — this must be exported; flag only when it also passes intent extras to dangerous sinks without validation.

---

#### Intent Data Used in SQL / File Path Without Validation

**VULN**:
```java
String id = getIntent().getStringExtra("user_id");
Cursor c = db.rawQuery("SELECT * FROM users WHERE id='" + id + "'", null);
```

```java
String filename = getIntent().getStringExtra("file");
File f = new File(getFilesDir(), filename);  // path traversal if filename contains ../
FileInputStream fis = new FileInputStream(f);
```

**SAFE**:
```java
String id = getIntent().getStringExtra("user_id");
Cursor c = db.rawQuery("SELECT * FROM users WHERE id=?", new String[]{id});
```

**TRUE POSITIVE**: `getIntent().getStringExtra(...)` / `getIntent().getData()` value flows without sanitization into `rawQuery`, `execSQL`, `new File(base, userValue)`, `loadUrl`, or `Runtime.exec`.

**FALSE POSITIVE**: Intent extra used only as a display label rendered in a `TextView` with no HTML rendering enabled.

---

#### WebView Loading Intent-Supplied URL

**VULN**:
```java
String url = getIntent().getStringExtra("url");
webView.loadUrl(url);  // arbitrary URL including javascript: or file://
```

**SAFE**:
```java
String url = getIntent().getStringExtra("url");
if (url != null && url.startsWith("https://trusted.example.com/")) {
    webView.loadUrl(url);
}
```

**TRUE POSITIVE**: `webView.loadUrl(...)` or `webView.loadData(...)` where the argument is directly derived from `getIntent()`, `getStringExtra`, `uri.getQueryParameter`, or another IPC channel without a strict prefix or allowlist check.

**FALSE POSITIVE**: `webView.loadUrl(BuildConfig.BASE_URL + "/help")` where `BuildConfig.BASE_URL` is a compile-time constant.

---

### WebView RCE

#### addJavascriptInterface Exposure

**VULN**:
```java
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(new FileAccessBridge(this), "NativeBridge");
// FileAccessBridge methods are now callable from any page loaded in the WebView
```

**SAFE** — restrict to trusted origins only and remove the interface when not needed:
```java
// On API < 17, addJavascriptInterface is exploitable regardless.
// On API >= 17, only @JavascriptInterface-annotated methods are exposed,
// but loading untrusted URLs still allows arbitrary method invocation.
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
    webView.addJavascriptInterface(bridge, "NativeBridge");
    webView.loadUrl("https://internal.example.com/ui");
} // ensure the loaded URL is never user-controlled
```

**TRUE POSITIVE**: `addJavascriptInterface` present AND `setJavaScriptEnabled(true)` AND `loadUrl` / `loadData` where the loaded URL or content is user-controlled or loaded from an untrusted origin.

**FALSE POSITIVE**: `addJavascriptInterface` where the WebView exclusively loads a bundled `file:///android_asset/` resource that contains no user-generated content and JavaScript is enabled only for that asset.

---

#### JavaScript Enabled with User-Controlled URL

**VULN**:
```java
WebSettings settings = webView.getSettings();
settings.setJavaScriptEnabled(true);
settings.setAllowFileAccessFromFileURLs(true);
webView.loadUrl(urlFromIntent);
```

**TRUE POSITIVE**: `setJavaScriptEnabled(true)` combined with `loadUrl` / `loadDataWithBaseURL` where the URL argument traces to external input (intent extra, deep link, push notification payload).

**FALSE POSITIVE**: `setJavaScriptEnabled(true)` with a hardcoded `loadUrl("https://app.example.com/home")` — no user control over the loaded origin.

---

#### shouldOverrideUrlLoading Returning False Unconditionally

**VULN**:
```java
webView.setWebViewClient(new WebViewClient() {
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        return false;  // allows all navigations including javascript: and file://
    }
});
```

**TRUE POSITIVE**: `shouldOverrideUrlLoading` returns `false` (or is absent) and no URL scheme validation is applied elsewhere before loading user-controlled navigations.

**FALSE POSITIVE**: Returns `false` only after an explicit scheme/host allowlist check has already confirmed the URL is safe.

---

### Insecure IPC

#### ContentProvider Without Permission Check

**VULN** — exported with no `android:permission`:
```xml
<provider
    android:name=".UserDataProvider"
    android:authorities="com.example.provider"
    android:exported="true" />
```

```java
@Override
public Cursor query(Uri uri, String[] projection, String selection,
                    String[] selectionArgs, String sortOrder) {
    return db.rawQuery("SELECT * FROM users WHERE " + selection, null);
    // 'selection' comes directly from untrusted caller
}
```

**SAFE**:
```xml
<provider
    android:name=".UserDataProvider"
    android:authorities="com.example.provider"
    android:exported="true"
    android:readPermission="com.example.permission.READ_DATA"
    android:writePermission="com.example.permission.WRITE_DATA" />
```

**TRUE POSITIVE**: `android:exported="true"` ContentProvider with no `android:permission` / `android:readPermission` attribute AND a `query` / `insert` / `update` / `delete` override that uses `selection` or `selectionArgs` in a raw SQL call without parameterization.

**FALSE POSITIVE**: ContentProvider exported solely for use by a companion app that shares the same `android:sharedUserId` and is declared as a system component. Still recommend adding permission protection as defense-in-depth.

---

#### SQL Injection in ContentProvider query()

**VULN**:
```java
public Cursor query(Uri uri, String[] proj, String selection, String[] args, String sort) {
    String query = "SELECT * FROM messages WHERE sender='" + selection + "'";
    return db.rawQuery(query, null);
}
```

**SAFE**:
```java
public Cursor query(Uri uri, String[] proj, String selection, String[] args, String sort) {
    return db.query("messages", proj, "sender=?", new String[]{selection}, null, null, sort);
}
```

**TRUE POSITIVE**: `selection` parameter concatenated into the SQL string passed to `rawQuery` or `execSQL` inside a ContentProvider method.

**FALSE POSITIVE**: `selection` passed as the `whereClause` argument of `db.query(table, proj, whereClause, whereArgs, ...)` where it is used as a parameterized clause with `whereArgs` — only flag if the literal SQL string is assembled by concatenation.

---

#### PendingIntent with Empty Base Intent

**VULN**:
```java
Intent base = new Intent();  // empty — action and component unset
PendingIntent pi = PendingIntent.getActivity(context, 0, base, PendingIntent.FLAG_MUTABLE);
// A malicious app receiving this PendingIntent can fill in any target
```

**SAFE**:
```java
Intent base = new Intent(context, TargetActivity.class);
PendingIntent pi = PendingIntent.getActivity(context, 0, base,
    PendingIntent.FLAG_IMMUTABLE);
```

**TRUE POSITIVE**: `PendingIntent` constructed from an `Intent` with no `setComponent`, `setClass`, or explicit action set, especially when `FLAG_MUTABLE` is used on API 31+.

**FALSE POSITIVE**: `FLAG_IMMUTABLE` PendingIntents with fully specified explicit intents — immutable PendingIntents cannot be modified by the recipient.

---

### Insecure Crypto (Android)

#### ECB Mode

**VULN**:
```java
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, secretKey);
```

**SAFE**:
```java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
```

**TRUE POSITIVE**: `Cipher.getInstance` argument contains `"ECB"` for any algorithm.

**FALSE POSITIVE**: None — ECB mode is never safe for encrypting data longer than one block.

---

#### Static / Zero IV

**VULN**:
```java
IvParameterSpec iv = new IvParameterSpec(new byte[16]);  // all-zero IV
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, key, iv);
```

**SAFE**:
```java
byte[] ivBytes = new byte[16];
new SecureRandom().nextBytes(ivBytes);
IvParameterSpec iv = new IvParameterSpec(ivBytes);
```

**TRUE POSITIVE**: `new IvParameterSpec(new byte[N])` — zero-initialized byte array used as IV, or any IV literal such as `"0000000000000000".getBytes()`.

**FALSE POSITIVE**: IV array that is subsequently filled by `SecureRandom.nextBytes(iv)` before use — evaluate the data flow, not just the allocation site.

---

#### Weak Key Size

**VULN**:
```java
KeyGenerator kg = KeyGenerator.getInstance("AES");
kg.init(64);  // 64-bit key — far below the 128-bit minimum
SecretKey key = kg.generateKey();
```

**SAFE**:
```java
KeyGenerator kg = KeyGenerator.getInstance("AES");
kg.init(256);
```

**TRUE POSITIVE**: `KeyGenerator.init(n)` where `n < 128` for AES, or `n < 2048` for RSA, or `n < 256` for EC.

**FALSE POSITIVE**: Key size argument is a variable whose value is determined at runtime from a validated configuration — flag only when the literal value is demonstrably weak.

---

#### java.util.Random for Security Tokens

**VULN**:
```java
Random rng = new Random();
String token = Long.toHexString(rng.nextLong());
session.setToken(token);
```

**SAFE**:
```java
SecureRandom rng = new SecureRandom();
byte[] tokenBytes = new byte[32];
rng.nextBytes(tokenBytes);
String token = Base64.encodeToString(tokenBytes, Base64.URL_SAFE | Base64.NO_WRAP);
```

**TRUE POSITIVE**: `new Random()` or `Math.random()` used to generate values assigned to variables named `token`, `nonce`, `otp`, `salt`, `sessionId`, `key`, or `secret`.

**FALSE POSITIVE**: `new Random()` used for UI randomness (shuffle, animation, A/B bucket assignment) where the value has no security meaning.

---

## iOS Vulnerable Patterns (Swift / Objective-C)

### Insecure Keychain / Storage

#### UserDefaults Storing Sensitive Data

**VULN**:
```swift
UserDefaults.standard.set(password, forKey: "userPassword")
UserDefaults.standard.set(authToken, forKey: "authToken")
```

**VULN (Objective-C)**:
```objc
[[NSUserDefaults standardUserDefaults] setObject:token forKey:@"auth_token"];
```

**SAFE** — store in the Keychain:
```swift
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "userPassword",
    kSecValueData as String: password.data(using: .utf8)!
]
SecItemAdd(query as CFDictionary, nil)
```

**TRUE POSITIVE**: `UserDefaults.standard.set(value, forKey: key)` where the value originates from a variable named `password`, `token`, `secret`, `key`, `credential`, `pin`, or `ssn`.

**FALSE POSITIVE**: `UserDefaults.standard.set(true, forKey: "hasCompletedOnboarding")` — non-sensitive flag. Evaluate the semantics of both the key name and the value origin.

---

#### File Written Without Data Protection

**VULN**:
```swift
let path = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("credentials.json")
try sensitiveData.write(to: path)  // no file protection attributes
```

**SAFE**:
```swift
try sensitiveData.write(to: path, options: .completeFileProtection)
// equivalent to NSFileProtectionComplete — file inaccessible when device is locked
```

**TRUE POSITIVE**: `.write(to: path)` or `FileManager.createFile(atPath:contents:attributes:)` with `attributes: nil` (or absent `NSFileProtectionKey`) when the written content is sensitive.

**FALSE POSITIVE**: Writing cached images, non-sensitive JSON configuration, or temporary files to `.cachesDirectory` without file protection is low risk; flag only when the written data contains credentials or PII.

---

#### Logging Sensitive Data

**VULN**:
```swift
print("Auth token: \(authToken)")
print("Password entered: \(password)")
NSLog("User credentials: %@ / %@", username, password)
```

**SAFE**:
```swift
print("Login attempt for user ID: \(userId)")  // no credential value emitted
```

**TRUE POSITIVE**: `print(...)` or `NSLog(...)` interpolating or formatting a variable whose name contains `password`, `token`, `secret`, `key`, `credential`, `pin`, or `ssn`.

**FALSE POSITIVE**: `print("Response status: \(statusCode)")` — no sensitive value present.

---

### Insecure URL Scheme / Deep Link Handling

#### Unvalidated Deep-Link URL Handling

**VULN**:
```swift
func application(_ app: UIApplication, open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    let target = url.host  // e.g. myapp://redirect?to=https://evil.com
    webView.load(URLRequest(url: URL(string: target!)!))
    return true
}
```

**SAFE**:
```swift
func application(_ app: UIApplication, open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    guard let host = url.host, allowedHosts.contains(host) else { return false }
    webView.load(URLRequest(url: URL(string: "https://\(host)/safe-path")!))
    return true
}
```

**TRUE POSITIVE**: URL components extracted from `application(_:open:options:)` or `scene(_:openURLContexts:)` flow directly into `WKWebView.load(URLRequest(...))`, `UIApplication.shared.open(...)`, or file operations without scheme/host validation.

**FALSE POSITIVE**: URL host extracted from the deep link and used only as a lookup key against a local dictionary or route map where actual navigation targets are hardcoded.

---

#### WKWebView Loading Unvalidated External URL

**VULN**:
```swift
let urlString = deepLinkURL.queryParameters["redirect"] ?? ""
webView.load(URLRequest(url: URL(string: urlString)!))
```

**SAFE**:
```swift
guard let urlString = deepLinkURL.queryParameters["redirect"],
      urlString.hasPrefix("https://trusted.example.com/") else { return }
webView.load(URLRequest(url: URL(string: urlString)!))
```

**TRUE POSITIVE**: `WKWebView.load(URLRequest(url: externalURL))` where `externalURL` is derived from external input (URL scheme, push notification, user text field) without strict prefix or allowlist validation.

**FALSE POSITIVE**: `webView.load(URLRequest(url: URL(string: "https://static.example.com/help")!))` — hardcoded URL, no user control.

---

### ATS Bypass (App Transport Security)

#### NSAllowsArbitraryLoads

**VULN** — Info.plist:
```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
```

**TRUE POSITIVE**: `NSAllowsArbitraryLoads` set to `true` at the top-level ATS dictionary — this disables TLS enforcement globally for all network connections.

**FALSE POSITIVE**: `NSAllowsArbitraryLoads` set to `true` only within `NSExceptionDomains` for a specific domain (e.g., a legacy internal server during a migration window) with `NSTemporaryExceptionAllowsInsecureHTTPLoads` is lower severity than the global flag; still report as a finding but at MEDIUM rather than HIGH.

---

#### NSExceptionDomains Insecure Exception

**VULN**:
```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>api.example.com</key>
        <dict>
            <key>NSTemporaryExceptionAllowsInsecureHTTPLoads</key>
            <true/>
            <key>NSIncludesSubdomains</key>
            <true/>
        </dict>
    </dict>
</dict>
```

**TRUE POSITIVE**: `NSTemporaryExceptionAllowsInsecureHTTPLoads: true` for a domain used as a production API endpoint, especially combined with `NSIncludesSubdomains: true`.

**FALSE POSITIVE**: Exceptions restricted to `localhost` or `127.0.0.1` for local development tooling — valid test configuration; do not flag in CI/CD SAST unless the build target is a release variant.

---

### Insecure Crypto (iOS)

#### DES or Small Key Size

**VULN**:
```swift
let status = CCCrypt(
    CCOperation(kCCEncrypt),
    CCAlgorithm(kCCAlgorithmDES),  // 56-bit key — broken
    CCOptions(kCCOptionPKCS7Padding),
    keyBytes, kCCKeySizeDES, iv,
    plaintext, plaintextLength,
    ciphertext, ciphertextLength, &moved)
```

**SAFE**:
```swift
CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
        keyBytes, kCCKeySizeAES256, iv, ...)
```

**TRUE POSITIVE**: `kCCAlgorithmDES`, `kCCAlgorithm3DES`, or `kCCAlgorithmRC4` in any `CCCrypt` call. Also flag `kCCAlgorithmAES` with key size constant `kCCKeySizeAES128` only when the key material is derived from a weak source (see below).

**FALSE POSITIVE**: `kCCAlgorithmAES` with `kCCKeySizeAES256` and a key derived from `SecRandomCopyBytes` — acceptable configuration.

---

#### Hardcoded Encryption Key

**VULN**:
```swift
let key = "MySecretKey12345"
let keyData = key.data(using: .utf8)!
CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
        (keyData as NSData).bytes, keyData.count, iv, ...)
```

**VULN (Objective-C)**:
```objc
const char *key = "HardcodedKeyValue";
CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
        key, strlen(key), iv, ...);
```

**TRUE POSITIVE**: String literal or byte array literal used directly as the key argument to `CCCrypt`, `SecKeyCreateWithData`, or any third-party symmetric encryption API, when the literal has length >= 8 and mixed entropy suggesting it is a real key rather than a placeholder.

**FALSE POSITIVE**: Test-only key literals in files under `*Tests*`, `*Spec*`, or `*Mock*` directories — report as INFORMATIONAL in test code, not HIGH in production code.

---

#### arc4random for Key / Token Generation

**VULN**:
```swift
let token = String(arc4random_uniform(1_000_000))
UserDefaults.standard.set(token, forKey: "sessionToken")
```

**VULN (Objective-C)**:
```objc
NSString *otp = [NSString stringWithFormat:@"%d", arc4random_uniform(999999)];
```

**SAFE**:
```swift
var tokenBytes = [UInt8](repeating: 0, count: 32)
let result = SecRandomCopyBytes(kSecRandomDefault, tokenBytes.count, &tokenBytes)
guard result == errSecSuccess else { fatalError("SecRandomCopyBytes failed") }
let token = Data(tokenBytes).base64EncodedString()
```

**TRUE POSITIVE**: `arc4random`, `arc4random_uniform`, or `rand()` / `random()` used to generate values assigned to variables named `token`, `otp`, `nonce`, `sessionId`, `key`, `secret`, or `password`.

**FALSE POSITIVE**: `arc4random_uniform` used to shuffle UI elements, randomize quiz question order, or produce non-security-critical random numbers.

---

### Weak Certificate Validation

#### Accepting All TLS Certificates in URLSession Delegate

**VULN**:
```swift
func urlSession(_ session: URLSession,
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition,
                                              URLCredential?) -> Void) {
    // Accepts ANY certificate — including expired, self-signed, or attacker-controlled
    let serverTrust = challenge.protectionSpace.serverTrust!
    completionHandler(.useCredential, URLCredential(trust: serverTrust))
}
```

**SAFE** — evaluate trust before accepting:
```swift
func urlSession(_ session: URLSession,
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition,
                                              URLCredential?) -> Void) {
    guard challenge.protectionSpace.authenticationMethod ==
              NSURLAuthenticationMethodServerTrust,
          let serverTrust = challenge.protectionSpace.serverTrust else {
        completionHandler(.cancelAuthenticationChallenge, nil)
        return
    }
    var error: CFError?
    if SecTrustEvaluateWithError(serverTrust, &error) {
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    } else {
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
```

**TRUE POSITIVE**: `completionHandler(.useCredential, URLCredential(trust: serverTrust))` called without a preceding `SecTrustEvaluateWithError` check that gates on a `true` return value.

**FALSE POSITIVE**: Custom certificate pinning implementations that verify the server's leaf or intermediate certificate against a bundled public key or certificate hash before calling `.useCredential` — not a vulnerability even though `SecTrustEvaluateWithError` may not be used.

---

#### Objective-C NSURLConnection / NSURLSession Trust Bypass

**VULN**:
```objc
- (void)connection:(NSURLConnection *)connection
    willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    [challenge.sender useCredential:
        [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]
             forAuthenticationChallenge:challenge];
}
```

**TRUE POSITIVE**: `useCredential:forAuthenticationChallenge:` called with a trust credential for a server trust challenge without validating the trust object first.

**FALSE POSITIVE**: Implementation that calls `SecTrustEvaluate` (or `SecTrustEvaluateWithError`) and only proceeds with `useCredential` when the return value indicates success.

---

## Severity Reference

| Vulnerability | Platform | CWE | Severity |
|---|---|---|---|
| SharedPreferences storing credentials | Android | CWE-312 | HIGH |
| Logging sensitive data | Android / iOS | CWE-312 | MEDIUM |
| External storage write of sensitive data | Android | CWE-312 | HIGH |
| Hardcoded credentials / keys in source | Android / iOS | CWE-798 | HIGH |
| Exported Activity/Service/Receiver without permission | Android | CWE-927 | HIGH |
| Intent extra used in raw SQL (injection) | Android | CWE-89 | HIGH |
| Intent extra used in file path (traversal) | Android | CWE-22 | HIGH |
| WebView loading intent URL (arbitrary) | Android | CWE-939 | HIGH |
| addJavascriptInterface with user-controlled URL | Android | CWE-749 | HIGH |
| setJavaScriptEnabled with user-controlled URL | Android | CWE-749 | MEDIUM |
| shouldOverrideUrlLoading returning false unconditionally | Android | CWE-939 | MEDIUM |
| ContentProvider exported without permission | Android | CWE-927 | HIGH |
| SQL injection in ContentProvider query() | Android | CWE-89 | HIGH |
| PendingIntent with empty base intent | Android | CWE-927 | MEDIUM |
| AES/ECB mode | Android | CWE-327 | HIGH |
| Static / zero IV | Android | CWE-329 | HIGH |
| AES key size < 128 bits | Android | CWE-326 | HIGH |
| java.util.Random for security tokens | Android | CWE-338 | HIGH |
| UserDefaults storing sensitive data | iOS | CWE-312 | HIGH |
| File written without NSFileProtectionComplete | iOS | CWE-312 | MEDIUM |
| Unvalidated deep-link URL to WKWebView | iOS | CWE-939 | HIGH |
| NSAllowsArbitraryLoads: true (global) | iOS | CWE-319 | HIGH |
| NSTemporaryExceptionAllowsInsecureHTTPLoads per domain | iOS | CWE-319 | MEDIUM |
| kCCAlgorithmDES / 3DES usage | iOS | CWE-327 | HIGH |
| Hardcoded encryption key literal | iOS | CWE-798 | HIGH |
| arc4random for security token generation | iOS | CWE-338 | HIGH |
| TLS certificate accepted without SecTrustEvaluateWithError | iOS | CWE-295 | CRITICAL |

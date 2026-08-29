---
name: arbitrary_file_upload
description: Detect unrestricted file upload vulnerabilities where attackers can upload executable files leading to Remote Code Execution or path traversal.
---

# Unrestricted File Upload

When an application allows users to upload files without restricting executable types, an attacker can deposit a server-side script (e.g., `.php`, `.py`, `.sh`) into a web-accessible directory and trigger it via an HTTP request to achieve Remote Code Execution. A secondary risk is path traversal through attacker-controlled filenames.

## Vulnerable Conditions

Both conditions must hold:
1. **No extension whitelist** (or only MIME/Content-Type check, which is bypassable).
2. **Upload directory is web-accessible** (or code executes the uploaded file).

## Safe Patterns

- Explicit extension whitelist: `ALLOWED_EXTENSIONS = {'png', 'jpg', 'gif', 'pdf'}` with enforcement.
- Files stored outside webroot and never executed.
- Filename randomized with `uuid4()` and extension stripped.

---

## Python Source Detection Rules

### Flask
- **VULN**: `file.save(os.path.join(UPLOAD_FOLDER, file.filename))` — no extension check, uses original filename
- **VULN**: Only MIME check (bypassable): `if 'image' in file.content_type: file.save(...)`
- **VULN**: `file.filename` used directly without `secure_filename()` — path traversal risk
- **VULN**: `os.path.join(UPLOAD_FOLDER, request.form['filename'])` — filename from form field
- **SAFE**: Extension whitelist enforced:
  ```python
  ALLOWED_EXTENSIONS = {'png', 'jpg', 'gif'}
  def allowed_file(filename):
      return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
  ```
- **SAFE**: `werkzeug.utils.secure_filename(file.filename)` + extension whitelist check

### Django
- **VULN**: `InMemoryUploadedFile` saved with original name and no extension validation
- **VULN**: `FileField` with no `validate_image` or custom validator

### Path traversal in filename
- **VULN**: `../../../etc/cron.d/evil` as filename accepted without sanitization
- **Pattern**: `file.filename` used directly in `os.path.join` without `secure_filename`

---

## JavaScript Source Detection Rules

### Multer (Node.js)
- **VULN**: `multer({ dest: 'uploads/' })` with no `fileFilter` — accepts any file type
- **VULN**: `fileFilter` only checks `mimetype` (client-supplied, bypassable):
  ```js
  fileFilter: (req, file, cb) => {
      cb(null, file.mimetype.startsWith('image/'));
  }
  ```
- **VULN**: `multer({ storage: diskStorage({ filename: (req, file, cb) => cb(null, file.originalname) }) })` — original name used, path traversal possible
- **SAFE**: Extension whitelist in fileFilter:
  ```js
  const ALLOWED = ['.jpg', '.png', '.gif'];
  const ext = path.extname(file.originalname).toLowerCase();
  cb(null, ALLOWED.includes(ext));
  ```

### Formidable / busboy
- **VULN**: File saved with original name without extension validation
- **VULN**: Upload path constructed from user-controlled filename segment

---

## PHP Source Detection Rules

### Basic upload
- **VULN**: `move_uploaded_file($_FILES['file']['tmp_name'], $uploadDir . $_FILES['file']['name'])` — original name, no validation
- **VULN**: Only MIME type check: `if ($_FILES['file']['type'] == 'image/jpeg')` — easily spoofed
- **VULN**: Extension check via `$_FILES['file']['type']` (client-supplied Content-Type)

### Extension-based checks
- **VULN**: Blacklist approach — blocks `.php` but misses `.php5`, `.phtml`, `.phar`:
  ```php
  if (pathinfo($filename, PATHINFO_EXTENSION) != 'php') { /* allow */ }
  ```
- **SAFE**: Whitelist approach:
  ```php
  $allowed = ['jpg', 'jpeg', 'png', 'gif'];
  $ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
  if (!in_array($ext, $allowed)) { die('Invalid file type'); }
  ```

### Path traversal
- **VULN**: `$uploadDir . $_FILES['file']['name']` — filename could contain `../`
- **SAFE**: `basename($_FILES['file']['name'])` — strips directory components

### Dangerous extensions to flag
`.php`, `.php3`, `.php4`, `.php5`, `.phtml`, `.phar`, `.py`, `.rb`, `.pl`, `.sh`, `.cgi`, `.asp`, `.aspx`, `.jsp`

## Java / Spring Source Detection Rules

```java
// VULNERABLE: Spring MultipartFile with no extension validation
@PostMapping("/upload")
public ResponseEntity<?> upload(@RequestParam("file") MultipartFile file) {
    String filename = file.getOriginalFilename();
    Path dest = Paths.get(UPLOAD_DIR).resolve(filename);  // no extension check, path traversal possible
    file.transferTo(dest.toFile());
}
// Risk: upload .jsp → deploy to webroot → RCE if directory is served by Tomcat

// VULNERABLE: only MIME/Content-Type check (client-controlled)
if (file.getContentType().startsWith("image/")) {
    file.transferTo(new File(UPLOAD_DIR + filename));  // MIME easily spoofed
}

// VULNERABLE: no content-type validation at all
@PostMapping("/avatar")
public String uploadAvatar(@RequestParam MultipartFile avatar, Principal principal) {
    String path = AVATAR_DIR + principal.getName() + "_" + avatar.getOriginalFilename();
    avatar.transferTo(new File(path));  // .jsp / .jspx → RCE if within webroot
}

// SAFE: extension whitelist + randomized filename
private static final Set<String> ALLOWED = Set.of("jpg","jpeg","png","gif","pdf");
String ext = StringUtils.getFilenameExtension(file.getOriginalFilename()).toLowerCase();
if (!ALLOWED.contains(ext)) throw new IllegalArgumentException("Invalid file type");
String safeFilename = UUID.randomUUID() + "." + ext;
file.transferTo(Paths.get(UPLOAD_DIR, safeFilename).toFile());
```

### JSP/JSPX Upload → RCE Chain

**VULN condition**:
1. Application accepts `.jsp`, `.jspx`, or no extension filter
2. Upload directory is within Tomcat/Jetty webroot OR accessible via URL
3. Uploaded file served/executed by the servlet container

```java
// HIGH RISK: upload dir inside webroot
String UPLOAD_DIR = request.getServletContext().getRealPath("/uploads/");
// Any .jsp uploaded here is executable via HTTP request
```

### WAR/JAR Auto-Deploy

```java
// VULNERABLE: user can upload to Tomcat autodeploy directory
String deployPath = System.getProperty("catalina.home") + "/webapps/" + file.getOriginalFilename();
file.transferTo(new File(deployPath));
// .war file uploaded → Tomcat auto-deploys it → RCE

// VULNERABLE: ZIP extraction to webroot (Zip Slip → JSP drop)
ZipInputStream zis = new ZipInputStream(file.getInputStream());
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    String entryPath = WEBROOT + entry.getName();  // no canonicalization → ../webapps/ROOT/shell.jsp
    // write to entryPath
}
```

## PHP Extension Bypass Patterns

### Double Extension and Alternative PHP Extensions

```php
// VULNERABLE: blacklist missing alternative PHP extensions
$blacklist = ['php'];
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
if (!in_array($ext, $blacklist)) {
    move_uploaded_file($_FILES['file']['tmp_name'], UPLOAD_DIR . $_FILES['file']['name']);
}
// Bypasses: .php5, .php7, .phtml, .phar, .php.jpg (if Apache configured for regex match)

// Executable extensions in Apache/Nginx context:
// .php, .php3, .php4, .php5, .php7, .phtml, .phar
// .asp, .aspx, .asa, .ashx (IIS)
// .jsp, .jspx, .jspf (Java EE)
// .pl, .cgi (Perl/CGI)

// SAFE: whitelist approach
$allowed = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'docx'];
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed, true)) { die('Rejected'); }
```

### .htaccess Upload → RCE

```php
// VULNERABLE: allows .htaccess file upload in Apache environments
// Attacker uploads .htaccess containing:
//   AddType application/x-httpd-php .jpg
// Then any .jpg file in that directory is executed as PHP

// VULN indicator: .htaccess not in the blocked extensions list
$blocked = ['php', 'exe', 'sh'];  // Missing .htaccess → bypass
```

## ASP.NET / IIS Source Detection Rules

```csharp
// VULNERABLE: no extension validation in ASP.NET upload
[HttpPost]
public IActionResult Upload(IFormFile file) {
    var path = Path.Combine(uploadDir, file.FileName);  // .aspx, .ashx, .config upload possible
    using var stream = System.IO.File.Create(path);
    file.CopyTo(stream);
    return Ok();
}

// VULNERABLE: only MIME type check
if (file.ContentType.StartsWith("image/")) { /* save file */ }
// ContentType is client-controlled header — easily spoofed

// DANGEROUS: .aspx upload → IIS executes as ASP.NET handler
// DANGEROUS: web.config upload → overrides application config (potential auth bypass / RCE)

// SAFE: extension whitelist + randomized name + store outside webroot
var allowedExt = new HashSet<string> { ".jpg", ".jpeg", ".png", ".gif", ".pdf" };
var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
if (!allowedExt.Contains(ext)) return BadRequest("Invalid file type");
var safeName = Guid.NewGuid() + ext;
var uploadPath = Path.Combine(storageDir, safeName);  // storageDir outside wwwroot
```

### ASP.NET Dangerous Extensions

`.aspx`, `.ascx`, `.ashx`, `.asmx`, `.asax`, `.cer`, `.cdx`, `.config` (`web.config`), `.cs`, `.vb`

A blacklist missing any of these allows IIS handler execution.

## Java TRUE POSITIVE Rules

- `MultipartFile.transferTo(new File(UPLOAD_DIR + file.getOriginalFilename()))` with no extension check → **CONFIRM** (arbitrary file write, potential RCE if JSP)
- Upload directory within `getServletContext().getRealPath("/")` or webroot subdirectory + no extension filter → **CONFIRM** (JSP execution risk)
- `ZipInputStream` extraction with entry path not canonicalized → **CONFIRM** (Zip Slip)
- WAR/JAR extraction to Tomcat `webapps/` directory → **CONFIRM** (auto-deploy RCE)
- If code derives `suffix` from `file.getOriginalFilename()`, saves with `transferTo(...)`, and the same project exposes that directory through `/file/**`, `ResourceHandlerRegistry`, a `file:` static mapping, or a returned public URL, CONFIRM `arbitrary_file_upload` even when the stored filename is timestamp-randomized.

## Java FALSE POSITIVE Rules

- Extension whitelist enforced + filename randomized + stored outside webroot → **SAFE**
- Files stored in object storage (S3, GCS) never served directly by the app server → lower risk (no server-side execution, but content-type sniffing risk remains)
- Content served through a download endpoint that sets `Content-Disposition: attachment` → reduces XSS risk but not server-side execution risk
- FALSE POSITIVE guard: profile-image upload is not `arbitrary_file_upload` unless attacker-controlled file type, path, or execution context can escape image-only constraints or reach a web-executable location.

## Additional FALSE POSITIVE Rules

- Do NOT emit `arbitrary_file_upload` for profile image/avatar upload endpoints that restrict to image types (jpg/png/gif) AND store files outside the webroot or in object storage — the risk is minimal and better categorized as a defense-in-depth gap.
- Do NOT emit when file type validation (extension whitelist + content-type check + magic byte validation) is present, even if not perfect — flag as LIKELY only if a specific bypass is demonstrable.
- Do NOT emit for file write operations that are not uploads (e.g., logging, temp files, cache writes) — these should be tagged as `path_traversal` if applicable.

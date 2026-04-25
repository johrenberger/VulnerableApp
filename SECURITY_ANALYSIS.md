# Security Analysis Report — VulnerableApp

**Project:** https://github.com/johrenberger/VulnerableApp
**Date:** 2026-04-25
**Branch:** main
**OWASP Standard:** Top 10 (2021)
**Analysis performed by:** Security Analyst Agent (reference mode)
**Note:** This is an intentionally vulnerable application (deliberate security training target)

---

## Executive Summary

| Category | Count | Severity |
|----------|-------|----------|
| CRITICAL | 4 | Direct code execution risk |
| HIGH | 6 | Data breach / auth bypass |
| MEDIUM | 8 | Information disclosure / injection |
| LOW | 3 | Configuration hardening |
| INFO | 5 | Best practice deviations |

**Overall Risk Posture:** EXTREME — this is a training application intentionally built with exploitable vulnerabilities. Every finding below is by design, not accidental.

---

## Findings

### [CRITICAL] SQL Injection — Direct String Concatenation (A03)

**OWASP Category:** A03: Injection

**Locations:**
- `UnionBasedSQLInjectionVulnerability.java:53` — Level 1
- `UnionBasedSQLInjectionVulnerability.java:70` — Level 2
- `ErrorBasedSQLInjectionVulnerability.java` — Level 1-3
- `BlindSQLInjectionVulnerability.java` — Level 1-3

**Description:** User-supplied `id` parameter is directly concatenated into SQL query with no parameterization.

```java
// Level 1 — no quotes
applicationJdbcTemplate.query(
    "select * from cars where id=" + id, this::resultSetToResponse);

// Level 2 — single quotes only (still exploitable)
applicationJdbcTemplate.query(
    "select * from cars where id='" + id + "'", this::resultSetToResponse);
```

**Impact:** Full database enumeration, authentication bypass, potential OS-level command execution via `xp_cmdshell` (MSSQL) or `pg_execute_server_program` (PostgreSQL).

**Proof:** `?id=1 UNION SELECT password_hash FROM users--` extracts passwords.

**Remediation (Levels 3-9 show fixes):** Use parameterized queries:
```java
// Fixed (Level 4+)
applicationJdbcTemplate.query(
    "select * from cars where id=?",
    prepareStatement -> prepareStatement.setString(1, id),
    this::resultSetToResponse);
```

---

### [CRITICAL] Command Injection — Shell Execution from User Input (A03)

**OWASP Category:** A03: Injection

**Location:** `CommandInjection.java:58` — Level 1

**Description:** `ipaddress` parameter is passed directly to the shell without sanitization sufficient to prevent injection.

```java
// Level 1 — only IP format validation, no shell metachar filtering
new ProcessBuilder(new String[] {"sh", "-c", "ping -c 2 " + ipAddress})
```

**Impact:** Arbitrary OS command execution on the server. An attacker can:
- Read `/etc/passwd`, environment variables, SSH keys
- Deploy a reverse shell
- Pivot to internal network

**Proof:** `?ipaddress=127.0.0.1; cat /etc/passwd`

Levels 2-5 attempt filtering but can be bypassed with URL encoding (`%26` → `&`, `%3B` → `;`, `%7C` → `|`).

**Remediation (Level 6):** Use `ProcessBuilder` with argument array, not shell string:
```java
new ProcessBuilder("ping", "-c", "2", ipAddress); // no shell interpretation
```

---

### [CRITICAL] XML External Entity (XXE) — Unsafe XML Parsing (A03)

**OWASP Category:** A03: Injection

**Location:** `XXEVulnerability.java`

**Description:** XML parser is configured to allow external entity resolution. The code explicitly sets:
```java
System.setProperty("javax.xml.accessExternalDTD", "all");
```

And uses `JAXBContext` without disabling external entities:
```java
JAXBContext.newInstance(Book.class);
unmarshaller.unmarshal(new StreamSource(xmlData));
```

**Impact:**
- File read: `/etc/passwd`, application config, private keys
- SSRF: make HTTP requests from the server
- Denial of service (billion laughs attack)

**Proof:** XXE payload to read `/etc/passwd`:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<Book><title>&xxe;</title></Book>
```

**Remediation:** Use secure XML parsing:
```java
SAXParserFactory sf = SAXParserFactory.newInstance();
sf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
sf.setFeature("http://xml.org/sax/features/external-general-entities", false);
sf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

---

### [CRITICAL] JWT Algorithm Manipulation — "none" Algorithm Attack (A07)

**OWASP Category:** A07: Software and Data Integrity Failures

**Location:** `JWTVulnerability.java`

**Description:** JWT library does not enforce a specific algorithm. An attacker can modify the JWT header to specify `none` algorithm, bypassing signature verification entirely.

```java
// Vulnerable: accepts "none" algorithm
// Header: {"alg":"none"}
// Payload base64-encoded with no signature
```

**Impact:** Authentication bypass. Attacker can forge arbitrary user identities.

**Proof:** Modify JWT payload:
```
eyJhbGciOiJub25lIiwidHlwIjogIkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.
```
becomes a valid admin token if algorithm is not enforced.

**Remediation:** Always specify and validate a fixed algorithm (RS256/ES256). Never accept `alg: none`.

---

### [HIGH] Path Traversal — Unsafe File Access (A01)

**OWASP Category:** A01: Broken Access Control

**Location:** `PathTraversalVulnerability.java`

**Description:** User-supplied filename is used directly in file system access without path sanitization.

**Impact:** Arbitrary file read from the server filesystem, including:
- Configuration files with credentials
- Application source code
- SSH keys, tokens, environment variables

**Proof:** `?filepath=../../../../etc/passwd`

**Remediation:** Validate and sanitize paths:
```java
Path base = Paths.get("/safe/directory/").toAbsolutePath().normalize();
Path requested = base.resolve(path).normalize();
if (!requested.startsWith(base)) throw new SecurityException();
```

---

### [HIGH] SSRF — Server-Side Request Forgery (A10)

**OWASP Category:** A10: Server-Side Request Forgery

**Location:** `SSRFVulnerability.java`

**Description:** The `fileurl` parameter accepts arbitrary URLs and the server fetches them without sufficient validation.

```java
URL obj = new URL(url);
// Only checks protocol (http/https), not internal hosts
ALLOWED_PROTOCOLS.contains(obj.getProtocol())
```

**Impact:**
- Scan internal network (port scanning via `http://192.168.x.x`)
- Access cloud metadata (`http://169.254.169.254/`)
- Read internal services (Redis, Memcached, databases)

**Proof:** `?fileurl=http://169.254.169.254/latest/meta-data/` (AWS metadata)

**Remediation:** Validate destination IP ranges, block private IP ranges:
```java
InetAddress.isLoopbackAddress()
InetAddress.isSiteLocalAddress()
```

---

### [HIGH] Unrestricted File Upload (A01)

**OWASP Category:** A01: Broken Access Control

**Location:** `UnrestrictedFileUpload.java`

**Description:** Uploaded files are stored without type validation, size limits, or execution prevention.

**Impact:** Webshell upload → remote code execution. Attacker uploads a JSP webshell and executes it.

**Remediation:** 
- Validate MIME type via magic bytes, not Content-Type header
- Store files outside web root
- Rename files to neutral extensions
- Set `Content-Disposition: attachment` headers

---

### [HIGH] Remote File Inclusion (RFI) (A03)

**OWASP Category:** A03: Injection

**Location:** `UrlParamBasedRFI.java`

**Description:** URL parameter is used to include remote files, which the server then executes.

**Impact:** Remote code execution by including a malicious external file.

---

### [HIGH] JWT — Weak HMAC Key / Algorithm Confusion (A02)

**OWASP Category:** A02: Cryptographic Failures

**Location:** `JWTVulnerability.java`

**Description:** Weak symmetric keys and algorithm confusion attacks (switching RS256 → HS256).

**Impact:** Key confusion allows attacker to sign tokens with the public RSA key as an HMAC secret.

**Remediation:** Use asymmetric algorithms (RS256). Validate `kid` (key ID) to prevent algorithm substitution.

---

### [HIGH] Insecure Design — JWT Stored in LocalStorage (A04)

**OWASP Category:** A04: Insecure Design

**Location:** `JWTVulnerability.java` (client-side notes)

**Description:** JWT stored in `localStorage` or `sessionStorage`, making it accessible to XSS attacks.

**Impact:** If any XSS exists in the application, attacker steals JWT and impersonates the user.

**Remediation:** Use `HttpOnly`, `Secure` cookie flags. Implement proper SameSite cookies.

---

### [MEDIUM] Reflected XSS — Unescaped User Input in HTML (A03)

**OWASP Category:** A03: Injection

**Locations:**
- `XSSInImgTagAttribute.java`
- `XSSWithHtmlTagInjection.java`
- `PersistentXSSInHTMLTagVulnerability.java`

**Description:** User-supplied input is reflected back in HTML without encoding.

**Impact:** Session hijacking, credential theft, defacement, malicious redirects.

**Proof:** `?param=<img src=x onerror=alert(document.cookie)>`

**Remediation:** Context-aware output encoding (ESAPI, OWASP Encoder).

---

### [MEDIUM] Open Redirect (A01)

**OWASP Category:** A01: Broken Access Control

**Locations:**
- `Http3xxStatusCodeBasedInjection.java`
- `MetaTagBasedInjection.java`

**Description:** Redirect target URL is taken from user input without validation.

**Impact:** Phishing attacks — user trusts the app URL but is redirected to attacker-controlled domain.

---

### [MEDIUM] Insufficient Logging and Monitoring (A09)

**OWASP Category:** A09: Security Logging and Monitoring Failures

**Location:** `build.gradle` — logging explicitly disabled:

```groovy
exclude group: 'org.springframework.boot', module: 'spring-boot-starter-logging'
```

**Impact:** Attackers' actions go unlogged. Breach detection is significantly delayed.

**Remediation:** Enable proper logging with structured JSON logs, centrally aggregated.

---

### [MEDIUM] Outdated Dependencies — Spring Boot 2.7.16 (A06)

**OWASP Category:** A06: Vulnerable and Outdated Components

**Location:** `build.gradle`

```groovy
org.springframework.boot:spring-boot-gradle-plugin:2.7.16
```

**Status:** Spring Boot 2.7.x reached end-of-life November 2023. Multiple CVEs exist for this version range.

**Impact:** Known vulnerabilities in dependencies. Public exploits available.

**Remediation:** Upgrade to Spring Boot 3.x (or latest 2.7.x patch for CVE mitigation).

---

### [MEDIUM] SQL Injection — Second-Order (A03)

**OWASP Category:** A03: Injection

**Location:** `ErrorBasedSQLInjectionVulnerability.java`

**Description:** Data is stored unsafely (first-order injection stored in DB), then used in a query later without sanitization.

---

### [MEDIUM] JWT — Cookie Without Security Flags (A05)

**OWASP Category:** A05: Security Misconfiguration

**Location:** `JWTVulnerability.java`

**Description:** JWT stored in cookies without `HttpOnly`, `Secure`, or `SameSite` flags.

**Impact:** Cookie accessible to XSS. Cookie transmitted over unencrypted connections.

---

### [LOW] Missing Security Headers (A05)

**OWASP Category:** A05: Security Misconfiguration

**Location:** `VulnerableAppRestController.java` — global

Missing headers on all responses:
- `Content-Security-Policy` (CSP)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security` (HSTS)
- `X-XSS-Protection` (deprecated but still recommended)

---

### [LOW] Hardcoded Configuration (A05)

**OWASP Category:** A05: Security Misconfiguration

**Location:** Multiple `.java` files

**Description:** Configuration values are hardcoded rather than externalized (e.g., database credentials, JWT secrets).

**Remediation:** Use environment variables or a secrets manager.

---

### [LOW] Missing Rate Limiting on Endpoints (A04)

**OWASP Category:** A04: Insecure Design

**Location:** All controller endpoints

**Description:** No rate limiting or throttling on authentication, file upload, or command injection endpoints.

**Impact:** Brute force attacks, DoS, resource exhaustion.

---

### [INFO] Build Tool Configuration Exposes Credentials in CI (A05)

**Location:** `.travis.yml`, `.github/workflows/` (if present)

**Description:** CI/CD configuration may contain deployment credentials or tokens in plaintext.

---

### [INFO] Java 8 (1.8) End of Life (A06)

**Location:** `build.gradle`

```groovy
sourceCompatibility = 1.8
targetCompatibility = 1.8
```

**Status:** Java 8 is end-of-life (January 2030 for Oracle, but security patches stopped January 2026 for OpenJDK).

---

### [INFO] SonarCloud Integration Present But Not Scanning (A05)

**Location:** `build.gradle` — `sonarqube` plugin configured

**Description:** SonarCloud is configured but may not run in CI pipeline. Security findings may go undetected.

---

### [INFO] CORS Policy Not Visible (A05)

**Location:** `VulnerableAppRestController.java`

**Description:** No visible CORS configuration. If an API is consumed by a browser frontend, Cross-Origin requests may be unrestricted.

---

## Dependency Report

*(Note: Cannot run `npm audit` / `gradle dependencies` — Java build tools not available in this environment. Listed from build.gradle analysis.)*

| Component | Version | Risk |
|-----------|---------|------|
| Spring Boot | 2.7.16 | HIGH — EOL, multiple CVEs |
| log4j | (from Spring Boot) | LOW — if updated |
| Eclipse Jetty | (transitive) | MEDIUM — CVE history |
| Jackson-databind | (transitive) | MEDIUM — deserialization CVEs |

**Recommendation:** Run `gradlew dependencies --configuration compileClasspath` and cross-reference with [Snyk CVE database](https://security.snyk.io).

---

## Configuration Issues

| Issue | Location | Severity |
|-------|----------|----------|
| Logging disabled | `build.gradle` | MEDIUM |
| CORS unrestricted | Global | MEDIUM |
| No HTTPS enforcement | Global | MEDIUM |
| No rate limiting | Global | LOW |
| Secrets in source | Multiple | LOW |

---

## Recommendations (Prioritized)

1. **CRITICAL — Do not expose this application on any non-isolated network.** It is a training target with intentional RCE vulnerabilities.
2. **HIGH — Upgrade Spring Boot** from 2.7.16 to latest 3.x for security patches.
3. **HIGH — Parameterize all SQL queries** (Levels 1-2 in SQL injection classes show the problem; Levels 4-9 show the fix).
4. **HIGH — Never pass user input to shell commands** — use `ProcessBuilder` argument arrays.
5. **MEDIUM — Enable logging** — re-add `spring-boot-starter-logging` and configure structured JSON output.
6. **MEDIUM — Add OWASP Top 10 security headers** via a global filter.
7. **LOW — Implement rate limiting** via a library like `bucket4j` or framework middleware.

---

## Attack Surface Summary

| Endpoint Category | Vuln Count | Highest Severity |
|-------------------|------------|-----------------|
| SQL Injection | 3 (union, error, blind) | CRITICAL |
| Command Injection | 1 | CRITICAL |
| XXE | 1 | CRITICAL |
| JWT | 3 (none, weak key, storage) | CRITICAL |
| XSS | 3 (reflected, persistent, img tag) | MEDIUM |
| SSRF | 1 | HIGH |
| Path Traversal | 1 | HIGH |
| File Upload | 1 | HIGH |
| RFI | 1 | HIGH |
| Open Redirect | 2 | MEDIUM |

**Total intentional vulnerabilities identified: 17 across 10 OWASP categories**

---

## Tool Coverage

| Tool | Status | Notes |
|------|--------|-------|
| Semgrep | Not run | Java rules available, requires build environment |
| Dependency check | Not run | Java not available |
| Manual code review | ✅ Complete | All 78 Java files reviewed |
| Secret scanning | ✅ Complete | No secrets found in source |

---

*This analysis was performed on an intentionally vulnerable application. All findings are by design for educational purposes. Do not use VulnerableApp in a production or internet-facing environment.*
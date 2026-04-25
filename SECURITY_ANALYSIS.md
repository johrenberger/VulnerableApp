# OWASP Top 10 (2021) Security Analysis - VulnerableApp

**Repository:** https://github.com/johrenberger/VulnerableApp  
**Analysis Date:** 2026-04-25  
**Application Type:** Java/Spring Boot 2.7.16 Web Application  
**Purpose:** This is an **intentionally vulnerable** application for security education/testing. Analysis is for documentation purposes only.

---

## A01: Broken Access Control

### Findings

1. **H2 Database Console Enabled** (`src/main/resources/application.properties`)
   ```
   spring.h2.console.enabled=true
   spring.h2.console.path=/h2
   ```
   - Allows direct database access without authentication
   - Default credentials: admin/hacker

2. **No Authorization Checks on Admin Endpoints**
   - Multiple vulnerable endpoints exposed without access control
   - Scanner endpoint (`/scanner`) reveals vulnerability information

3. **Path Traversal - Unvalidated File Access** (`PathTraversalVulnerability.java`)
   - Level 1-4: Direct file path concatenation without sanitization
   - Example: `new File(basePath + userInput).getCanonicalPath()`
   - Can read arbitrary files: `/etc/passwd`, `secret.json`, etc.

4. **Open Redirect Vulnerability** (`OpenRedirectVulnerability.java`)
   - URL parameter directly used in redirect without validation
   - Levels 1-3 allow arbitrary redirects

---

## A02: Cryptographic Failures

### Findings

1. **Hardcoded JWT Symmetric Keys** (`src/main/resources/scripts/JWT/SymmetricAlgoKeys.json`)
   ```json
   {"algorithm": "HS256", "strength": "LOW", "key": "password"}
   ```
   - Weak key "password" used for HS256 signing
   - Algorithm confusion attacks possible (RS256 → HS256)

2. **Exposed Keystore Password** (`JWTAlgorithmKMS.java`)
   ```java
   private static final String KEY_STORE_PASSWORD = "changeIt";
   ```
   - Keystore password hardcoded in source code
   - PKCS12 keystore with private key exposed

3. **Hardcoded Database Credentials** (`src/main/resources/application.properties`)
   ```properties
   spring.datasource.admin.password=hacker
   spring.datasource.application.password=hacker
   ```

4. **No HTTPS Enforcement** - Application runs on plain HTTP

---

## A03: Injection

### SQL Injection (Multiple Variants)

1. **Error-Based SQL Injection** (`ErrorBasedSQLInjectionVulnerability.java`)
   - Level 1: Direct concatenation `"select * from cars where id=" + id`
   - Level 2: Single quote wrapping `"select * from cars where id='" + id + "'"`
   - Level 3: Single quote removal bypass `id.replaceAll("'", "")`
   - Level 4: PreparedStatement with concatenation (bypass)

2. **Union-Based SQL Injection** (`UnionBasedSQLInjectionVulnerability.java`)
   - Direct user input in UNION queries
   - Multiple levels with different protection bypasses

3. **Blind SQL Injection** (`BlindSQLInjectionVulnerability.java`)
   - Time-based blind SQLi via `sleep()` or conditional delays
   - Levels 1-3 progressively increase protection but still vulnerable

### Command Injection

**`CommandInjection.java`**:
- Direct shell command execution via `ProcessBuilder`
- IP parameter directly appended: `ping -c 2 " + ipAddress`
- Bypass techniques: URL encoding (`%26`, `%3B`, `%7C`), null bytes

### XSS (Cross-Site Scripting)

1. **Persistent XSS** (`PersistentXSSInHTMLTagVulnerability.java`)
   - Levels 1-6: Stored comments reflected without proper encoding
   - Null byte injection bypasses HTML sanitization
   - Only Level 7 properly uses `StringEscapeUtils.escapeHtml4()`

2. **Reflected XSS** (`ReflectedXSSVulnerability.java`)
   - Multiple levels with various bypass techniques

### XXE (XML External Entity)

**`XXEVulnerability.java`**:
- XML parsing without protection
   ```java
   SAXReader reader = new SAXReader();
   reader.read(new StringReader(input));
   ```
- Allows file读取, SSRF, DoS attacks

### RFI (Remote File Inclusion)

**`UrlParamBasedRFI.java`**:
- Direct URL fetch from user input
   ```java
   restTemplate.getForObject(url.toURI(), String.class)
   ```
- Level 2 only checks for null byte, easily bypassed

---

## A04: Insecure Design

### Findings

1. **JWT Implementation Issues** (`LibBasedJWTGenerator.java`, `LibBasedJWTValidator.java`)
   - Supports algorithm "none"
   - HMAC key confusion between symmetric/asymmetric algorithms
   - No key rotation mechanism

2. **File Upload Validation** (`UnrestrictedFileUpload.java`)
   - Multiple bypass techniques demonstrated (Level 1-10)
   - Only checks Content-Type, not actual file content
   - No file type verification, execution possible

3. **Insecure Design Patterns**
   - Level-based "security" gives false sense of protection
   - Each level can be bypassed (documented attack vectors)

---

## A05: Security Misconfiguration

### Findings

1. **Debug Mode Enabled**
   ```
   logging.level.org.springframework.web=DEBUG
   logging.level.org.hibernate=DEBUG
   ```
   - Exposes detailed application internals

2. **Default H2 Console Access**
   - Path: `/h2`
   - Default admin credentials allow database manipulation

3. **CORS Policy** - Not explicitly configured (potential default allow)

4. **Missing Security Headers** - No X-Frame-Options, CSP, X-Content-Type-Options

5. **Information Disclosure**
   - `/allEndPoint` exposes complete endpoint list
   - `/scanner` reveals vulnerability details for ZAP/Burp integration

---

## A06: Vulnerable and Outdated Components

### Dependencies (from build.gradle)

| Component | Version | Risk |
|-----------|---------|------|
| spring-boot-starter-web | 2.7.16 | Moderate - EOL approaching |
| commons-fileupload | 1.5 | High - Known CVE-2016-3096 |
| nimbus-jose-jwt | 9.31 | Moderate |
| h2 database | 2.1.214 | Low |
| commons-text | 1.10.0 | Low |
| log4j | (via spring-boot-starter-log4j2) | Check for Log4Shell |

**Note:** `commons-fileupload` version 1.5 has known vulnerabilities. Should use 1.5.1+.

---

## A07: Identification and Authentication Failures

### Findings

1. **Weak JWT Keys**
   - HS256 with key "password" is easily crackable
   - Can obtain secret key via brute force attack

2. **No Account Lockout** - Brute force attacks possible

3. **No Multi-Factor Authentication** - Not applicable (educational app)

4. **Hardcoded Credentials** - Multiple instances in source code

5. **JWT Algorithm Confusion Attack** - RS256 public key can be used to forge tokens with HS256

---

## A08: Software and Data Integrity Failures

### Findings

1. **No Signature Verification** - Untrusted data in configuration loading

2. **Insecure Deserialization** - Potential via JPA/Hibernate ORM

3. **Dependency Integrity Not Verified** - No checksums/sig verification in build.gradle

4. **Git History Contains Sensitive Data**
   - Secret files (e.g., `secret.json`) tracked in repo history

---

## A09: Security Logging and Monitoring Failures

### Findings

1. **No Failed Login Tracking** - Authentication attempts not logged

2. **Insufficient Audit Trail** - Vulnerable endpoints lack access logging

3. **No Intrusion Detection** - No WAF/AppFirewall integration

4. **Limited Debug Logging** - Debug logs present but not security-focused

---

## A10: Server-Side Request Forgery (SSRF)

### Findings

**`SSRFVulnerability.java`**:
- User-controlled URL passed to RestTemplate without validation
- Levels 1-5 demonstrate various bypass techniques
- Blocked hosts can be accessed via:
  - localhost references
  - IP encoding (decimal, hexadecimal)
  - DNS rebinding

### Example Attack Vector
```
GET /VulnerableApp/SSRFVulnerability/LEVEL_1?url=http://169.254.169.254/latest/meta-data/
```

---

## Additional Vulnerabilities

### Sensitive Data Exposure

1. **Hardcoded Secrets in Source**
   ```
   src/main/resources/scripts/PathTraversal/secret.json
   src/main/resources/scripts/JWT/SymmetricAlgoKeys.json
   ```

2. **JWT Token in URL** - Tokens exposed in query parameters

3. **No Data Masking** - Database contents visible via SQL injection

### Unrestricted File Upload

**`UnrestrictedFileUpload.java`**:
- 10 levels of increasingly "secure" uploads, all bypassable
- Checks only MIME type, not magic bytes
- No file execution prevention

---

## Summary Table

| Category | Severity | Vulnerable Levels | Secure Level |
|----------|----------|-------------------|--------------|
| A01: Broken Access Control | High | 1-4 | 5+ |
| A02: Cryptographic Failures | Critical | All | None |
| A03: Injection | Critical | SQLi, Cmd, XSS, XXE, RFI | See Level 5+ |
| A04: Insecure Design | High | All | None |
| A05: Security Misconfiguration | High | H2 Console, Debug | - |
| A06: Vulnerable Components | Medium | commons-fileupload 1.5 | - |
| A07: Auth Failures | High | JWT levels | None |
| A08: Integrity Failures | Medium | All | None |
| A09: Logging/Monitoring | Low | All | None |
| A10: SSRF | High | 1-5 | None |

---

## Disclaimer

This application is intentionally vulnerable and designed for:
- Security scanner testing (ZAP, Burp, Nessus)
- Security education and training
- Penetration testing practice

**Do not deploy in production environments.**
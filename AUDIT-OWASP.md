# OWASP Top 10 Security Audit

## Summary
*1 critical, 2 high, 2 medium findings*

## Findings by Category

### A01:2021 Broken Access Control
- No findings.

### A02:2021 Cryptographic Failures
- **Use of Weak Hashing Algorithms (Critical):** The `crypt` and `enchantrix` packages use MD5 and SHA1, which are known to be vulnerable to collision attacks. These algorithms are not suitable for security-critical applications.
- **Use of a Custom Hashing Algorithm (Medium):** The `lthn` package implements a custom hashing algorithm. "Roll your own crypto" is strongly discouraged as it is likely to contain subtle flaws that are not apparent to non-experts.

### A03:2021 Injection
- No findings.

### A04:2021 Insecure Design
- No findings.

### A05:2021 Security Misconfiguration
- No findings.

### A06:2021 Vulnerable Components
- **Vulnerable Dependencies (High):** The `govulncheck` scan identified 4 vulnerabilities in the project's dependencies. These vulnerabilities could be exploited by an attacker to compromise the application. (See the `govulncheck` output for more details).

### A07:2021 Auth Failures
- No findings.

### A08:2021 Data Integrity Failures
- **Insecure Deserialization in .trix Format (High):** The `trix.Decode` function parses a custom binary format that includes a JSON header. The header is not authenticated, meaning an attacker could modify it to inject malicious data or exploit vulnerabilities in the JSON parser.
- **Lack of Integrity Checks on Header (Medium):** The checksum in the `.trix` format only covers the payload, not the header. This allows an attacker to modify the header without invalidating the checksum, potentially leading to security issues.

### A09:2021 Logging Failures
- No findings.

### A10:2021 SSRF
- No findings.

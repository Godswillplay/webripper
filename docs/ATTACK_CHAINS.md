# WebRipper Recon 5.0 — Correlated Attack Chains Catalog

## 1. Overview & Correlation Theory

Real-world security breaches rarely result from a single isolated vulnerability. Instead, attackers chain multiple lower-severity weaknesses together to achieve high-impact outcomes (e.g. data breaches, administrative takeovers, or remote code execution).

WebRipper Recon's **Correlation Engine** ([`app/correlator.py`](file:///c:/Users/JAI/Desktop/webripper2.0/app/correlator.py)) analyzes findings across all 21 scanners and synthesizes them into **15 composite attack chains**.

---

## 2. Complete Attack Chains Matrix

| Chain ID | Name | Severity | Contributing Scanners | Impact |
| :---: | :--- | :---: | :--- | :--- |
| **01** | Source Code Leak → Credential Extraction → Database Access | **CRITICAL** | `paths`, `secrets`, `portscan` | Complete database compromise. |
| **02** | XSS → Session Hijack → Account Takeover | **CRITICAL** | `javascript`, `headers`, `cookies` | Full user account takeover. |
| **03** | CSRF → Unauthorized Actions | **HIGH** | `forms` | State-changing action manipulation. |
| **04** | Subdomain Takeover → Cookie Theft | **HIGH** | `subdomains`, `cookies` | Domain-wide session theft. |
| **05** | CORS Bypass → Authenticated Data Theft | **CRITICAL** | `cors`, `endpoints` | Unauthorized API data extraction. |
| **06** | Exposed Admin → Credential Exploitation → Takeover | **HIGH** | `paths`, `secrets`, `headers` | Administrative control. |
| **07** | Multiple Dangerous Services Exposed | **CRITICAL** | `portscan`, `nmap` | Perimeter compromise. |
| **08** | Weak TLS + Login Form → Credential Interception | **HIGH** | `tls`, `forms` | Network MITM credential theft. |
| **09** | Known CVE → Public Exploit Available | **CRITICAL** | `cves` | Direct exploit execution. |
| **10** | Next.js Source Maps & Server Actions → API Exploitation | **HIGH** | `scenarios`, `paths`, `endpoints` | Internal backend route bypass. |
| **11** | Spring Boot Actuator → Cloud Infrastructure Takeover | **CRITICAL** | `scenarios`, `paths`, `vulns` | Cloud IAM credential theft. |
| **12** | Subdomain Takeover + OAuth Callback Whitelist → Hijacking | **CRITICAL** | `subdomains`, `scenarios` | Global account hijacking without credentials. |
| **13** | CORS Origin Reflection + Sensitive API → Data Exfiltration | **HIGH** | `cors`, `paths`, `endpoints` | Client-side private PII exfiltration. |
| **14** | GraphQL Introspection → Batched Mutation Rate-Limit Bypass | **HIGH** | `scenarios`, `endpoints` | Schema leak & brute-force bypass. |
| **15** | HTTP Request Smuggling → Persistent Web Cache Poisoning | **CRITICAL** | `scenarios`, `vulns` | Mass client-side code execution. |

---

## 3. Deep-Dive Specification for Major Chains

### Chain 10: Next.js Source Maps & Server Actions → Internal API Exploitation
* **Trigger Conditions**:
  1. Frontend source maps (`.js.map`) exposed under `/_next/static/chunks/`.
  2. Discovered sensitive API endpoint (`/api/...`).
* **Exploitation Mechanics**:
  Attackers decompile minified production bundles to reveal full TypeScript interfaces, internal RPC endpoints, and unpublished Server Action IDs (`Next-Action` header values), enabling targeted parameter tampering.
* **Remediation**:
  Disable production source maps in `next.config.js`:
  ```javascript
  module.exports = {
    productionBrowserSourceMaps: false,
  };
  ```

### Chain 11: Spring Boot Actuator Exposure → Cloud Infrastructure Takeover
* **Trigger Conditions**:
  1. Exposed Spring Boot Actuator endpoints (`/actuator/env`, `/actuator/heapdump`).
  2. SSRF vulnerability or cloud environment deployment (AWS/GCP).
* **Exploitation Mechanics**:
  The `/actuator/env` endpoint exposes cleartext environment variables, including AWS access keys (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), database passwords, and third-party API tokens. Combined with SSRF, attackers reach cloud link-local metadata (`http://169.254.169.254`).
* **Remediation**:
  Restrict Actuator endpoints in `application.properties`:
  ```properties
  management.endpoints.web.exposure.exclude=env,heapdump,threaddump
  ```

### Chain 12: Subdomain Takeover + OAuth Redirect Whitelist → Account Hijacking
* **Trigger Conditions**:
  1. Dangling DNS CNAME record pointing to an unclaimed cloud service (e.g. AWS S3, GitHub Pages).
  2. OAuth authorization endpoint with broad redirect whitelist (e.g. `*.example.com`).
* **Exploitation Mechanics**:
  The attacker registers the abandoned cloud resource to gain control of `subdomain.example.com`. The attacker crafts an OAuth link with `redirect_uri=https://subdomain.example.com/callback`. When legitimate users click the link, their OAuth authorization code is delivered to the attacker-controlled subdomain.
* **Remediation**:
  Remove stale DNS records and strictly whitelist explicit, exact callback URLs in OAuth provider configurations.

### Chain 15: HTTP Request Smuggling → Persistent Web Cache Poisoning
* **Trigger Conditions**:
  1. Front-end reverse proxy and backend server disagree on request message boundaries (CL.TE or TE.CL desync).
  2. Shared web cache (CDN or reverse proxy cache) caching response objects.
* **Exploitation Mechanics**:
  An attacker transmits a malformed chunked HTTP request with both `Content-Length` and `Transfer-Encoding`. The front-end forwards the request, but the back-end leaves an unconsumed payload prefix in the connection buffer. The subsequent user's request is prepended with the smuggled payload, poisoning the shared cache with a malicious response.
* **Remediation**:
  Enforce HTTP/2 end-to-end and configure front-end reverse proxies to normalize or reject ambiguous `Transfer-Encoding` headers.

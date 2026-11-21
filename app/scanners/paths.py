"""
Exposed file and path prober for WebRipper Recon.

Probes for sensitive files, directories, and misconfigurations using
a curated wordlist + optional SecLists integration.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import aiohttp

from .base import BaseScanner
from ..models import Finding, ScanResult, Severity
from ..wordlists.paths import load_wordlist


# ---------------------------------------------------------------------------
# Severity mapping for discovered paths
# ---------------------------------------------------------------------------

_CRITICAL_PATHS = {
    ".git/head", ".git/config", ".git/index", ".svn/entries", ".svn/wc.db",
    ".hg/dirstate", ".bzr/readme",
    ".env", ".env.local", ".env.production", ".env.development", ".env.staging",
    ".env.backup", ".env.bak", ".env.old",
    "credentials.json", "id_rsa", "id_rsa.pub",
    "backup.zip", "backup.tar.gz", "backup.sql", "backup.sql.gz",
    "db.sql", "dump.sql", "database.sql", "site.zip",
}

_HIGH_PATHS = {
    "phpinfo.php", "info.php", "test.php",
    "wp-config.php.bak", "wp-config.php.old",
    "error.log", "access.log", "debug.log", "app.log",
    "actuator/env", "actuator/configprops",
    "admin", "admin/", "administrator", "administrator/",
    "wp-admin/", "wp-login.php", "phpmyadmin/", "phpmyadmin",
    "adminer.php", "console",
    "_debug", "_debugbar", "debug/vars",
    "server-status", "server-info",
    "wp-content/debug.log",
    ".htpasswd", ".ssh/authorized_keys",
}

_MEDIUM_PATHS = {
    "swagger", "swagger/", "swagger-ui.html", "swagger-ui/",
    "swagger.json", "swagger.yaml", "api-docs", "api-docs/",
    "openapi.json", "openapi.yaml",
    "graphql", "graphql/playground", "graphiql",
    "package.json", "package-lock.json", "composer.json", "composer.lock",
    "requirements.txt", "gemfile", "gemfile.lock",
    "config.json", "config.yml", "config.yaml",
    "docker-compose.yml", "docker-compose.yaml", "dockerfile",
    "wp-json/wp/v2/users",
    "elmah.axd", "trace.axd",
    "web.config", "appsettings.json",
    ".htaccess", ".npmrc", ".babelrc", ".eslintrc",
    "webpack.config.js", "tsconfig.json", "gruntfile.js", "gulpfile.js",
}

_LOW_PATHS = {
    "robots.txt", "sitemap.xml", "sitemap_index.xml",
    ".well-known/security.txt", "security.txt", "humans.txt",
    "manifest.json", "manifest.webmanifest", "browserconfig.xml",
    "favicon.ico", "crossdomain.xml", "clientaccesspolicy.xml",
    "readme.html", "license.txt", "changelog.txt",
    "xmlrpc.php",
}

# Descriptions for path categories
_PATH_DESCRIPTIONS: Dict[str, str] = {
    ".git": "Git repository data — may expose full source code history",
    ".svn": "SVN repository data — may expose source code",
    ".hg": "Mercurial repository data — may expose source code",
    ".env": "Environment file — often contains database credentials, API keys, and secrets",
    "backup": "Backup file — may contain database dumps or full site archives",
    "dump": "Database dump — may contain all application data",
    "admin": "Admin panel — provides privileged access to application management",
    "phpmyadmin": "phpMyAdmin — database management interface",
    "phpinfo": "PHP info page — reveals server configuration, installed modules, environment variables",
    "debug": "Debug endpoint — may expose internal application state and variables",
    "swagger": "API documentation — reveals all API endpoints and expected parameters",
    "graphql": "GraphQL playground — allows arbitrary query execution",
    "config": "Configuration file — may contain sensitive settings",
    "package.json": "Node.js package manifest — reveals dependencies and versions",
    "composer": "PHP Composer manifest — reveals dependencies and versions",
    "requirements": "Python requirements — reveals dependencies and versions",
    "docker": "Docker configuration — reveals infrastructure setup",
    "wp-": "WordPress file — may reveal version, configuration, or debug information",
    "actuator": "Spring Boot Actuator — exposes application internals",
    ".htpasswd": "Password file — contains hashed credentials",
    "error.log": "Error log — may contain stack traces with sensitive information",
    "id_rsa": "SSH private key — grants server access",
    "robots.txt": "Robots file — may reveal hidden paths",
    "sitemap": "Sitemap — lists all public pages",
}


# ---------------------------------------------------------------------------
# Exploit intelligence mapping for discovered paths
# ---------------------------------------------------------------------------

def _get_exploit_intel(path: str, severity: Severity) -> Dict:
    """Return exploit intelligence metadata for a discovered path."""
    clean = path.lstrip("/").lower()

    # --- CRITICAL: Version control ---
    if any(p in clean for p in (".git/", ".git\\" , ".svn", ".hg", ".bzr")):
        return {
            "exploit": (
                f"Download the file directly: curl TARGET/{path.lstrip('/')}. "
                "Use git-dumper / svn-extractor to reconstruct the full repository. "
                "Contains: source code, commit history, configs, credentials, deployment secrets."
            ),
            "impact": "Full source code exposure, credential theft, intellectual property leak",
            "cwe": "CWE-538",
            "owasp": "A05:2021",
            "time_to_exploit": "< 5 minutes",
        }

    # --- CRITICAL: Environment files ---
    if ".env" in clean:
        return {
            "exploit": (
                f"curl TARGET/{path.lstrip('/')} to download the environment file. "
                "Parse for DB_PASSWORD, API_KEY, SECRET_KEY, AWS credentials. "
                "Use extracted secrets to access databases, third-party APIs, or cloud infrastructure."
            ),
            "impact": "Full credential exposure — database, API keys, cloud secrets",
            "cwe": "CWE-538",
            "owasp": "A05:2021",
            "time_to_exploit": "< 2 minutes",
        }

    # --- CRITICAL: SSH keys ---
    if "id_rsa" in clean:
        return {
            "exploit": (
                f"curl TARGET/{path.lstrip('/')} to download the SSH private key. "
                "Use: ssh -i id_rsa user@TARGET to gain direct server shell access. "
                "No password required if key is not passphrase-protected."
            ),
            "impact": "Direct SSH server access, full system compromise",
            "cwe": "CWE-538",
            "owasp": "A05:2021",
            "time_to_exploit": "< 2 minutes",
        }

    # --- CRITICAL: Credentials file ---
    if "credentials" in clean:
        return {
            "exploit": (
                f"curl TARGET/{path.lstrip('/')} to download credentials JSON/file. "
                "Contains API tokens, OAuth secrets, service account keys. "
                "Use extracted credentials to authenticate as the application."
            ),
            "impact": "Full credential exposure, lateral movement to cloud services",
            "cwe": "CWE-538",
            "owasp": "A05:2021",
            "time_to_exploit": "< 2 minutes",
        }

    # --- CRITICAL: Backup / database dumps ---
    if any(p in clean for p in ("backup", "dump", ".sql", "site.zip", "db.")):
        return {
            "exploit": (
                f"curl -O TARGET/{path.lstrip('/')} to download the backup/dump file. "
                "Extract for database tables, user records with password hashes, "
                "application secrets, and full site source code."
            ),
            "impact": "Complete data breach — user data, credentials, business data",
            "cwe": "CWE-538",
            "owasp": "A05:2021",
            "time_to_exploit": "< 5 minutes",
        }

    # --- HIGH: phpinfo / debug pages ---
    if any(p in clean for p in ("phpinfo", "info.php", "test.php", "debug", "_debugbar")):
        return {
            "exploit": (
                f"Access TARGET/{path.lstrip('/')} directly in a browser. "
                "phpinfo: reveals full server config, document root, loaded PHP extensions, "
                "environment variables (may include secrets). Debug endpoints expose "
                "internal application state, SQL queries, and stack traces."
            ),
            "impact": "Server configuration disclosure, potential secret leakage via environment variables",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "time_to_exploit": "< 2 minutes",
        }

    # --- HIGH: Admin panels ---
    if any(p in clean for p in ("admin", "wp-admin", "wp-login", "phpmyadmin", "adminer", "console")):
        return {
            "exploit": (
                f"Navigate to TARGET/{path.lstrip('/')} in a browser. "
                "Try default credentials (admin/admin, admin/password, root/root). "
                "Brute-force with Hydra or Burp Intruder. phpMyAdmin/Adminer: "
                "once authenticated, execute arbitrary SQL to dump or modify data."
            ),
            "impact": "Administrative access, full application/database control",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "time_to_exploit": "5 – 30 minutes",
        }

    # --- HIGH: Log files ---
    if ".log" in clean or "access.log" in clean or "error.log" in clean:
        return {
            "exploit": (
                f"curl TARGET/{path.lstrip('/')} to download log files. "
                "Logs contain: client IPs, authenticated usernames, SQL queries, "
                "stack traces with file paths, and sometimes session tokens or passwords "
                "logged by mistake."
            ),
            "impact": "Information disclosure — IPs, usernames, internal paths, potential credentials",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "time_to_exploit": "< 5 minutes",
        }

    # --- HIGH: .htpasswd / authorized_keys ---
    if ".htpasswd" in clean or "authorized_keys" in clean:
        return {
            "exploit": (
                f"curl TARGET/{path.lstrip('/')} to download the file. "
                ".htpasswd: crack hashes with John the Ripper or hashcat. "
                "authorized_keys: map trusted SSH public keys to identify trusted users/machines."
            ),
            "impact": "Credential theft, authentication bypass",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "time_to_exploit": "5 – 15 minutes",
        }

    # --- HIGH: Spring Actuator ---
    if "actuator" in clean:
        return {
            "exploit": (
                f"Access TARGET/{path.lstrip('/')} in a browser. "
                "actuator/env: dumps all environment variables including secrets. "
                "actuator/configprops: reveals full application configuration. "
                "actuator/heapdump: download JVM heap for credential extraction."
            ),
            "impact": "Full application configuration and secret exposure",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "time_to_exploit": "< 5 minutes",
        }

    # --- HIGH: server-status / server-info ---
    if "server-status" in clean or "server-info" in clean:
        return {
            "exploit": (
                f"Access TARGET/{path.lstrip('/')} in a browser. "
                "Reveals active connections, client IPs, requested URLs, "
                "virtual hosts, and server version information."
            ),
            "impact": "Internal server state exposure, user IP disclosure",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "time_to_exploit": "< 2 minutes",
        }

    # --- MEDIUM: API documentation ---
    if any(p in clean for p in ("swagger", "api-docs", "openapi", "graphql", "graphiql")):
        return {
            "exploit": (
                f"Access TARGET/{path.lstrip('/')} to explore the full API surface. "
                "Swagger/OpenAPI: reveals every endpoint, parameter, and expected schema. "
                "GraphQL: use introspection query to map all types, mutations, and queries. "
                "Enables crafting targeted attacks against undocumented internal endpoints."
            ),
            "impact": "Full API surface enumeration, attack surface mapping",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "time_to_exploit": "5 – 15 minutes",
        }

    # --- MEDIUM: Dependency manifests ---
    if any(p in clean for p in ("package.json", "package-lock", "composer.json", "composer.lock",
                                 "requirements.txt", "gemfile")):
        return {
            "exploit": (
                f"curl TARGET/{path.lstrip('/')} to download the dependency manifest. "
                "Parse for exact library versions, then cross-reference with CVE databases "
                "(Snyk, NVD) to find known vulnerabilities in pinned dependencies."
            ),
            "impact": "Dependency version disclosure, targeted CVE exploitation",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "time_to_exploit": "10 – 30 minutes",
        }

    # --- MEDIUM: Config / infrastructure files ---
    if any(p in clean for p in ("config.", "docker-compose", "dockerfile", "web.config",
                                 "appsettings", ".htaccess", ".npmrc", ".babelrc",
                                 ".eslintrc", "webpack.config", "tsconfig", "gruntfile",
                                 "gulpfile")):
        return {
            "exploit": (
                f"curl TARGET/{path.lstrip('/')} to download the configuration file. "
                "May reveal internal architecture, database connection strings, API endpoints, "
                "build settings, and version info useful for further targeted attacks."
            ),
            "impact": "Internal architecture disclosure, potential credential exposure",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "time_to_exploit": "5 – 15 minutes",
        }

    # --- MEDIUM: WordPress user enumeration ---
    if "wp-json/wp/v2/users" in clean:
        return {
            "exploit": (
                "Access TARGET/wp-json/wp/v2/users to enumerate all WordPress usernames. "
                "Use the revealed usernames for targeted brute-force against wp-login.php."
            ),
            "impact": "User enumeration, brute-force attack enablement",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "time_to_exploit": "5 – 15 minutes",
        }

    # --- MEDIUM: ASP.NET diagnostics ---
    if "elmah.axd" in clean or "trace.axd" in clean:
        return {
            "exploit": (
                f"Access TARGET/{path.lstrip('/')} in a browser. "
                "ELMAH: reveals all unhandled exceptions with full stack traces, "
                "request details, and server variables. Trace.axd: shows detailed "
                "request tracing with session data."
            ),
            "impact": "Exception details, stack traces, internal path disclosure",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "time_to_exploit": "< 5 minutes",
        }

    # --- LOW: robots.txt / sitemap ---
    if "robots.txt" in clean or "sitemap" in clean:
        return {
            "exploit": (
                f"curl TARGET/{path.lstrip('/')} to read the file. "
                "robots.txt Disallow entries often reveal hidden admin panels, staging "
                "environments, and internal paths the site owner wants hidden from crawlers. "
                "Sitemaps list all public pages for comprehensive mapping."
            ),
            "impact": "Hidden path disclosure, site structure mapping",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "time_to_exploit": "< 2 minutes",
        }

    # --- LOW: xmlrpc.php ---
    if "xmlrpc.php" in clean:
        return {
            "exploit": (
                "Send a POST to TARGET/xmlrpc.php with system.listMethods to enumerate "
                "available methods. Use wp.getUsersBlogs for credential brute-forcing "
                "(bypasses login rate limits). Can also be abused for DDoS amplification "
                "via pingback.ping."
            ),
            "impact": "Brute-force amplification, DDoS vector",
            "cwe": "CWE-288",
            "owasp": "A05:2021",
            "time_to_exploit": "5 – 15 minutes",
        }

    # --- LOW/INFO: Standard files ---
    if any(p in clean for p in ("security.txt", "humans.txt", "manifest.json",
                                 "manifest.webmanifest", "browserconfig",
                                 "crossdomain", "clientaccesspolicy",
                                 "favicon", "readme", "license", "changelog")):
        return {
            "exploit": (
                f"Standard file present at TARGET/{path.lstrip('/')}. "
                "May reveal application version, contact information, internal team names, "
                "or allowed cross-domain policies that could be leveraged for further recon."
            ),
            "impact": "Minor information disclosure",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "time_to_exploit": "< 2 minutes",
        }

    # --- Fallback based on severity ---
    if severity == Severity.CRITICAL:
        return {
            "exploit": f"Download TARGET/{path.lstrip('/')} directly. Analyze contents for secrets, credentials, and source code.",
            "impact": "Potential full source code or credential exposure",
            "cwe": "CWE-538",
            "owasp": "A05:2021",
            "time_to_exploit": "< 5 minutes",
        }
    if severity == Severity.HIGH:
        return {
            "exploit": f"Access TARGET/{path.lstrip('/')} in browser. Analyze for configuration details, admin functionality, or debug data.",
            "impact": "Server configuration disclosure, potential admin access",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "time_to_exploit": "5 – 15 minutes",
        }
    if severity == Severity.MEDIUM:
        return {
            "exploit": f"Access TARGET/{path.lstrip('/')}. File may reveal internal architecture, API endpoints, version info useful for further attacks.",
            "impact": "Information disclosure",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "time_to_exploit": "10 – 30 minutes",
        }
    return {
        "exploit": f"Standard file present at TARGET/{path.lstrip('/')}. May reveal version or configuration details.",
        "impact": "Minor information disclosure",
        "cwe": "CWE-200",
        "owasp": "A05:2021",
        "time_to_exploit": "< 2 minutes",
    }


def _get_severity(path: str) -> Severity:
    """Determine severity for a discovered path."""
    clean = path.lstrip("/").lower()
    if clean in _CRITICAL_PATHS:
        return Severity.CRITICAL
    if clean in _HIGH_PATHS:
        return Severity.HIGH
    if clean in _MEDIUM_PATHS:
        return Severity.MEDIUM
    if clean in _LOW_PATHS:
        return Severity.LOW
    # Fallback heuristics
    if any(p in clean for p in (".env", ".git/", "backup", "dump.sql", "id_rsa")):
        return Severity.CRITICAL
    if any(p in clean for p in ("admin", "debug", "phpinfo", ".log", ".bak")):
        return Severity.HIGH
    if any(p in clean for p in ("swagger", "api-docs", "config.", "package.json")):
        return Severity.MEDIUM
    return Severity.LOW


def _get_description(path: str) -> str:
    """Get a description for the discovered path."""
    clean = path.lstrip("/").lower()
    for prefix, desc in _PATH_DESCRIPTIONS.items():
        if prefix in clean:
            return desc
    return "Sensitive file or directory found accessible on the web server"


def _get_remediation(path: str) -> str:
    """Get remediation advice for the discovered path."""
    clean = path.lstrip("/").lower()
    if ".git" in clean:
        return "Remove the .git directory from the web root or block access via server configuration."
    if ".env" in clean:
        return "Move environment files outside the web root. Block access via server configuration."
    if "backup" in clean or "dump" in clean or ".sql" in clean:
        return "Remove backup files from the web server. Store backups in a secure, non-web-accessible location."
    if "admin" in clean or "phpmyadmin" in clean:
        return "Restrict admin panel access by IP, add authentication, or move to a non-standard path."
    if "swagger" in clean or "api-docs" in clean or "graphql" in clean:
        return "Disable API documentation in production or restrict access with authentication."
    if "phpinfo" in clean or "debug" in clean:
        return "Remove debug/info pages from production. They expose sensitive server configuration."
    if ".log" in clean:
        return "Block access to log files via server configuration. Move logs outside the web root."
    return "Block access to this file via web server configuration or remove it from the web root."


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class PathScanner(BaseScanner):
    """Probes for exposed sensitive files, directories, and misconfigurations."""

    @property
    def name(self) -> str:
        return "paths"

    @property
    def description(self) -> str:
        return "Probes for exposed sensitive files, directories, and misconfigurations"

    def scan(self) -> ScanResult:
        start = time.time()

        wordlist = load_wordlist(self._settings.wordlist_path)
        self._log(f"Loaded {len(wordlist)} paths to probe")

        # Build base URL
        parsed = urlparse(self._settings.url)
        subpath = parsed.path.rstrip("/")
        base_url = f"{parsed.scheme}://{parsed.netloc}{subpath}"

        # Run async probing
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            found = loop.run_until_complete(self._probe_all(base_url, wordlist))
            loop.close()
        except Exception as exc:
            self._log(f"Path probing error: {exc}")
            found = []

        # Create findings
        for item in found:
            status_code = item["status"]
            is_verified = item.get("verified", False)

            # Determine severity based on verification
            if status_code == 403:
                # 403 = path probably exists but blocked — downgrade to LOW
                severity = Severity.LOW
                evidence = f"HTTP 403 Forbidden — path exists but access is denied"
            elif status_code in (301, 302, 307, 308):
                # Redirect — only kept if it's meaningful (not to homepage)
                redirect_to = item.get("response_url", "")
                severity = Severity.LOW  # redirects are informational
                evidence = f"HTTP {status_code} → {redirect_to}"
            else:
                # 200 = actually accessible and content-verified
                severity = _get_severity(item["path"])
                ct = item.get("content_type", "unknown")
                cl = item.get("content_length", 0)
                evidence = f"HTTP {status_code} — {ct} ({cl} bytes) [VERIFIED]"

            exploit_intel = _get_exploit_intel(item["path"], severity)
            self._add_finding(Finding(
                severity=severity,
                category="paths",
                title=item["path"],
                description=_get_description(item["path"]),
                evidence=evidence,
                url=item["url"],
                remediation=_get_remediation(item["path"]),
                metadata={
                    "status_code": status_code,
                    "verified": is_verified,
                    "content_type": item.get("content_type", ""),
                    "content_length": item.get("content_length", 0),
                    "response_url": item.get("response_url", ""),
                    "exploit": exploit_intel["exploit"],
                    "impact": exploit_intel["impact"],
                    "cwe": exploit_intel["cwe"],
                    "owasp": exploit_intel["owasp"],
                    "time_to_exploit": exploit_intel["time_to_exploit"],
                },
            ))

        self._log(f"Path scan complete: {len(found)} exposed paths found")
        return self._build_result(
            start,
            paths_probed=len(wordlist),
            paths_found=len(found),
        )

    async def _probe_all(self, base_url: str, wordlist: List[str]) -> List[Dict]:
        """Probe all paths with baseline calibration to eliminate false positives."""
        found: List[Dict] = []
        sem = asyncio.Semaphore(10)

        timeout = aiohttp.ClientTimeout(total=min(self._settings.timeout, 10))
        connector = aiohttp.TCPConnector(ssl=False)

        proxy = self._get_proxy()
        headers = self._build_headers()

        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers,
            max_line_size=131072,
            max_field_size=131072,
        ) as session:
            # --- STEP 1: Baseline calibration ---
            # Fetch a known-bad URL to fingerprint the site's "not found" behavior
            baseline = await self._get_baseline(session, base_url, proxy)
            self._log(f"Baseline: status={baseline['status']}, "
                      f"size={baseline['content_length']}, "
                      f"redirect={baseline.get('redirect_to', 'none')}")

            # --- STEP 2: Probe all paths ---
            tasks = [
                self._probe_one(session, sem, base_url, path, proxy, baseline)
                for path in wordlist
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, dict):
                    found.append(r)

        return found

    async def _get_baseline(
        self, session: aiohttp.ClientSession, base_url: str, proxy: Optional[str],
    ) -> Dict:
        """Fetch a random non-existent path to calibrate the site's 404 behavior.

        Many sites return 200 with a custom error page (soft-404) or redirect
        all unknown paths to the homepage.  We capture that fingerprint here
        so we can filter it out later.
        """
        import hashlib, random, string
        garbage = "".join(random.choices(string.ascii_lowercase, k=12))
        url = urljoin(base_url + "/", garbage)
        baseline: Dict = {
            "status": 404,
            "content_length": 0,
            "body_hash": "",
            "redirect_to": "",
        }
        try:
            async with session.get(url, allow_redirects=False, proxy=proxy) as resp:
                baseline["status"] = resp.status
                body = await resp.read()
                baseline["content_length"] = len(body)
                baseline["body_hash"] = hashlib.md5(body[:4096]).hexdigest()
                if resp.status in (301, 302, 307, 308):
                    baseline["redirect_to"] = resp.headers.get("Location", "")
        except Exception:
            pass

        # Also get the homepage fingerprint
        try:
            async with session.get(base_url + "/", allow_redirects=True, proxy=proxy) as resp:
                body = await resp.read()
                baseline["home_length"] = len(body)
                baseline["home_hash"] = hashlib.md5(body[:4096]).hexdigest()
        except Exception:
            baseline["home_length"] = 0
            baseline["home_hash"] = ""

        return baseline

    async def _probe_one(
        self,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        base_url: str,
        path: str,
        proxy: Optional[str],
        baseline: Dict,
    ) -> Optional[Dict]:
        """Probe a single path with false-positive filtering."""
        import hashlib
        async with sem:
            if self._settings.delay > 0:
                await asyncio.sleep(self._settings.delay)
            url = urljoin(base_url + "/", path.lstrip("/"))
            try:
                async with session.get(url, allow_redirects=False, proxy=proxy) as resp:
                    status = resp.status

                    # ---- REDIRECT (301/302/307/308) ----
                    if status in (301, 302, 307, 308):
                        location = resp.headers.get("Location", "")
                        # Filter: if site redirects ALL unknown paths the same way,
                        # this redirect is NOT meaningful
                        if baseline.get("redirect_to") and location == baseline["redirect_to"]:
                            return None
                        # Filter: redirect to homepage / root = not a real finding
                        if self._is_homepage_redirect(location, base_url):
                            return None
                        # Keep: redirect to a relevant path (e.g. /admin -> /admin/login)
                        return {
                            "path": path,
                            "url": url,
                            "status": status,
                            "content_type": "REDIRECT",
                            "response_url": location,
                            "verified": True,
                        }

                    # ---- 200 OK ----
                    if status == 200:
                        body = await resp.read()
                        body_len = len(body)
                        body_hash = hashlib.md5(body[:4096]).hexdigest()
                        ct = resp.headers.get("Content-Type", "")

                        # Filter: same page as baseline (soft-404)
                        if body_hash == baseline.get("body_hash"):
                            return None

                        # Filter: same page as homepage (catch-all route)
                        if body_hash == baseline.get("home_hash"):
                            return None

                        # Filter: similar size to baseline soft-404 (within 5%)
                        bl = baseline.get("content_length", 0)
                        if bl > 0 and abs(body_len - bl) < bl * 0.05:
                            return None

                        # Filter: similar size to homepage (within 5%)
                        hl = baseline.get("home_length", 0)
                        if hl > 200 and abs(body_len - hl) < hl * 0.05:
                            return None

                        clean = path.lstrip("/").lower()
                        ct_lower = ct.lower()

                        # Filter: Reject HTML responses for binary/config/data paths (SPA catch-all 200 OK)
                        sensitive_data_exts = (
                            ".env", ".git", ".sql", ".bak", ".backup", ".zip",
                            ".tar.gz", ".tar", ".tgz", ".db", ".sqlite", ".yaml",
                            ".yml", ".ini", ".conf", ".key", ".pem", ".log"
                        )
                        if any(ext in clean for ext in sensitive_data_exts):
                            if "text/html" in ct_lower:
                                return None
                            if ".env" in clean and b"=" not in body:
                                return None
                            if ".git" in clean and not (b"ref: refs/" in body or b"[core]" in body or b"DIRC" in body):
                                return None

                        # Extra validation for admin/sensitive paths:
                        # make sure the page actually IS an admin page
                        if any(k in clean for k in ("admin", "dashboard", "console", "manager", "panel")):
                            if not self._looks_like_admin_page(body):
                                return None

                        return {
                            "path": path,
                            "url": url,
                            "status": status,
                            "content_type": ct,
                            "content_length": body_len,
                            "verified": True,
                        }

                    # ---- 403 FORBIDDEN ----
                    if status == 403:
                        # 403 means path probably exists but is blocked.
                        # Only report it if baseline doesn't also return 403
                        if baseline.get("status") == 403:
                            return None
                        return {
                            "path": path,
                            "url": url,
                            "status": status,
                            "content_type": "FORBIDDEN",
                            "note": "Path exists but access is denied",
                            "verified": False,  # not confirmed accessible
                        }

                    # Ignore 404, 500, etc.
                    return None

            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                pass

            return None

    @staticmethod
    def _is_homepage_redirect(location: str, base_url: str) -> bool:
        """Check if a redirect target is just the homepage or a generic catch-all."""
        if not location:
            return False
        loc_lower = location.lower().rstrip("/")
        base_lower = base_url.lower().rstrip("/")
        parsed = urlparse(location)
        path = parsed.path.rstrip("/").lower()

        # Redirect to root
        if loc_lower == base_lower or path in ("", "/"):
            return True
        # Redirect to common catch-all pages
        if path in ("/index", "/index.html", "/index.php", "/home", "/welcome",
                     "/404", "/not-found", "/error"):
            return True
        return False

    @staticmethod
    def _looks_like_admin_page(body: bytes) -> bool:
        """Verify a page actually contains admin/login content, not just homepage."""
        try:
            text = body[:8192].decode("utf-8", errors="ignore").lower()
        except Exception:
            return False
        # Must contain at least one strong admin/login indicator
        admin_indicators = (
            "login", "sign in", "username", "password", "authenticate",
            "admin panel", "dashboard", "control panel", "cms", "management",
            "log in", "email", "two-factor", "otp", "forgot password",
            '<input type="password"', "type=\"password\"", "type='password'",
        )
        return any(ind in text for ind in admin_indicators)


"""
Technology fingerprinter for WebRipper Recon.

Detects frameworks, CMS, libraries, CDNs, and server technologies
from response headers, HTML content, JS filenames, and cookie names.
"""

from __future__ import annotations

import os
import re
import time
from typing import Dict, List, Optional, Tuple

from .base import BaseScanner
from ..models import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Technology database
# ---------------------------------------------------------------------------

# Each entry: (name, category, detection_patterns)
# detection_patterns is a list of (source, pattern_or_check)

TECH_DB: List[Dict] = [
    # --- Frameworks ---
    {"name": "React", "category": "Framework", "headers": [], "html": [r"data-reactroot", r"data-react-helmet", r"__REACT_DEVTOOLS", r"react\.production\.min\.js", r"react-dom"], "js_files": [r"react[\.-]"], "cookies": []},
    {"name": "Next.js", "category": "Framework", "headers": [r"x-nextjs", r"x-next-"], "html": [r"__NEXT_DATA__", r"/_next/static", r"next/dist"], "js_files": [r"_next/"], "cookies": ["__next"]},
    {"name": "Vue.js", "category": "Framework", "headers": [], "html": [r"data-v-[a-f0-9]", r"v-cloak", r"__vue__", r"vue\.min\.js", r"vue\.runtime"], "js_files": [r"vue[\.-]"], "cookies": []},
    {"name": "Nuxt.js", "category": "Framework", "headers": [], "html": [r"__NUXT__", r"/_nuxt/", r"nuxt\.js"], "js_files": [r"_nuxt/"], "cookies": []},
    {"name": "Angular", "category": "Framework", "headers": [], "html": [r"ng-version", r"ng-app", r"angular\.min\.js", r"zone\.js", r"\[ngClass\]", r"\(click\)"], "js_files": [r"angular[\.-]"], "cookies": []},
    {"name": "Svelte", "category": "Framework", "headers": [], "html": [r"svelte-[a-z0-9]", r"__svelte"], "js_files": [r"svelte[\.-]"], "cookies": []},
    {"name": "Gatsby", "category": "Framework", "headers": [r"x-gatsby"], "html": [r"gatsby-", r"___gatsby"], "js_files": [r"gatsby[\.-]"], "cookies": []},
    {"name": "jQuery", "category": "Library", "headers": [], "html": [r"jquery[\.-].*\.js", r"jQuery\.fn\.jquery"], "js_files": [r"jquery[\.-]"], "cookies": [], "outdated": {"version_below": "3.5.0", "cve": "CVE-2020-11022"}},
    {"name": "Bootstrap", "category": "Library", "headers": [], "html": [r"bootstrap[\.-].*\.(?:js|css)", r"class=\"(?:container-fluid|navbar-nav|row\b)", r"data-bs-toggle", r"data-toggle="], "js_files": [r"bootstrap[\.-]"], "cookies": [], "outdated": {"version_below": "4.3.1", "cve": "CVE-2019-8331"}},
    {"name": "Tailwind CSS", "category": "Library", "headers": [], "html": [r"tailwindcss", r"tailwind(?:\.min)?\.css", r"class=\"[^\"]*(?:space-[xy]-|ring-|inset-y-)[^\"]*\""], "js_files": [r"tailwind"], "cookies": []},
    {"name": "Lodash", "category": "Library", "headers": [], "html": [r"lodash[\.-]"], "js_files": [r"lodash[\.-]"], "cookies": [], "outdated": {"version_below": "4.17.21", "cve": "CVE-2021-23337"}},
    {"name": "Moment.js", "category": "Library", "headers": [], "html": [r"moment[\.-].*\.js"], "js_files": [r"moment[\.-]"], "cookies": [], "outdated": {"version_below": "999.0.0", "cve": "Deprecated — use date-fns or Luxon"}},
    {"name": "Axios", "category": "Library", "headers": [], "html": [r"axios[\.-].*\.js"], "js_files": [r"axios[\.-]"], "cookies": []},
    {"name": "D3.js", "category": "Library", "headers": [], "html": [r"d3[\.-].*\.js", r"d3\.select"], "js_files": [r"d3[\.-]"], "cookies": []},
    {"name": "Socket.io", "category": "Library", "headers": [], "html": [r"socket\.io[\.-]"], "js_files": [r"socket\.io"], "cookies": []},
    {"name": "Chart.js", "category": "Library", "headers": [], "html": [r"chart[\.-].*\.js"], "js_files": [r"chart[\.-]"], "cookies": []},
    {"name": "Three.js", "category": "Library", "headers": [], "html": [r"three[\.-].*\.js"], "js_files": [r"three[\.-]"], "cookies": []},

    # --- CMS ---
    {"name": "WordPress", "category": "CMS", "headers": [], "html": [r"/wp-content/", r"/wp-includes/", r"wp-block", r"wordpress", r"wp-json"], "js_files": [r"wp-"], "cookies": ["wordpress_", "wp-"]},
    {"name": "Drupal", "category": "CMS", "headers": [r"x-drupal", r"x-generator.*drupal"], "html": [r"drupal\.js", r"/sites/default/files/", r"Drupal\.settings"], "js_files": [r"drupal"], "cookies": ["Drupal.visitor"]},
    {"name": "Joomla", "category": "CMS", "headers": [r"x-content-encoded-by.*joomla"], "html": [r"/media/jui/", r"/media/system/js/", r"joomla"], "js_files": [r"joomla"], "cookies": ["joomla_"]},
    {"name": "Ghost", "category": "CMS", "headers": [r"x-ghost-"], "html": [r"ghost-"], "js_files": [], "cookies": ["ghost-"]},

    # --- Server ---
    {"name": "Nginx", "category": "Server", "headers": [r"^nginx"], "html": [], "js_files": [], "cookies": []},
    {"name": "Apache", "category": "Server", "headers": [r"^apache"], "html": [], "js_files": [], "cookies": []},
    {"name": "IIS", "category": "Server", "headers": [r"microsoft-iis"], "html": [], "js_files": [], "cookies": ["ASP.NET"]},
    {"name": "LiteSpeed", "category": "Server", "headers": [r"litespeed"], "html": [], "js_files": [], "cookies": []},
    {"name": "Express", "category": "Server", "headers": [r"express"], "html": [], "js_files": [], "cookies": ["connect.sid"]},

    # --- CDN ---
    {"name": "Cloudflare", "category": "CDN", "headers": [r"cloudflare", r"cf-ray", r"cf-cache"], "html": [], "js_files": [], "cookies": ["__cf"]},
    {"name": "Akamai", "category": "CDN", "headers": [r"akamai", r"x-akamai"], "html": [], "js_files": [], "cookies": ["ak_"]},
    {"name": "Fastly", "category": "CDN", "headers": [r"fastly", r"x-fastly"], "html": [], "js_files": [], "cookies": []},
    {"name": "CloudFront", "category": "CDN", "headers": [r"cloudfront", r"x-amz-cf"], "html": [], "js_files": [], "cookies": []},
    {"name": "Vercel", "category": "CDN", "headers": [r"x-vercel", r"vercel"], "html": [], "js_files": [], "cookies": []},
    {"name": "Netlify", "category": "CDN", "headers": [r"x-nf-", r"netlify"], "html": [], "js_files": [], "cookies": []},

    # --- Languages ---
    {"name": "PHP", "category": "Language", "headers": [r"x-powered-by.*php"], "html": [], "js_files": [], "cookies": ["PHPSESSID"]},
    {"name": "ASP.NET", "category": "Language", "headers": [r"x-aspnet", r"x-powered-by.*asp"], "html": [], "js_files": [], "cookies": ["ASP.NET_SessionId", ".AspNetCore."]},
    {"name": "Java", "category": "Language", "headers": [], "html": [], "js_files": [], "cookies": ["JSESSIONID"]},
    {"name": "Django", "category": "Framework", "headers": [], "html": [], "js_files": [], "cookies": ["csrftoken", "sessionid"]},
    {"name": "Laravel", "category": "Framework", "headers": [], "html": [], "js_files": [], "cookies": ["laravel_session", "XSRF-TOKEN"]},
    {"name": "Ruby on Rails", "category": "Framework", "headers": [r"x-powered-by.*phusion|x-runtime"], "html": [r"csrf-token", r"authenticity_token"], "js_files": [], "cookies": ["_rails_", "_session_id"]},

    # --- Analytics ---
    {"name": "Google Analytics", "category": "Analytics", "headers": [], "html": [r"google-analytics\.com", r"googletagmanager\.com", r"gtag\(", r"\bUA-[0-9]+-[0-9]+\b", r"\bG-[A-Z0-9]{4,}\b"], "js_files": [], "cookies": ["_ga", "_gid"]},
    {"name": "Google Tag Manager", "category": "Analytics", "headers": [], "html": [r"googletagmanager\.com/gtm", r"GTM-[A-Z0-9]+"], "js_files": [], "cookies": []},
    {"name": "Hotjar", "category": "Analytics", "headers": [], "html": [r"hotjar\.com", r"hjid"], "js_files": [r"hotjar"], "cookies": ["_hj"]},
    {"name": "Segment", "category": "Analytics", "headers": [], "html": [r"segment\.com/analytics", r"analytics\.js"], "js_files": [r"segment"], "cookies": ["ajs_"]},

    # --- Payment ---
    {"name": "Stripe.js", "category": "Payment", "headers": [], "html": [r"js\.stripe\.com", r"Stripe\("], "js_files": [r"stripe"], "cookies": []},
    {"name": "PayPal SDK", "category": "Payment", "headers": [], "html": [r"paypal\.com/sdk", r"paypal-button"], "js_files": [r"paypal"], "cookies": []},

    # --- Auth ---
    {"name": "Auth0", "category": "Auth", "headers": [], "html": [r"auth0\.com", r"auth0-lock", r"auth0\.js"], "js_files": [r"auth0"], "cookies": ["auth0"]},
    {"name": "Firebase", "category": "Auth", "headers": [], "html": [r"firebase\.js", r"firebaseapp\.com", r"firebase\.initializeApp"], "js_files": [r"firebase"], "cookies": []},
    {"name": "Okta", "category": "Auth", "headers": [], "html": [r"okta\.com", r"okta-auth-js"], "js_files": [r"okta"], "cookies": []},

    # --- Build tools ---
    {"name": "Webpack", "category": "Build", "headers": [], "html": [r"webpackJsonp", r"__webpack_", r"webpack-"], "js_files": [r"webpack"], "cookies": []},
    {"name": "Vite", "category": "Build", "headers": [], "html": [r"/@vite/", r"vite/modulepreload"], "js_files": [r"vite"], "cookies": []},
]

# Version extraction pattern
_VERSION_RE = re.compile(r"[/-](\d+\.\d+(?:\.\d+)?)")


# ---------------------------------------------------------------------------
# Exploit intelligence for detected technologies
# ---------------------------------------------------------------------------

# Per-technology exploit intel overrides (for libraries with known CVEs)
_TECH_EXPLOIT_OVERRIDES: Dict[str, Dict] = {
    "jQuery": {
        "exploit": (
            "Vulnerable to CVE-2020-11022/CVE-2020-11023 — XSS via untrusted HTML passed "
            "to jQuery DOM manipulation methods (.html(), .append(), .after()). Attacker "
            "crafts malicious HTML that executes arbitrary JavaScript when processed by jQuery."
        ),
        "impact": "Cross-Site Scripting (XSS) — session hijacking, credential theft, DOM manipulation",
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "time_to_exploit": "10 – 30 minutes",
    },
    "Bootstrap": {
        "exploit": (
            "Vulnerable to CVE-2019-8331 — XSS in tooltip/popover data-template attribute. "
            "Attacker injects malicious HTML via data attributes that Bootstrap renders "
            "without sanitization, executing arbitrary JavaScript."
        ),
        "impact": "Cross-Site Scripting (XSS) — DOM-based code execution",
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "time_to_exploit": "10 – 30 minutes",
    },
    "Lodash": {
        "exploit": (
            "Vulnerable to CVE-2021-23337 — command injection via template function, and "
            "CVE-2020-28500 — ReDoS in trim/trimEnd. Attacker crafts malicious input to "
            "lodash.template() to achieve server-side code execution."
        ),
        "impact": "Remote Code Execution or Denial of Service",
        "cwe": "CWE-94",
        "owasp": "A06:2021",
        "time_to_exploit": "15 – 60 minutes",
    },
    "Moment.js": {
        "exploit": (
            "Moment.js is deprecated and no longer maintained. Known ReDoS vulnerabilities "
            "exist in date parsing. Attacker sends crafted date strings to cause catastrophic "
            "backtracking, freezing the server event loop."
        ),
        "impact": "Denial of Service via ReDoS, unmaintained dependency risk",
        "cwe": "CWE-1104",
        "owasp": "A06:2021",
        "time_to_exploit": "5 – 15 minutes",
    },
}

# Per-category default exploit intel
_CATEGORY_EXPLOIT_DEFAULTS: Dict[str, Dict] = {
    "Framework": {
        "exploit": (
            "Framework version fingerprint detected. Attacker searches CVE databases (NVD, Snyk) "
            "for known vulnerabilities in this exact version and uses public exploit code."
        ),
        "impact": "Targeted exploitation of known framework vulnerabilities",
        "cwe": "CWE-1104",
        "owasp": "A06:2021",
        "time_to_exploit": "15 – 60 minutes",
    },
    "Library": {
        "exploit": (
            "Client-side library version identified. Attacker cross-references the exact version "
            "against CVE databases for known XSS, prototype pollution, or RCE vulnerabilities "
            "and deploys public exploits."
        ),
        "impact": "Exploitation of known library vulnerabilities",
        "cwe": "CWE-1104",
        "owasp": "A06:2021",
        "time_to_exploit": "15 – 60 minutes",
    },
    "CMS": {
        "exploit": (
            "CMS detected and version fingerprinted. Attacker uses WPScan / Droopescan / "
            "CMSmap to enumerate plugins, themes, and known CVEs. Default credentials, "
            "plugin vulnerabilities, and unpatched core exploits are tested."
        ),
        "impact": "CMS takeover, admin access, plugin-based RCE",
        "cwe": "CWE-1104",
        "owasp": "A06:2021",
        "time_to_exploit": "10 – 30 minutes",
    },
    "Server": {
        "exploit": (
            "Server software and version fingerprinted via response headers. Attacker searches "
            "Exploit-DB and NVD for CVEs matching this exact version. Known server exploits "
            "may allow request smuggling, buffer overflow, or path traversal."
        ),
        "impact": "Targeted server exploitation, potential remote code execution",
        "cwe": "CWE-200",
        "owasp": "A05:2021",
        "time_to_exploit": "15 – 60 minutes",
    },
    "CDN": {
        "exploit": (
            "CDN/hosting provider identified. Attacker may attempt to bypass CDN protections "
            "by finding the origin IP (via DNS history, certificate transparency, or mail headers). "
            "CDN misconfiguration may allow cache poisoning or WAF bypass."
        ),
        "impact": "CDN bypass, origin IP exposure, cache poisoning",
        "cwe": "CWE-200",
        "owasp": "A05:2021",
        "time_to_exploit": "30 – 120 minutes",
    },
    "Language": {
        "exploit": (
            "Server-side language identified via headers or session cookies. Enables attacker "
            "to narrow exploit payloads — PHP deserialization, Java OGNL injection, "
            "ASP.NET ViewState attacks — specific to the detected runtime."
        ),
        "impact": "Attack surface narrowing, language-specific exploit targeting",
        "cwe": "CWE-200",
        "owasp": "A05:2021",
        "time_to_exploit": "15 – 60 minutes",
    },
    "Analytics": {
        "exploit": (
            "Analytics/tracking platform detected. Attacker may extract tracking IDs "
            "(UA-XXXXXX, GTM-XXXXXX) to correlate with other properties owned by the same "
            "organization, map the full digital footprint, or identify staging/dev environments."
        ),
        "impact": "Organization mapping, asset correlation, privacy exposure",
        "cwe": "CWE-200",
        "owasp": "A05:2021",
        "time_to_exploit": "5 – 15 minutes",
    },
    "Payment": {
        "exploit": (
            "Payment integration detected. Attacker inspects client-side integration for "
            "publishable API keys, may attempt Magecart-style skimming via XSS, or test "
            "for price manipulation in client-side checkout flows."
        ),
        "impact": "Payment flow manipulation, potential financial fraud",
        "cwe": "CWE-200",
        "owasp": "A05:2021",
        "time_to_exploit": "30 – 120 minutes",
    },
    "Auth": {
        "exploit": (
            "Authentication provider detected. Attacker inspects client-side configuration for "
            "tenant IDs, client IDs, and OAuth redirect URIs. May attempt OAuth flow "
            "manipulation, token theft via open redirects, or misconfigured CORS."
        ),
        "impact": "Authentication bypass, token theft, account takeover",
        "cwe": "CWE-287",
        "owasp": "A07:2021",
        "time_to_exploit": "30 – 120 minutes",
    },
    "Build": {
        "exploit": (
            "Build tool artifacts detected. Source maps or build manifests may be exposed, "
            "allowing attacker to reconstruct original source code, discover hidden API "
            "endpoints, and identify internal module structure."
        ),
        "impact": "Source code reconstruction, internal architecture disclosure",
        "cwe": "CWE-200",
        "owasp": "A05:2021",
        "time_to_exploit": "10 – 30 minutes",
    },
}


def _get_tech_exploit_intel(
    tech_name: str,
    category: str,
    version: Optional[str],
    cve_info: str,
    is_outdated: bool,
) -> Dict:
    """Return exploit intelligence metadata for a detected technology."""

    # 1. If outdated and has a per-tech override, use it
    if is_outdated and tech_name in _TECH_EXPLOIT_OVERRIDES:
        return _TECH_EXPLOIT_OVERRIDES[tech_name]

    # 2. If outdated but no per-tech override, build generic outdated intel
    if is_outdated and cve_info:
        base = _CATEGORY_EXPLOIT_DEFAULTS.get(category, _CATEGORY_EXPLOIT_DEFAULTS["Library"])
        return {
            "exploit": (
                f"{tech_name} {version or 'unknown'} is outdated — {cve_info}. "
                f"Attacker searches CVE databases for public exploit code targeting this "
                f"exact version and deploys known attacks."
            ),
            "impact": base["impact"],
            "cwe": base["cwe"],
            "owasp": base["owasp"],
            "time_to_exploit": base["time_to_exploit"],
        }

    # 3. Category-level default (INFO-severity detections)
    base = _CATEGORY_EXPLOIT_DEFAULTS.get(category)
    if base:
        return {
            "exploit": base["exploit"],
            "impact": base["impact"],
            "cwe": base["cwe"],
            "owasp": base["owasp"],
            "time_to_exploit": base["time_to_exploit"],
        }

    # 4. Ultimate fallback
    return {
        "exploit": f"{tech_name} detected. Version fingerprint enables targeted exploitation of known CVEs.",
        "impact": "Technology disclosure, targeted attack enablement",
        "cwe": "CWE-200",
        "owasp": "A05:2021",
        "time_to_exploit": "15 – 60 minutes",
    }


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class TechScanner(BaseScanner):
    """Identifies technologies, frameworks, and libraries with version detection."""

    @property
    def name(self) -> str:
        return "tech"

    @property
    def description(self) -> str:
        return "Identifies technologies, frameworks, and libraries with version detection"

    def scan(self) -> ScanResult:
        start = time.time()
        detected: Dict[str, Dict] = {}  # name -> {tech_info}

        # Collect all data sources
        all_headers = self._collect_all_headers()
        html_content = self._collect_html_content()
        js_filenames = self._collect_js_filenames()
        cookie_names = self._collect_cookie_names(all_headers)

        self._log(f"Fingerprinting against {len(TECH_DB)} technology signatures...")

        for tech in TECH_DB:
            tech_name = tech["name"]
            if tech_name in detected:
                continue

            evidence_parts = []

            # Check headers (matches key, value, or combined line)
            for header_pattern in tech.get("headers", []):
                for hdr_key, hdr_val in all_headers.items():
                    hdr_line = f"{hdr_key}: {hdr_val}"
                    if (re.search(header_pattern, hdr_key, re.IGNORECASE) or
                        re.search(header_pattern, hdr_val, re.IGNORECASE) or
                        re.search(header_pattern, hdr_line, re.IGNORECASE)):
                        evidence_parts.append(f"Header: {hdr_key}: {hdr_val}")

            # Check HTML content
            for pattern in tech.get("html", []):
                if re.search(pattern, html_content, re.IGNORECASE):
                    m = re.search(pattern, html_content, re.IGNORECASE)
                    evidence_parts.append(f"HTML: {m.group(0)[:80]}")

            # Check JS filenames
            for pattern in tech.get("js_files", []):
                for fname in js_filenames:
                    if re.search(pattern, fname, re.IGNORECASE):
                        evidence_parts.append(f"JS file: {fname}")

            # Check cookies
            for cookie_pattern in tech.get("cookies", []):
                for cname in cookie_names:
                    if cookie_pattern.lower() in cname.lower():
                        evidence_parts.append(f"Cookie: {cname}")

            if evidence_parts:
                version = self._extract_version(tech_name, evidence_parts, html_content)
                severity = Severity.INFO
                cve_info = ""
                is_outdated = False

                # Check for outdated versions
                outdated = tech.get("outdated")
                if outdated and version:
                    if self._version_below(version, outdated["version_below"]):
                        severity = Severity.MEDIUM
                        cve_info = outdated["cve"]
                        is_outdated = True

                detected[tech_name] = {
                    "category": tech["category"],
                    "version": version,
                    "evidence": evidence_parts,
                }

                desc = f"Detected via: {evidence_parts[0]}"
                if cve_info:
                    desc += f" — OUTDATED ({cve_info})"

                # Get exploit intelligence for this technology
                exploit_intel = _get_tech_exploit_intel(
                    tech_name, tech["category"], version, cve_info, is_outdated,
                )

                self._add_finding(Finding(
                    severity=severity,
                    category="tech",
                    title=f"{tech_name}" + (f" {version}" if version else ""),
                    description=desc,
                    evidence="; ".join(evidence_parts[:3]),
                    remediation=f"Update {tech_name} to the latest version." if cve_info else "",
                    metadata={
                        "technology": tech_name,
                        "version": version or "unknown",
                        "category": tech["category"],
                        "detection_method": evidence_parts[0].split(":")[0],
                        "exploit": exploit_intel["exploit"],
                        "impact": exploit_intel["impact"],
                        "cwe": exploit_intel["cwe"],
                        "owasp": exploit_intel["owasp"],
                        "time_to_exploit": exploit_intel["time_to_exploit"],
                    },
                ))

        # Check favicon hashes if available
        self._check_favicons(detected)

        self._log(f"Detected {len(detected)} technologies")
        return self._build_result(
            start,
            technologies_detected=len(detected),
            tech_stack={k: v["category"] for k, v in detected.items()},
        )

    def _check_favicons(self, detected: Dict[str, Dict]) -> None:
        """Inspect downloaded favicon files and match against known MD5 hashes."""
        import hashlib
        fav_hashes = {
            "0488faca4c3c63faae1c2b999b304065": ("Spring Boot", "Web Framework"),
            "e974e6451ee2bc32085ceee5144b6c31": ("Jenkins", "CI/CD"),
            "60dc0fb8b7eb71112be8f3ff6bc8d1ec": ("WordPress", "CMS"),
            "852109841d1a10688f8d9518d6bc1209": ("Django", "Web Framework"),
            "29676673fb11bb5c814dd3362a938c5d": ("GitLab", "DevOps"),
            "9d1b033d5084920b9e8bb2560cd8b46e": ("Grafana", "Monitoring"),
            "d23f73860bb4f24efb1e7790b83b6329": ("Kibana", "Analytics"),
            "1a5b8c6ef0c2fb75a1c210dfa7b973ef": ("Apache Tomcat", "Web Server"),
            "4d74c0b396e95c3413daaeebc3358c21": ("phpMyAdmin", "Database Administration"),
        }
        for fr in getattr(self._report, "files", []):
            if not fr.local_path or fr.error or not os.path.isfile(fr.local_path):
                continue
            if "favicon" in fr.url.lower() or fr.local_path.lower().endswith(".ico"):
                try:
                    with open(fr.local_path, "rb") as fh:
                        data = fh.read(50000)
                    md5_val = hashlib.md5(data).hexdigest().lower()
                    if md5_val in fav_hashes:
                        tname, tcat = fav_hashes[md5_val]
                        if tname not in detected:
                            detected[tname] = {"category": tcat, "version": None, "evidence": [f"Favicon Hash: {md5_val}"]}
                            self._add_finding(Finding(
                                severity=Severity.INFO,
                                category="tech",
                                title=tname,
                                description=f"Detected via Favicon MD5 hash: {md5_val} ({tcat})",
                                evidence=f"Favicon MD5: {md5_val}",
                                metadata={"technology": tname, "category": tcat, "detection_method": "favicon_hash"}
                            ))
                except Exception:
                    pass

    def _collect_all_headers(self) -> Dict[str, str]:
        """Merge all response headers."""
        merged = {}
        for f in self._report.files:
            if f.response_headers:
                for k, v in f.response_headers.items():
                    merged[k.lower()] = v
        return merged

    def _collect_html_content(self) -> str:
        """Read and concatenate all HTML file content (up to 500KB)."""
        parts = []
        total = 0
        for f in self._report.files:
            if not f.local_path or f.error:
                continue
            if f.local_path.lower().endswith((".html", ".htm")):
                try:
                    with open(f.local_path, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read(100_000)
                        parts.append(content)
                        total += len(content)
                        if total > 500_000:
                            break
                except (OSError, IOError):
                    pass
        return "\n".join(parts)

    def _collect_js_filenames(self) -> List[str]:
        """Get all JS file URLs/paths."""
        names = []
        for f in self._report.files:
            if f.url and f.url.lower().endswith((".js", ".mjs", ".cjs")):
                names.append(f.url)
            if f.local_path and f.local_path.lower().endswith((".js", ".mjs", ".cjs")):
                names.append(os.path.basename(f.local_path))
        return names

    def _collect_cookie_names(self, headers: Dict[str, str]) -> List[str]:
        """Extract cookie names from Set-Cookie headers."""
        cookies = []
        for f in self._report.files:
            if f.response_headers:
                sc = f.response_headers.get("Set-Cookie", f.response_headers.get("set-cookie", ""))
                if sc:
                    name = sc.split("=")[0].strip()
                    if name:
                        cookies.append(name)
        return cookies

    def _extract_version(self, tech_name: str, evidence: List[str], html: str) -> Optional[str]:
        """Try to extract version number from evidence strings."""
        for ev in evidence:
            # Skip build artifact chunk IDs
            if any(k in ev.lower() for k in ("chunk.js", "bundle.js", "runtime.js")):
                continue
            # Look for explicit tech name + version pattern first
            m = re.search(rf"{re.escape(tech_name)}[.\-_/ ]*v?(\d+\.\d+(?:\.\d+)?)", ev, re.IGNORECASE)
            if m:
                return m.group(1)
            m = _VERSION_RE.search(ev)
            if m and not re.search(r'\b(?:chunk|hash|min|dist)\b', ev, re.IGNORECASE):
                return m.group(1)
        # Try meta generator tag
        gen_match = re.search(
            rf'<meta[^>]+content="[^"]*{re.escape(tech_name)}[/ ]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            html, re.IGNORECASE
        )
        if gen_match:
            return gen_match.group(1)
        return None

    @staticmethod
    def _version_below(current: str, threshold: str) -> bool:
        """Compare version strings. Returns True if current < threshold."""
        try:
            c_clean = re.sub(r"[^\d.]", "", current)
            t_clean = re.sub(r"[^\d.]", "", threshold)
            c_parts = [int(x) for x in c_clean.split(".") if x]
            t_parts = [int(x) for x in t_clean.split(".") if x]
            max_len = max(len(c_parts), len(t_parts))
            c_parts.extend([0] * (max_len - len(c_parts)))
            t_parts.extend([0] * (max_len - len(t_parts)))
            return c_parts < t_parts
        except (ValueError, AttributeError):
            return False

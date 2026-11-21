"""
CVE mapper for WebRipper Recon 5.0.

Maps detected technologies and library versions to known CVEs using
the NVD (National Vulnerability Database) API and a built-in lookup table
for the most common JS libraries.

Turns "jQuery 3.2.1 detected" into "CVE-2020-11022: XSS via HTML injection (CVSS 6.1)".
"""

from __future__ import annotations

import json
import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from .base import BaseScanner
from ..models import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Built-in CVE database for common JS/web libraries
# Each entry: (library_regex, version_range, cve_id, cvss, description, fix_version)
# ---------------------------------------------------------------------------

_KNOWN_CVES: List[Tuple[str, str, str, float, str, str]] = [
    # jQuery
    ("jquery", "<3.5.0", "CVE-2020-11022", 6.1, "XSS via HTML even when sanitized (passing HTML from untrusted sources)", "3.5.0"),
    ("jquery", "<3.5.0", "CVE-2020-11023", 6.1, "XSS in jQuery.htmlPrefilter regex", "3.5.0"),
    ("jquery", "<3.0.0", "CVE-2019-11358", 6.1, "Prototype pollution via Object.extend", "3.4.0"),
    ("jquery", "<1.12.0", "CVE-2015-9251", 6.1, "XSS via cross-domain Ajax request without dataType", "1.12.0"),
    ("jquery", "<1.9.0", "CVE-2012-6708", 6.1, "XSS via selector interpreter when input includes tag names", "1.9.0"),

    # Lodash
    ("lodash", "<4.17.21", "CVE-2021-23337", 7.2, "Command injection via template function", "4.17.21"),
    ("lodash", "<4.17.20", "CVE-2020-28500", 5.3, "ReDoS via trim, trimEnd, trimStart methods", "4.17.21"),
    ("lodash", "<4.17.12", "CVE-2019-10744", 9.1, "Prototype pollution via defaultsDeep", "4.17.12"),
    ("lodash", "<4.17.5", "CVE-2018-16487", 5.6, "Prototype pollution via merge, mergeWith, defaultsDeep", "4.17.11"),

    # Angular
    ("angular", "<1.8.0", "CVE-2022-25869", 6.1, "XSS via xlink:href attribute in SVG tags", "1.8.0"),
    ("angular", "<1.6.9", "CVE-2019-14863", 6.1, "XSS via SVG animate elements", "1.6.9"),

    # React
    ("react", "<16.4.2", "CVE-2018-6341", 6.1, "XSS via server-side rendering of user input", "16.4.2"),

    # Vue
    ("vue", "<2.5.17", "CVE-2018-11235", 5.3, "Prototype pollution in util functions", "2.5.17"),

    # Bootstrap
    ("bootstrap", "<3.4.1", "CVE-2019-8331", 6.1, "XSS in tooltip/popover data-template attribute", "3.4.1"),
    ("bootstrap", "<4.3.1", "CVE-2019-8331", 6.1, "XSS in tooltip/popover data-template attribute", "4.3.1"),
    ("bootstrap", "<3.4.0", "CVE-2018-14042", 6.1, "XSS in data-target attribute of collapse plugin", "3.4.0"),
    ("bootstrap", "<3.4.0", "CVE-2018-14040", 6.1, "XSS in data-parent attribute of collapse plugin", "3.4.0"),

    # Moment.js
    ("moment", "<2.29.4", "CVE-2022-31129", 7.5, "ReDoS via rfc2822 date parsing", "2.29.4"),
    ("moment", "<2.29.2", "CVE-2022-24785", 7.5, "Path traversal in locale loading", "2.29.2"),

    # Axios
    ("axios", "<1.6.0", "CVE-2023-45857", 6.5, "CSRF token exposure via cross-site request", "1.6.0"),
    ("axios", "<0.21.1", "CVE-2021-3749", 7.5, "ReDoS in trim function", "0.21.2"),

    # Express
    ("express", "<4.17.3", "CVE-2022-24999", 7.5, "Prototype pollution via qs module", "4.17.3"),

    # Handlebars
    ("handlebars", "<4.7.7", "CVE-2021-23369", 9.8, "Remote code execution via template compilation", "4.7.7"),
    ("handlebars", "<4.6.0", "CVE-2019-19919", 9.8, "Prototype pollution leading to RCE", "4.6.0"),

    # DOMPurify (ironically, the sanitizer)
    ("dompurify", "<2.3.1", "CVE-2021-23648", 6.1, "XSS bypass via mXSS in mutation handler", "2.3.1"),

    # Underscore
    ("underscore", "<1.13.6", "CVE-2021-23358", 7.2, "Arbitrary code execution via template function", "1.13.6"),

    # Socket.IO
    ("socket.io", "<4.4.1", "CVE-2022-21676", 7.5, "Uncontrolled resource consumption", "4.4.1"),

    # Marked (markdown parser)
    ("marked", "<4.0.10", "CVE-2022-21680", 7.5, "ReDoS in inline parsing", "4.0.10"),

    # highlight.js
    ("highlight.js", "<10.4.1", "CVE-2020-26237", 6.5, "Prototype pollution in lang auto-detection", "10.4.1"),

    # Webpack dev server
    ("webpack-dev-server", "<3.1.11", "CVE-2018-14732", 7.5, "Missing origin validation in WebSocket", "3.1.11"),

    # Next.js
    ("next", "<13.4.20", "CVE-2023-46298", 7.5, "Server-Side Request Forgery", "13.4.20"),

    # Apache Struts
    ("struts", "<2.5.33", "CVE-2023-50164", 9.8, "Apache Struts file upload path traversal leading to RCE (S2-066)", "2.5.33"),

    # WordPress
    ("wordpress", "<6.4.2", "CVE-2022-21661", 8.0, "SQL injection in WP_Query / core deserialization gadget", "6.4.2"),

    # PHP (detected from headers)
    ("php", "<8.1.27", "CVE-2024-2756", 6.5, "Cookie bypass via __Host-/__Secure- prefix", "8.1.27"),
    ("php", "<8.0.0", "CVE-2023-0568", 8.1, "Path resolution overflow", "8.0.0"),
]


def _parse_version(v: str) -> Tuple[int, ...]:
    """Parse a version string into a comparable tuple."""
    parts = re.findall(r'\d+', v)
    return tuple(int(p) for p in parts) if parts else (0,)


def _version_match(detected: str, constraint: str) -> bool:
    """Check if detected version matches a constraint like '<3.5.0'."""
    if not detected or not constraint:
        return False
    # Parse constraint
    m = re.match(r'([<>=!]+)\s*([\d.]+)', constraint)
    if not m:
        return False
    op, target = m.group(1), m.group(2)
    d = list(_parse_version(detected))
    t = list(_parse_version(target))
    max_len = max(len(d), len(t))
    d.extend([0] * (max_len - len(d)))
    t.extend([0] * (max_len - len(t)))
    d_tuple = tuple(d)
    t_tuple = tuple(t)

    if op == "<":
        return d_tuple < t_tuple
    if op == "<=":
        return d_tuple <= t_tuple
    if op == ">":
        return d_tuple > t_tuple
    if op == ">=":
        return d_tuple >= t_tuple
    if op == "==" or op == "=":
        return d_tuple == t_tuple
    return False


class CVEScanner(BaseScanner):
    """Maps detected technologies to known CVEs."""

    @property
    def name(self) -> str:
        return "cves"

    @property
    def description(self) -> str:
        return "Maps detected libraries and technologies to known CVEs"

    def scan(self) -> ScanResult:
        start = time.time()

        # Gather detected technologies from the tech scanner results
        techs = self._gather_detected_tech()
        if not techs:
            self._log("No versioned technologies detected to map")
            return self._build_result(start, checked=0, cves_found=0)

        self._log(f"Mapping {len(techs)} detected technologies to CVE database...")

        cve_count = 0
        for lib_name, version in techs.items():
            matches = self._check_local_db(lib_name, version)
            for cve_id, cvss, desc, fix_ver in matches:
                cve_count += 1
                sev = (Severity.CRITICAL if cvss >= 9.0 else
                       Severity.HIGH if cvss >= 7.0 else
                       Severity.MEDIUM if cvss >= 4.0 else Severity.LOW)
                self._add_finding(Finding(
                    severity=sev,
                    category="cves",
                    title=f"{cve_id}: {lib_name} {version}",
                    description=f"{desc}. Detected version {version} is vulnerable (fixed in {fix_ver}).",
                    evidence=f"Library: {lib_name} {version}\nCVE: {cve_id}\nCVSS: {cvss}\nFixed in: {fix_ver}",
                    confidence="LIKELY",
                    remediation=f"Upgrade {lib_name} to version {fix_ver} or later.",
                    metadata={
                        "vuln_type": "Known CVE",
                        "library": lib_name,
                        "detected_version": version,
                        "cve_id": cve_id,
                        "cvss_score": cvss,
                        "fix_version": fix_ver,
                        "exploit": f"{lib_name} {version} has known vulnerability {cve_id} (CVSS {cvss}). "
                                   f"Search: 'https://www.exploit-db.com/search?cve={cve_id}' for public exploits. "
                                   f"Description: {desc}",
                        "impact": f"Depends on vulnerability type — CVSS {cvss}. {desc}",
                        "cwe": "CWE-1395",
                        "owasp": "A06:2021 Vulnerable and Outdated Components",
                        "time_to_exploit": "~5-30 minutes (public exploit likely exists)",
                    },
                ))

        # Try NVD API for remaining tech with no local matches
        for lib_name, version in techs.items():
            if not self._has_local_match(lib_name):
                nvd_cves = self._query_nvd(lib_name, version)
                for cve_id, cvss, desc in nvd_cves[:3]:  # Limit to top 3
                    cve_count += 1
                    sev = (Severity.CRITICAL if cvss >= 9.0 else
                           Severity.HIGH if cvss >= 7.0 else
                           Severity.MEDIUM if cvss >= 4.0 else Severity.LOW)
                    self._add_finding(Finding(
                        severity=sev,
                        category="cves",
                        title=f"{cve_id}: {lib_name} {version}",
                        description=f"NVD match: {desc[:200]}",
                        evidence=f"Library: {lib_name} {version}\nCVE: {cve_id}\nCVSS: {cvss}",
                        confidence="LIKELY",
                        remediation=f"Review {cve_id} and upgrade {lib_name} if affected.",
                        metadata={
                            "vuln_type": "Known CVE (NVD)",
                            "library": lib_name,
                            "cve_id": cve_id,
                            "cvss_score": cvss,
                            "exploit": f"Search exploit-db or GitHub for {cve_id} PoC",
                            "impact": desc[:200],
                            "cwe": "CWE-1395",
                            "owasp": "A06:2021 Vulnerable and Outdated Components",
                            "time_to_exploit": "varies",
                        },
                    ))
                time.sleep(1)  # NVD rate limit

        self._log(f"CVE scan complete: {cve_count} known vulnerabilities found")
        return self._build_result(start, checked=len(techs), cves_found=cve_count)

    def _gather_detected_tech(self) -> Dict[str, str]:
        """Extract versioned technology detections from tech scanner results and headers."""
        techs: Dict[str, str] = {}

        # Check scan results for tech scanner findings from recon
        if self._recon and hasattr(self._recon, 'scan_results'):
            for sr in self._recon.scan_results:
                for finding in sr.findings:
                    if finding.category == "tech":
                        tech_name = finding.metadata.get("technology", "")
                        ver = finding.metadata.get("version", "")
                        if tech_name and ver and ver != "unknown":
                            techs[tech_name.lower()] = ver

        # Parse tech from the downloaded files' response headers
        for f in self._report.files:
            # Server header
            server = f.response_headers.get("server", "") or f.response_headers.get("Server", "")
            if server:
                m = re.search(r'(Apache|nginx|IIS|LiteSpeed|PHP|OpenSSL)[/ ]*([\d.]+)', server, re.I)
                if m:
                    techs[m.group(1).lower()] = m.group(2)

            # X-Powered-By
            powered = f.response_headers.get("x-powered-by", "") or f.response_headers.get("X-Powered-By", "")
            if powered:
                m = re.search(r'PHP/([\d.]+)', powered)
                if m:
                    techs["php"] = m.group(1)
                m = re.search(r'ASP\.NET|Express', powered)
                if m:
                    techs[m.group(0).lower()] = ""

        # Parse JS library versions from downloaded JavaScript files
        for f in self._report.files:
            if not f.local_path or not f.local_path.endswith((".js", ".mjs")):
                continue
            try:
                with open(f.local_path, "r", encoding="utf-8", errors="ignore") as fh:
                    head = fh.read(5000)  # First 5KB usually has version comments

                # jQuery: /*! jQuery v3.6.0
                m = re.search(r'jQuery\s+v?([\d.]+)', head)
                if m:
                    techs["jquery"] = m.group(1)

                # Lodash: lodash 4.17.21
                m = re.search(r'lodash[. ]+v?([\d.]+)', head, re.I)
                if m:
                    techs["lodash"] = m.group(1)

                # Angular: angular(?:js)?.*?v?([\d.]+)
                m = re.search(r'angular(?:js)?[. ]+v?([\d.]+)', head, re.I)
                if m:
                    techs["angular"] = m.group(1)

                # React: react\.(?:production|development).*?([\d.]+)
                m = re.search(r'react[.\-](?:production|development)[.\-]min.*?([\d.]+)', head, re.I)
                if m:
                    techs["react"] = m.group(1)

                # Vue: Vue.js v2.6.14
                m = re.search(r'Vue\.js\s+v([\d.]+)', head)
                if m:
                    techs["vue"] = m.group(1)

                # Bootstrap: Bootstrap v5.1.3
                m = re.search(r'Bootstrap\s+v([\d.]+)', head)
                if m:
                    techs["bootstrap"] = m.group(1)

                # Moment.js
                m = re.search(r'moment(?:\.js)?\s+v?([\d.]+)', head, re.I)
                if m:
                    techs["moment"] = m.group(1)

                # Axios
                m = re.search(r'axios\s+v?([\d.]+)', head, re.I)
                if m:
                    techs["axios"] = m.group(1)

                # Handlebars
                m = re.search(r'[Hh]andlebars\s+v?([\d.]+)', head)
                if m:
                    techs["handlebars"] = m.group(1)

                # highlight.js
                m = re.search(r'highlight\.js\s+v?([\d.]+)', head, re.I)
                if m:
                    techs["highlight.js"] = m.group(1)

                # Socket.IO
                m = re.search(r'socket\.io[- ]client[/ ]([\d.]+)', head, re.I)
                if m:
                    techs["socket.io"] = m.group(1)

                # DOMPurify
                m = re.search(r'DOMPurify\s+([\d.]+)', head)
                if m:
                    techs["dompurify"] = m.group(1)

            except (OSError, IOError):
                continue

        # Also check package.json if downloaded
        for f in self._report.files:
            if f.local_path and f.local_path.endswith("package.json"):
                try:
                    with open(f.local_path, "r", encoding="utf-8") as fh:
                        pkg = json.loads(fh.read())
                    for section in ("dependencies", "devDependencies"):
                        deps = pkg.get(section, {})
                        for name, ver in deps.items():
                            clean_name = name.lower().split("/")[-1]
                            clean_ver = re.sub(r'[\^~>=<]', '', ver).strip()
                            if clean_ver and re.match(r'\d', clean_ver):
                                techs[clean_name] = clean_ver
                except (OSError, json.JSONDecodeError):
                    pass

        return techs

    def _check_local_db(self, lib_name: str, version: str) -> List[Tuple[str, float, str, str]]:
        """Check local CVE database for matches."""
        results = []
        lib_lower = lib_name.lower().strip()
        for pattern, constraint, cve_id, cvss, desc, fix_ver in _KNOWN_CVES:
            if (pattern == lib_lower or pattern in lib_lower.split("-") or pattern in lib_lower.split(".")) and _version_match(version, constraint):
                results.append((cve_id, cvss, desc, fix_ver))
        return results

    def _has_local_match(self, lib_name: str) -> bool:
        """Check if a library has any entries in the local DB."""
        lib_lower = lib_name.lower().strip()
        return any(p == lib_lower or p in lib_lower.split("-") or p in lib_lower.split(".") for p, *_ in _KNOWN_CVES)

    def _query_nvd(self, keyword: str, version: str) -> List[Tuple[str, float, str]]:
        """Query NVD API for CVEs matching a keyword. Returns [(cve_id, cvss, description)]."""
        if not version:
            return []
        try:
            query = quote(f"{keyword} {version}")
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=5"
            req = Request(url, headers={
                "User-Agent": "WebRipper-Recon/5.0",
                "Accept": "application/json",
            })
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())

            results = []
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                desc_list = cve.get("descriptions", [])
                desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")

                # Get CVSS score
                metrics = cve.get("metrics", {})
                cvss = 0.0
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = metrics.get(metric_key, [])
                    if metric_list:
                        cvss = metric_list[0].get("cvssData", {}).get("baseScore", 0.0)
                        break

                if cve_id and cvss > 0:
                    results.append((cve_id, cvss, desc[:300]))

            return sorted(results, key=lambda x: -x[1])  # Highest CVSS first

        except (URLError, HTTPError, json.JSONDecodeError, Exception):
            return []

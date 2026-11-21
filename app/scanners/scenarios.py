"""
Scenario Intelligence Scanner for WebRipper Recon 5.0.

Dynamically matches target technology fingerprints against real-world
HackerOne bug bounty scenario recipes, executing non-destructive canary probes
with zero rate-limit noise.
"""

from __future__ import annotations

import re
import ssl
import time
import urllib.request
from typing import Dict, List, Set
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from .base import BaseScanner
from ..cvss import CVSSScore
from ..intelligence import get_engine, ScenarioRecipe
from ..models import Finding, ScanResult, Severity


class ScenarioScanner(BaseScanner):
    """Executes fingerprint-targeted canary probes based on real-world HackerOne bug bounty writeups."""

    @property
    def name(self) -> str:
        return "scenarios"

    @property
    def description(self) -> str:
        return "Executes fingerprint-targeted canary probes based on real-world bug bounty disclosures"

    def scan(self) -> ScanResult:
        start = time.time()
        self._log("Analyzing target tech stack for matching bug bounty scenarios...")

        # 1. Extract detected technologies from crawl and headers
        detected_techs = self._detect_technologies()
        self._log(f"Detected technologies for scenario matching: {', '.join(detected_techs) if detected_techs else 'Generic Web'}")

        # 2. Retrieve targeted scenarios from Intelligence Engine
        engine = get_engine()
        scenarios: List[ScenarioRecipe] = []

        if detected_techs:
            scenarios = engine.find_scenarios_for_tech(list(detected_techs))

        # Always include baseline universal scenarios (Git, CORS, metadata)
        universal = engine.find_scenarios_for_tech(["git", "cors", "aws"])
        for u in universal:
            if u not in scenarios:
                scenarios.append(u)

        self._log(f"Executing {len(scenarios)} targeted scenario canary probes (pacing enforced)...")

        # 3. Execute targeted canary probes
        tested_count = 0
        matched_count = 0
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        delay = getattr(self._settings, "delay", 0.0)

        proxy = self._get_proxy()
        for sc in scenarios:
            tested_count += 1
            probe_url = urljoin(self._settings.url, sc.probe_path.lstrip("/"))
            try:
                headers = self._build_headers()
                headers.setdefault("Accept", "*/*")
                if sc.probe_headers:
                    headers.update(sc.probe_headers)

                data = sc.probe_body.encode("utf-8") if sc.probe_body else None
                req = Request(probe_url, data=data, headers=headers, method=sc.probe_method)

                status_code = 0
                body = ""
                resp_headers = {}

                try:
                    if proxy:
                        proxy_handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
                        opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=ctx))
                        with opener.open(req, timeout=self._settings.timeout) as resp:
                            status_code = resp.status
                            body = resp.read().decode("utf-8", errors="ignore")[:4000]
                            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    else:
                        with urlopen(req, timeout=self._settings.timeout, context=ctx) as resp:
                            status_code = resp.status
                            body = resp.read().decode("utf-8", errors="ignore")[:4000]
                            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                except HTTPError as e:
                    status_code = e.code
                    try:
                        body = e.read().decode("utf-8", errors="ignore")[:4000]
                    except Exception:
                        body = ""
                    resp_headers = {k.lower(): v for k, v in e.headers.items()}
                except (URLError, TimeoutError, OSError):
                    continue

                # 4. Evaluate match criteria
                if status_code in sc.match_status:
                    is_match = False
                    search_corpus = f"{body}\n" + "\n".join(f"{k}: {v}" for k, v in resp_headers.items())

                    if sc.match_regex:
                        if re.search(sc.match_regex, search_corpus, re.IGNORECASE):
                            is_match = True
                    else:
                        is_match = True

                    # Negative filter check
                    if is_match and sc.negative_regex:
                        if re.search(sc.negative_regex, search_corpus, re.IGNORECASE):
                            is_match = False

                    if is_match:
                        matched_count += 1
                        cvss_score = CVSSScore.from_vector(sc.cvss_vector) if sc.cvss_vector else CVSSScore.from_score(7.5)
                        severity_map = {
                            "Critical": Severity.CRITICAL,
                            "High": Severity.HIGH,
                            "Medium": Severity.MEDIUM,
                            "Low": Severity.LOW,
                            "None": Severity.INFO,
                        }
                        sev = severity_map.get(cvss_score.label, Severity.HIGH)

                        evidence_snippet = body[:250].strip() or f"Status code: {status_code}"

                        # Synthesize reproduction cURL PoC
                        hdr_parts = [f'-H "{k}: {v}"' for k, v in headers.items() if k.lower() != "user-agent"]
                        hdr_str = (" " + " ".join(hdr_parts)) if hdr_parts else ""
                        data_str = f" --data '{sc.probe_body}'" if sc.probe_body else ""
                        poc_curl = f"curl -i -s -k -X {sc.probe_method} '{probe_url}'{hdr_str}{data_str}".strip()

                        self._add_finding(Finding(
                            severity=sev,
                            category=sc.category,
                            title=f"Scenario: {sc.title}",
                            description=(
                                f"{sc.author_insight}\n\n"
                                f"Historical Reference: {sc.bounty_reference}\n"
                                f"Applicable Tech Stack: {', '.join(sc.tech_stack)}"
                            ),
                            evidence=f"URL: {probe_url}\nStatus: {status_code}\nEvidence: {evidence_snippet}",
                            url=probe_url,
                            remediation=sc.remediation,
                            metadata={
                                "scenario_id": sc.id,
                                "cwe": sc.cwe,
                                "cvss": sc.cvss_vector,
                                "cvss_score": cvss_score.score,
                                "bounty_reference": sc.bounty_reference,
                                "tech_stack": ", ".join(sc.tech_stack),
                                "author_insight": sc.author_insight,
                                "impact": f"Real-world verified vulnerability scenario ({sc.bounty_reference})",
                                "poc_curl": poc_curl,
                            },
                        ))

            except Exception as probe_err:
                self._log(f"Scenario probe note ({sc.id}): {probe_err}")
            finally:
                if delay > 0:
                    time.sleep(delay)

        # 4. Cross-reference detected technologies with CISA Known Exploited Vulnerabilities (KEV)
        kev_count = 0
        for tech in list(detected_techs)[:5]:
            kevs = engine.search_cisa_kev(tech, limit=2)
            for kev in kevs:
                kev_count += 1
                self._add_finding(Finding(
                    severity=Severity.HIGH,
                    category="cves",
                    title=f"CISA KEV Active Exploit: {kev['cve_id']} ({kev['vendor']} {kev['product']})",
                    description=(
                        f"Active In-The-Wild Exploitation Advisory (CISA KEV):\n"
                        f"{kev['vuln_name']}\n\n"
                        f"{kev['short_description']}\n\n"
                        f"Required Action: {kev['required_action']}"
                    ),
                    evidence=f"Component match: {tech} -> {kev['vendor']} {kev['product']} ({kev['cve_id']})",
                    remediation=kev['required_action'],
                    metadata={
                        "cve": kev['cve_id'],
                        "cwes": kev['cwes'],
                        "cisa_kev": True,
                        "date_added": kev['date_added'],
                    },
                ))

        self._log(f"Scenario Intelligence scan complete: {matched_count} canary vulnerabilities, {kev_count} CISA KEV advisories ({tested_count} probes executed).")
        return self._build_result(start, tested_scenarios=tested_count, confirmed_vulnerabilities=matched_count)

    def _detect_technologies(self) -> Set[str]:
        """Collect technology tags from tech scanner results, crawled assets, headers, and extensions."""
        techs: Set[str] = set()

        if not self._report and not self._recon:
            return techs

        # 1. Harvest technologies directly from TechScanner findings if already executed
        scan_results = []
        if self._recon and hasattr(self._recon, "scan_results"):
            scan_results = self._recon.scan_results
        elif hasattr(self._report, "scan_results"):
            scan_results = self._report.scan_results

        for sr in scan_results:
            if sr.scanner_name == "tech":
                for f in sr.findings:
                    if f.metadata:
                        tech_val = str(f.metadata.get("technology") or f.metadata.get("tech") or "").lower()
                        if tech_val:
                            techs.add(tech_val)
                            techs.add(tech_val.replace(".", "").replace(" ", "").replace("-", ""))
                    t_title = f.title.lower()
                    for kw in [
                        "react", "next.js", "vue", "nuxt", "angular", "svelte", "gatsby",
                        "wordpress", "drupal", "joomla", "ghost",
                        "nginx", "apache", "iis", "litespeed", "express",
                        "spring", "django", "laravel", "rails", "fastapi", "flask",
                        "supabase", "firebase", "graphql", "apollo",
                        "aws", "gcp", "azure", "cloudflare", "docker", "kubernetes",
                        "jenkins", "elasticsearch", "kibana", "prometheus", "git",
                    ]:
                        if kw in t_title:
                            techs.add(kw.replace(".", ""))

        # 2. Check response paths and signatures from downloaded files
        files_list = getattr(self._report, "files", None) or getattr(self._report, "downloaded_files", None) or []
        for f in files_list:
            url_lower = getattr(f, "url", "").lower()
            if "/_next/" in url_lower:
                techs.update(["nextjs", "react", "node", "vercel"])
            if "/wp-content/" in url_lower or "/wp-includes/" in url_lower:
                techs.update(["wordpress", "php", "cms"])
            if "/graphql" in url_lower:
                techs.update(["graphql", "apollo"])
            if ".php" in url_lower:
                techs.update(["php", "laravel"])
            if "/static/" in url_lower:
                techs.update(["django", "python"])
            if "/actuator" in url_lower:
                techs.update(["spring", "springboot", "java"])
            if "/swagger" in url_lower or "/openapi" in url_lower:
                techs.update(["swagger", "openapi", "api"])

        # 3. Check crawled pages and captured requests
        for page_url in getattr(self._report, "pages", []) or []:
            page_lower = page_url.lower()
            if "/_next/" in page_lower:
                techs.update(["nextjs", "react", "node", "vercel"])
            if "/wp-content/" in page_lower or "/wp-includes/" in page_lower:
                techs.update(["wordpress", "php", "cms"])
            if "/graphql" in page_lower:
                techs.update(["graphql", "apollo"])
            if ".php" in page_lower:
                techs.update(["php", "laravel"])
            if "/static/" in page_lower:
                techs.update(["django", "python"])
            if "/actuator" in page_lower:
                techs.update(["spring", "springboot", "java"])
            if "/swagger" in page_lower or "/openapi" in page_lower:
                techs.update(["swagger", "openapi", "api"])

        for req in getattr(self._report, "captured_requests", []) or []:
            req_url = (req.get("url", "") if isinstance(req, dict) else getattr(req, "url", "")).lower()
            if "/_next/" in req_url:
                techs.update(["nextjs", "react", "node", "vercel"])
            if "/wp-content/" in req_url or "/wp-includes/" in req_url:
                techs.update(["wordpress", "php", "cms"])
            if "/graphql" in req_url:
                techs.update(["graphql", "apollo"])
            if ".php" in req_url:
                techs.update(["php", "laravel"])
            if "/static/" in req_url:
                techs.update(["django", "python"])
            if "/actuator" in req_url:
                techs.update(["spring", "springboot", "java"])
            if "/swagger" in req_url or "/openapi" in req_url:
                techs.update(["swagger", "openapi", "api"])

        # 4. Also inspect base URL path and settings
        url_parsed = urlparse(self._settings.url)
        path = url_parsed.path.lower()
        if "graphql" in path:
            techs.add("graphql")
        if "actuator" in path:
            techs.update(["spring", "springboot"])

        return techs

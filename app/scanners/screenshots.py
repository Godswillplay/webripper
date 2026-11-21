"""
Screenshot capture scanner for WebRipper Recon 5.0.

Auto-screenshots admin panels, login pages, and interesting endpoints.
Uses Playwright (bundled with WebRipper) for browser-based captures.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

from .base import BaseScanner
from ..models import Finding, ScanResult, Severity


# Patterns that indicate interesting pages worth screenshotting
_INTERESTING_PATTERNS = re.compile(
    r"(?:login|signin|sign-in|auth|admin|dashboard|panel|manager|console|portal|backend"
    r"|wp-admin|wp-login|phpmyadmin|cpanel|webmail|owa|remote|vpn|sso|register"
    r"|signup|sign-up|forgot|reset|password|account|profile|settings|config"
    r"|api/docs|swagger|graphql|api-explorer|status|health|debug|monitoring"
    r"|upload|file-manager|terminal|shell|.env|.git|backup)",
    re.IGNORECASE,
)


class ScreenshotScanner(BaseScanner):
    """Captures screenshots of interesting pages (login, admin, dashboards)."""

    @property
    def name(self) -> str:
        return "screenshots"

    @property
    def description(self) -> str:
        return "Auto-captures screenshots of admin panels, login pages, and interesting endpoints"

    def scan(self) -> ScanResult:
        start = time.time()
        self._log("Identifying pages to screenshot...")

        # Identify interesting URLs
        interesting: List[Dict] = []
        seen_urls: Set[str] = set()

        for f in self._report.files:
            if not f.url or f.error:
                continue
            url_lower = f.url.lower()
            if f.url in seen_urls:
                continue

            # Only screenshot pages that actually returned content (200 OK)
            # Skip redirected or error pages — they produce misleading screenshots
            if f.status and f.status != 200:
                continue

            # Check if URL matches interesting patterns
            path = urlparse(f.url).path
            if _INTERESTING_PATTERNS.search(url_lower) or _INTERESTING_PATTERNS.search(path):
                category = self._categorize_url(url_lower)
                interesting.append({"url": f.url, "category": category})
                seen_urls.add(f.url)

        if not interesting:
            self._log("No interesting pages found to screenshot")
            return self._build_result(start, screenshots=0)

        # Limit to 20 pages to avoid excessive time
        interesting = interesting[:20]
        self._log(f"Found {len(interesting)} interesting pages to screenshot")

        # Create screenshots directory
        screenshot_dir = os.path.join(self._settings.output_dir, "screenshots")
        os.makedirs(screenshot_dir, exist_ok=True)

        # Capture screenshots
        captured = []
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            captured = loop.run_until_complete(
                self._capture_screenshots(interesting, screenshot_dir)
            )
            loop.close()
        except Exception as e:
            self._log(f"Screenshot capture error: {e}")
            self._add_finding(Finding(
                severity=Severity.INFO,
                category="screenshots",
                title="Screenshot Capture Failed",
                description=f"Could not capture screenshots: {e}. Playwright/Chromium may not be available.",
                metadata={
                    "exploit": "N/A — informational",
                    "impact": "Screenshots not available in report",
                    "cwe": "", "owasp": "", "time_to_exploit": "N/A",
                },
            ))

        # Create findings for each captured screenshot
        for cap in captured:
            sev = Severity.HIGH if cap["category"] in ("admin", "debug") else (
                Severity.MEDIUM if cap["category"] in ("login", "upload") else Severity.INFO
            )
            self._add_finding(Finding(
                severity=sev,
                category="screenshots",
                title=f"Screenshot: {cap['category'].title()} — {cap['url'][:60]}",
                description=f"Captured screenshot of {cap['category']} page: {cap['url']}",
                evidence=f"Screenshot saved: {cap['path']}",
                remediation=self._get_remediation(cap["category"]),
                metadata={
                    "screenshot_path": cap["path"],
                    "page_category": cap["category"],
                    "url": cap["url"],
                    "exploit": self._get_exploit_info(cap["category"]),
                    "impact": self._get_impact(cap["category"]),
                    "cwe": "CWE-200",
                    "owasp": "A01:2021 Broken Access Control",
                    "time_to_exploit": "~5 minutes",
                },
            ))

        self._log(f"Screenshot scan complete: {len(captured)} pages captured")
        return self._build_result(start, screenshots=len(captured))

    async def _capture_screenshots(self, pages: List[Dict], output_dir: str) -> List[Dict]:
        """Capture screenshots using Playwright."""
        captured = []
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            self._log("Playwright not available — skipping screenshots")
            return captured

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 720},
                    ignore_https_errors=True,
                )

                # Inject auth if available
                if self._settings.auth_cookie:
                    cookies = []
                    domain = urlparse(self._settings.url).hostname
                    for part in self._settings.auth_cookie.split(";"):
                        part = part.strip()
                        if "=" in part:
                            key, val = part.split("=", 1)
                            cookies.append({
                                "name": key.strip(),
                                "value": val.strip(),
                                "domain": domain,
                                "path": "/",
                            })
                    if cookies:
                        await context.add_cookies(cookies)

                page = await context.new_page()

                if self._settings.auth_token:
                    await page.set_extra_http_headers({
                        "Authorization": f"Bearer {self._settings.auth_token}"
                    })

                for i, info in enumerate(pages):
                    try:
                        self._log(f"  Screenshotting ({i+1}/{len(pages)}): {info['url'][:60]}")
                        safe_name = re.sub(r'[^\w\-.]', '_', urlparse(info["url"]).path)[:50] or "index"
                        filename = f"{i:02d}_{info['category']}_{safe_name}.png"
                        filepath = os.path.join(output_dir, filename)

                        await page.goto(info["url"], timeout=15000, wait_until="domcontentloaded")
                        await page.wait_for_timeout(1000)  # Allow JS to render
                        await page.screenshot(path=filepath, full_page=False)

                        captured.append({
                            "url": info["url"],
                            "category": info["category"],
                            "path": filepath,
                        })
                    except Exception as e:
                        self._log(f"  Skip {info['url'][:40]}: {e}")

                await browser.close()
        except Exception as e:
            self._log(f"Playwright browser error: {e}")

        return captured

    @staticmethod
    def _categorize_url(url: str) -> str:
        """Categorize a URL by its type."""
        if re.search(r"admin|panel|dashboard|manager|console|backend|cpanel", url):
            return "admin"
        if re.search(r"login|signin|sign-in|auth|sso|wp-login", url):
            return "login"
        if re.search(r"register|signup|sign-up", url):
            return "registration"
        if re.search(r"swagger|api-doc|graphql|api-explorer", url):
            return "api_docs"
        if re.search(r"upload|file-manager", url):
            return "upload"
        if re.search(r"debug|status|health|monitoring|\.env|\.git", url):
            return "debug"
        if re.search(r"forgot|reset|password", url):
            return "password_reset"
        return "interesting"

    @staticmethod
    def _get_exploit_info(category: str) -> str:
        exploits = {
            "admin": "Admin panel exposed. Attempt default credentials (admin:admin, admin:password). Check for auth bypass, IDOR, or direct URL access.",
            "login": "Login page found. Attack vectors: credential stuffing, brute force, SQL injection in login form, session fixation.",
            "api_docs": "API documentation exposed. Extract all endpoints, test each for auth bypass, IDOR, mass assignment.",
            "upload": "Upload functionality found. Test: unrestricted file upload (webshell), path traversal, MIME type bypass.",
            "debug": "Debug/diagnostic page exposed. May leak: stack traces, environment variables, database connections, internal IPs.",
            "registration": "Registration form found. Test: mass account creation, email enumeration, weak password policy bypass.",
            "password_reset": "Password reset flow found. Test: token predictability, user enumeration, host header injection.",
        }
        return exploits.get(category, "Interesting page discovered — manual review recommended.")

    @staticmethod
    def _get_impact(category: str) -> str:
        impacts = {
            "admin": "Full application control if admin credentials are compromised",
            "login": "Account takeover via credential attacks",
            "api_docs": "Complete API attack surface mapped",
            "upload": "Remote code execution via malicious file upload",
            "debug": "Sensitive configuration and internal architecture exposure",
        }
        return impacts.get(category, "Information disclosure")

    @staticmethod
    def _get_remediation(category: str) -> str:
        remediations = {
            "admin": "Restrict admin panel access by IP whitelist or VPN. Enable MFA. Change default credentials.",
            "login": "Implement rate limiting, account lockout, CAPTCHA. Use MFA.",
            "api_docs": "Restrict API documentation to authenticated users or internal networks only.",
            "upload": "Validate file types server-side, use random filenames, store outside webroot.",
            "debug": "Disable debug endpoints in production. Restrict access by IP.",
        }
        return remediations.get(category, "Review page for sensitive information exposure.")

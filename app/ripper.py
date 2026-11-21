"""
Web asset extraction engine for WebRipper Recon 3.0.

Implements the full extraction pipeline:
  1. Fetch root HTML (+ recursive crawling with depth control)
  2. Parse HTML for asset URLs (tags, attributes, srcset, meta)
  3. Scan inline <script> blocks for module imports, fetches, asset URLs
  4. Scan inline <style> blocks for url() and @import references
  5. Probe well-known paths (robots.txt, manifest.json, etc.)
  6. Deep-scan discovered JS/CSS files for additional URLs
  7. Parse source maps and save embedded sourcesContent
  8. Dynamic browser capture via Playwright (optional)
  9. Deduplicate & filter discovered URLs
  10. Download all assets concurrently with progress reporting
  11. Write report.json
"""

from __future__ import annotations

import asyncio
import collections
import hashlib
import json
import logging
import os
import posixpath
import re
import ssl
import time
import urllib.robotparser
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import (
    parse_qs,
    unquote,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

import aiohttp
from bs4 import BeautifulSoup

from .models import (
    EventType,
    FileResult,
    ProgressEvent,
    RipperSettings,
    RipReport,
    _format_size,
)
from .stealth import (
    STEALTH_CHROMIUM_ARGS,
    STEALTH_INIT_SCRIPT,
    AutoThrottle,
    NetworkRecorder,
    generate_browser_headers,
    get_stealth_profile,
    is_ad_or_tracker,
    parse_retry_after,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_USER_AGENT = "WebRipper-Recon/3.0"

WELL_KNOWN_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/manifest.json",
    "/manifest.webmanifest",
    "/service-worker.js",
    "/sw.js",
    "/favicon.ico",
    "/browserconfig.xml",
    "/humans.txt",
    "/.well-known/security.txt",
]

ASSET_EXTENSIONS = re.compile(
    r"\.(js|mjs|cjs|css|json|woff2?|ttf|eot|otf|"
    r"png|jpe?g|gif|svg|webp|avif|ico|bmp|tiff?|"
    r"mp4|webm|ogv|mp3|ogg|wav|flac|aac|"
    r"wasm|map|xml|txt|csv|pdf)(?:[?#]|$)",
    re.IGNORECASE,
)

_WINDOWS_RESERVED = re.compile(r'[<>:"|?*]')
_MAX_COMPONENT = 200

_WINDOWS_DEVICE_NAMES = frozenset({
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
})


# ---------------------------------------------------------------------------
# Regex patterns for JS / CSS scanning
# ---------------------------------------------------------------------------

_RE_JS_IMPORT_FROM = re.compile(
    r"""(?:import|export)\s+[^\n;]+?\s+from\s+['"`]([^'"`]+)['"`]"""
)
_RE_JS_IMPORT_BARE = re.compile(r"""import\s+['"`]([^'"`]+)['"`]""")
_RE_JS_DYNAMIC_IMPORT = re.compile(r"""import\(\s*['"`]([^'"`]+)['"`]\s*\)""")
_RE_JS_REQUIRE = re.compile(r"""require\(\s*['"`]([^'"`]+)['"`]\s*\)""")
_RE_JS_FETCH = re.compile(
    r"""(?:fetch|axios\.get|axios\.post|axios)\(\s*['"`]([^'"`]+)['"`]\s*"""
)
_RE_JS_SOURCEMAP = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
_RE_JS_ASSET_URL = re.compile(
    r"""['"`]([^'"`]*?\.(?:js|mjs|css|json|woff2?|ttf|eot|otf|"""
    r"""png|jpe?g|gif|svg|webp|avif|ico|mp4|webm|mp3|ogg|wav|"""
    r"""wasm|map)(?:\?[^'"`]*?)?)['"`]""",
    re.IGNORECASE,
)

_RE_CSS_URL = re.compile(
    r"""url\(\s*['"]?([^'")\s]+?)['"]?\s*\)""", re.IGNORECASE
)
_RE_CSS_IMPORT = re.compile(
    r"""@import\s+(?:url\(\s*['"]?([^'")\s]+?)['"]?\s*\)|['"]([^'"]+)['"])""",
    re.IGNORECASE,
)
_RE_CSS_SOURCEMAP = re.compile(r"/\*[#@]\s*sourceMappingURL=(\S+?)\s*\*/")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_url(url: str, base: str) -> Optional[str]:
    """Resolve *url* against *base*, strip fragments, normalize ports & paths, return absolute URL or None."""
    if not url:
        return None
    url = url.strip()
    if not url or url.startswith("#"):
        return None

    url_lower = url.lower()
    if url_lower.startswith(("data:", "blob:", "javascript:", "mailto:", "tel:", "callto:", "sms:", "geo:", "viber:", "whatsapp:")):
        return None

    resolved = urljoin(base, url)
    parsed = urlparse(resolved)
    if parsed.scheme not in ("http", "https"):
        return None

    # Lowercase netloc and strip standard default ports
    netloc = parsed.netloc.lower()
    if netloc.endswith(":80") and parsed.scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and parsed.scheme == "https":
        netloc = netloc[:-4]

    # Normalize dot segments in path
    path = parsed.path or "/"
    if "//" in path or "/." in path:
        ends_slash = path.endswith("/")
        path = posixpath.normpath(path)
        if ends_slash and not path.endswith("/"):
            path += "/"

    clean = urlunparse(parsed._replace(netloc=netloc, path=path, fragment=""))
    return clean


def _sanitize_path(url: str, output_dir: str) -> str:
    """Convert a URL into a safe local filesystem path under *output_dir*."""
    parsed = urlparse(url)
    host = parsed.netloc or "unknown_host"

    raw_path = unquote(parsed.path or "/").replace("\\", "/")
    segments = [s for s in raw_path.split("/") if s and s not in ("..", ".")]

    safe_segments: list[str] = []
    for seg in segments:
        seg = _WINDOWS_RESERVED.sub("_", seg)
        seg = seg.strip(". ")
        if not seg:
            continue
        if len(seg) > _MAX_COMPONENT:
            seg = seg[:_MAX_COMPONENT]
        # Check DOS device names (e.g. aux.js -> _aux.js, con -> _con)
        base_name = seg.split(".")[0].upper()
        if base_name in _WINDOWS_DEVICE_NAMES:
            seg = f"_{seg}"
        safe_segments.append(seg)

    if parsed.query:
        query_hash = hashlib.md5(parsed.query.encode()).hexdigest()[:10]
        if safe_segments and not raw_path.endswith("/"):
            name = safe_segments[-1]
            dot = name.rfind(".")
            if dot > 0:
                name = f"{name[:dot]}__{query_hash}{name[dot:]}"
            else:
                name = f"{name}__{query_hash}"
            safe_segments[-1] = name
        else:
            safe_segments.append(f"index__{query_hash}.html")

    if not safe_segments or (raw_path.endswith("/") and not parsed.query):
        safe_segments.append("index.html")

    host = _WINDOWS_RESERVED.sub("_", host).strip(". ")
    target_path = os.path.normpath(os.path.join(output_dir, host, *safe_segments))
    canonical_out = os.path.normpath(output_dir)
    try:
        Path(target_path).resolve().relative_to(Path(canonical_out).resolve())
    except ValueError:
        target_path = os.path.normpath(os.path.join(output_dir, host, "safe_fallback_" + hashlib.md5(url.encode()).hexdigest()[:8] + ".html"))
    return target_path


def _parse_srcset(srcset_value: str) -> List[str]:
    """Extract URLs from an HTML srcset attribute value."""
    urls: list[str] = []
    for entry in srcset_value.split(","):
        parts = entry.strip().split()
        if parts:
            urls.append(parts[0])
    return urls


# ---------------------------------------------------------------------------
# WebRipper
# ---------------------------------------------------------------------------


class WebRipper:
    """Asynchronous web asset extraction engine with recursive crawling.

    Fetches a root URL, discovers linked assets through HTML parsing,
    inline JS/CSS scanning, well-known path probing, deep CSS/JS scanning,
    optional Playwright-based dynamic capture, then downloads everything
    into a mirrored directory tree.

    Supports recursive link-following with depth control and concurrent
    downloads with configurable worker count.
    """

    def __init__(
        self,
        settings: RipperSettings,
        progress_callback: Callable[[ProgressEvent], None],
    ) -> None:
        self._settings = settings
        self._callback = progress_callback
        self._cancel_event = asyncio.Event()

        self._discovered: Set[str] = set()
        self._downloaded_count = 0
        self._failed_count = 0
        self._total_bytes = 0
        self._results: List[FileResult] = []
        self._base_url = settings.url
        self._origin = ""
        self._root_html = ""

        # Recursive crawling state
        self._visited_pages: Set[str] = set()
        self._pages_crawled = 0
        self._robot_disallowed: Set[str] = set()
        self._robot_parser: Optional[urllib.robotparser.RobotFileParser] = None

        # Concurrency & domain pacing state
        self._domain_locks: Dict[str, asyncio.Lock] = collections.defaultdict(asyncio.Lock)
        self._domain_last_request: Dict[str, float] = {}
        self._background_tasks: Set[asyncio.Task] = set()

        # Modern scraper state (inspired by Scrapling)
        self._captured_requests: List[Dict[str, Any]] = []
        self._network_recorder = NetworkRecorder()
        self._throttle = AutoThrottle(
            start_delay=settings.delay,
            max_delay=30.0,
            target_concurrency=max(settings.workers, 1),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> RipReport:
        """Execute the full extraction pipeline and return a ``RipReport``."""
        start = datetime.now(timezone.utc)
        cancelled = False

        parsed_origin = urlparse(self._base_url)
        self._origin = f"{parsed_origin.scheme.lower()}://{parsed_origin.netloc.lower()}"

        try:
            timeout = aiohttp.ClientTimeout(total=self._settings.timeout)
            connector = aiohttp.TCPConnector(ssl=False)

            # Build realistic browser headers with client hints and custom overrides
            headers = generate_browser_headers(
                user_agent=self._settings.user_agent,
                custom_headers=self._settings.custom_headers,
            )
            # Inject authentication — combine custom_cookies + auth_cookie
            cookie_parts = []
            if self._settings.custom_cookies:
                cookie_parts.append(self._settings.custom_cookies)
            if self._settings.auth_cookie:
                cookie_parts.append(self._settings.auth_cookie)
            if cookie_parts:
                headers["Cookie"] = "; ".join(cookie_parts)
            if self._settings.auth_token:
                headers["Authorization"] = f"Bearer {self._settings.auth_token}"

            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers=headers,
                max_line_size=131072,
                max_field_size=131072,
            ) as session:
                # Phase 0: Robots.txt
                if self._settings.respect_robots:
                    await self._fetch_robots(session)

                # Phase 1: Fetch root HTML
                self._emit_phase("Fetching root page")
                root_ok = await self._fetch_root(session)
                if not root_ok:
                    self._emit_log("Failed to fetch root page — aborting")
                    return self._build_report(start)

                if self._is_cancelled():
                    cancelled = True
                else:
                    # Phase 2-4: Parse HTML, scan inline JS & CSS
                    self._emit_phase("Parsing HTML & extracting URLs")
                    self._parse_html()
                    self._emit_log(
                        f"Discovered {len(self._discovered)} URLs from HTML"
                    )

                    # Phase 2b: Recursive crawling
                    if self._settings.depth > 1:
                        self._emit_phase(f"Recursive crawling (depth {self._settings.depth})")
                        await self._recursive_crawl(session)

                if self._is_cancelled():
                    cancelled = True
                elif not cancelled:
                    # Phase 5: Probe well-known paths
                    self._emit_phase("Probing well-known paths")
                    await self._probe_well_known(session)

                if self._is_cancelled():
                    cancelled = True
                elif not cancelled:
                    # Phase 6-7: Deep scan JS/CSS and source maps
                    self._emit_phase("Deep scanning JS & CSS assets")
                    await self._deep_scan(session)

                if self._is_cancelled():
                    cancelled = True
                elif not cancelled:
                    # Phase 8: Dynamic browser capture (optional)
                    if self._settings.dynamic_capture:
                        self._emit_phase("Dynamic browser capture")
                        await self._dynamic_capture()

                if self._is_cancelled():
                    cancelled = True
                elif not cancelled:
                    # Phase 9: Deduplicate & filter
                    self._emit_phase("Filtering & deduplicating")
                    download_list = self._filter_urls()
                    self._emit_log(
                        f"{len(download_list)} assets to download after filtering"
                    )

                    # Phase 10: Download (concurrently)
                    self._emit_phase(f"Downloading assets ({self._settings.workers} workers)")
                    await self._download_all(session, download_list)

                if self._is_cancelled():
                    cancelled = True

        except asyncio.CancelledError:
            cancelled = True
        except Exception as exc:
            self._emit_log(f"Unexpected pipeline error: {exc}")
            logger.exception("Pipeline error")
        finally:
            if self._background_tasks:
                for t in list(self._background_tasks):
                    if not t.done():
                        t.cancel()
                await asyncio.gather(*list(self._background_tasks), return_exceptions=True)
                self._background_tasks.clear()

        report = self._build_report(start, cancelled=cancelled)

        # Phase 11: Write report.json
        self._emit_phase("Writing report")
        self._write_report(report)

        if cancelled:
            self._callback(
                ProgressEvent(
                    event_type=EventType.CANCELLED,
                    message="Rip cancelled by user",
                    downloaded=self._downloaded_count,
                    failed=self._failed_count,
                    total=len(self._results),
                )
            )
        else:
            self._callback(
                ProgressEvent(
                    event_type=EventType.COMPLETE,
                    message=(
                        f"Complete — {self._downloaded_count} downloaded, "
                        f"{self._failed_count} failed, "
                        f"{_format_size(self._total_bytes)} total"
                    ),
                    downloaded=self._downloaded_count,
                    failed=self._failed_count,
                    total=len(self._results),
                )
            )

        return report

    def cancel(self) -> None:
        """Signal cancellation."""
        self._cancel_event.set()
        for t in list(self._background_tasks):
            if not t.done():
                t.cancel()

    # ------------------------------------------------------------------
    # Phase 0: Robots.txt
    # ------------------------------------------------------------------

    async def _fetch_robots(self, session: aiohttp.ClientSession) -> None:
        """Fetch and parse robots.txt using standard RobotFileParser."""
        robots_url = urljoin(self._origin + "/", "robots.txt")
        proxy = self._settings.proxy or None
        try:
            async with session.get(robots_url, proxy=proxy) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    rp = urllib.robotparser.RobotFileParser()
                    rp.parse(text.splitlines())
                    self._robot_parser = rp
                    for line in text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path:
                                self._robot_disallowed.add(path)
                    self._emit_log(f"Parsed robots.txt ({len(self._robot_disallowed)} disallow rules)")
        except Exception:
            pass

    def _is_robot_allowed(self, url: str) -> bool:
        """Check if URL is allowed by robots.txt."""
        if not self._settings.respect_robots:
            return True
        if self._robot_parser:
            try:
                ua = self._settings.user_agent or DEFAULT_USER_AGENT
                return self._robot_parser.can_fetch(ua, url)
            except Exception:
                pass
        if not self._robot_disallowed:
            return True
        path = urlparse(url).path
        for disallowed in self._robot_disallowed:
            if disallowed == "/":
                continue  # Don't block all root URLs on naive match
            if path.startswith(disallowed):
                return False
        return True

    # ------------------------------------------------------------------
    # Phase 1: Fetch root HTML
    # ------------------------------------------------------------------

    async def _fetch_root(self, session: aiohttp.ClientSession) -> bool:
        """Fetch the root page HTML. Returns True on success, with fallback for oversized headers & WAFs."""
        proxy = self._settings.proxy or None
        try:
            async with session.get(self._base_url, proxy=proxy) as resp:
                if resp.status != 200:
                    self._emit_log(f"Root page returned HTTP {resp.status} — attempting fallback")
                    return await self._fetch_root_fallback(status_code=resp.status)
                final_url = str(resp.url)
                if final_url != self._base_url:
                    self._base_url = final_url
                    parsed_fin = urlparse(final_url)
                    self._origin = f"{parsed_fin.scheme.lower()}://{parsed_fin.netloc.lower()}"
                self._root_html = await resp.text(errors="replace")
                root_headers = {k: v for k, v in resp.headers.items()}

                # Save root HTML to disk
                root_path = _sanitize_path(self._base_url, self._settings.output_dir)
                os.makedirs(os.path.dirname(root_path), exist_ok=True)
                with open(root_path, "w", encoding="utf-8", errors="replace") as f:
                    f.write(self._root_html)
                root_size = len(self._root_html.encode("utf-8", errors="replace"))

                self._results.append(FileResult(
                    url=self._base_url,
                    status=200,
                    size=root_size,
                    content_type=resp.headers.get("Content-Type", ""),
                    local_path=root_path,
                    response_headers=root_headers,
                ))
                self._downloaded_count += 1
                self._total_bytes += root_size
                self._pages_crawled += 1
                self._visited_pages.add(self._base_url)
                self._emit_log(f"Fetched root page ({_format_size(root_size)})")
                return True
        except Exception as exc:
            self._emit_log(f"Initial root fetch error ({exc}) — activating resilient fallback")
            return await self._fetch_root_fallback(original_error=exc)

    async def _fetch_root_fallback(
        self,
        original_error: Optional[Exception] = None,
        status_code: Optional[int] = None,
    ) -> bool:
        """Resilient fallback mechanism when root page fails due to oversized headers, LineTooLong, or WAF blocks."""
        proxy = self._settings.proxy or None

        # Fallback 1: Ultra-large HTTP header buffer (512 KB) with safe standard compression
        self._emit_log("Retrying root page fetch with expanded 512KB HTTP header buffer...")
        try:
            headers = generate_browser_headers(
                user_agent=self._settings.user_agent,
                custom_headers=self._settings.custom_headers,
            )
            # Force standard gzip/deflate on retry to bypass any Brotli decoding errors
            headers["Accept-Encoding"] = "gzip, deflate"
            if self._settings.auth_cookie:
                headers["Cookie"] = self._settings.auth_cookie
            if self._settings.auth_token:
                headers["Authorization"] = f"Bearer {self._settings.auth_token}"

            timeout = aiohttp.ClientTimeout(total=self._settings.timeout)
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers=headers,
                max_line_size=524288,
                max_field_size=524288,
            ) as fb_session:
                async with fb_session.get(self._base_url, proxy=proxy) as resp:
                    if resp.status == 200:
                        self._root_html = await resp.text(errors="replace")
                        root_headers = {k: v for k, v in resp.headers.items()}
                        root_path = _sanitize_path(self._base_url, self._settings.output_dir)
                        os.makedirs(os.path.dirname(root_path), exist_ok=True)
                        with open(root_path, "w", encoding="utf-8", errors="replace") as f:
                            f.write(self._root_html)
                        root_size = len(self._root_html.encode("utf-8", errors="replace"))

                        self._results.append(FileResult(
                            url=self._base_url,
                            status=200,
                            size=root_size,
                            content_type=resp.headers.get("Content-Type", ""),
                            local_path=root_path,
                            response_headers=root_headers,
                        ))
                        self._downloaded_count += 1
                        self._total_bytes += root_size
                        self._pages_crawled += 1
                        self._visited_pages.add(self._base_url)
                        self._emit_log(f"Fetched root page via extended 512KB buffer ({_format_size(root_size)})")
                        return True
        except Exception as buffer_err:
            self._emit_log(f"Extended buffer retry encountered: {buffer_err}")

        # Fallback 2: Dynamic Chromium Browser Render via Playwright
        self._emit_log("Attempting Playwright stealth browser fallback for root page...")
        try:
            from playwright.async_api import async_playwright
            from .dependencies import _get_default_browser_dir
            browser_path = str(_get_default_browser_dir())
            if os.path.isdir(browser_path):
                os.environ["PLAYWRIGHT_BROWSERS_PATH"] = browser_path

            async with async_playwright() as pw:
                launch_options: Dict[str, Any] = {
                    "headless": True,
                    "args": STEALTH_CHROMIUM_ARGS,
                }
                if proxy:
                    launch_options["proxy"] = {"server": proxy}

                browser = await self._launch_browser(pw, launch_options)
                try:
                    profile = get_stealth_profile(0)
                    effective_ua = profile["user_agent"] if (not self._settings.user_agent or self._settings.user_agent.lower().startswith("webripper")) else self._settings.user_agent
                    context = await browser.new_context(
                        viewport=profile["viewport"],
                        user_agent=effective_ua,
                        ignore_https_errors=True,
                    )
                    await context.add_init_script(script=STEALTH_INIT_SCRIPT)
                    page = await context.new_page()
                    resp = await page.goto(
                        self._base_url,
                        timeout=self._settings.timeout * 1000,
                        wait_until="domcontentloaded",
                    )
                    self._root_html = await page.content()
                    root_path = _sanitize_path(self._base_url, self._settings.output_dir)
                    os.makedirs(os.path.dirname(root_path), exist_ok=True)
                    with open(root_path, "w", encoding="utf-8", errors="replace") as f:
                        f.write(self._root_html)
                    root_size = len(self._root_html.encode("utf-8", errors="replace"))

                    pw_headers: Dict[str, str] = {}
                    if resp:
                        try:
                            pw_headers = await resp.all_headers()
                        except Exception:
                            pass

                    self._results.append(FileResult(
                        url=self._base_url,
                        status=200,
                        size=root_size,
                        content_type="text/html",
                        local_path=root_path,
                        response_headers=pw_headers,
                    ))
                    self._downloaded_count += 1
                    self._total_bytes += root_size
                    self._pages_crawled += 1
                    self._visited_pages.add(self._base_url)
                    self._emit_log(f"Successfully retrieved root page via Playwright browser ({_format_size(root_size)})")
                    return True
                finally:
                    await browser.close()
        except Exception as pw_err:
            self._emit_log(f"Playwright browser fallback error: {pw_err}")

        return False

    async def _launch_browser(self, pw, base_options: Dict[str, Any]):
        """Launch Playwright browser with multi-channel fallback (Chromium -> Edge -> Chrome)."""
        # 1. Try standard managed Chromium
        try:
            return await pw.chromium.launch(**base_options)
        except Exception as e_chromium:
            # 2. Try Microsoft Edge (built-in on Windows)
            try:
                edge_options = dict(base_options)
                edge_options["channel"] = "msedge"
                browser = await pw.chromium.launch(**edge_options)
                self._emit_log("Using system Microsoft Edge for browser automation")
                return browser
            except Exception:
                pass

            # 3. Try Google Chrome (if installed)
            try:
                chrome_options = dict(base_options)
                chrome_options["channel"] = "chrome"
                browser = await pw.chromium.launch(**chrome_options)
                self._emit_log("Using system Google Chrome for browser automation")
                return browser
            except Exception:
                pass

            # 4. If PLAYWRIGHT_BROWSERS_PATH was pointing to a mismatched folder, try default location
            if "PLAYWRIGHT_BROWSERS_PATH" in os.environ:
                saved = os.environ.pop("PLAYWRIGHT_BROWSERS_PATH", None)
                try:
                    browser = await pw.chromium.launch(**base_options)
                    return browser
                except Exception:
                    pass
                finally:
                    if saved:
                        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = saved

            raise e_chromium

    # ------------------------------------------------------------------
    # Phase 2-4: Parse HTML
    # ------------------------------------------------------------------

    def _parse_html(self) -> None:
        """Parse the root HTML and extract all discoverable asset URLs."""
        self._parse_html_content(self._root_html, self._base_url)

    def _parse_html_content(self, html: str, base: str) -> None:
        """Parse HTML content and extract all discoverable asset URLs."""
        soup = BeautifulSoup(html, "lxml")

        # Respect <base href="..."> if present in document
        base_tag = soup.find("base", href=True)
        if base_tag and base_tag.get("href"):
            base = urljoin(base, str(base_tag["href"]).strip())

        # <script src>
        for tag in soup.find_all("script", src=True):
            self._add(tag["src"], base)

        # <link href>
        for tag in soup.find_all("link", href=True):
            self._add(tag["href"], base)

        # <img>
        for tag in soup.find_all("img"):
            if tag.get("src"):
                self._add(tag["src"], base)
            if tag.get("data-src"):
                self._add(tag["data-src"], base)
            for attr in ("srcset", "data-srcset"):
                val = tag.get(attr)
                if val:
                    for u in _parse_srcset(val):
                        self._add(u, base)

        # <source>
        for tag in soup.find_all("source"):
            if tag.get("src"):
                self._add(tag["src"], base)
            if tag.get("srcset"):
                for u in _parse_srcset(tag["srcset"]):
                    self._add(u, base)

        # <video>, <audio>
        for tag_name in ("video", "audio"):
            for tag in soup.find_all(tag_name):
                if tag.get("src"):
                    self._add(tag["src"], base)
                if tag.get("poster"):
                    self._add(tag["poster"], base)

        # <iframe>, <object>, <embed>, <track>, <input type="image">, <area>
        for tag in soup.find_all("iframe", src=True):
            self._add(tag["src"], base)
        for tag in soup.find_all("object", data=True):
            self._add(tag["data"], base)
        for tag in soup.find_all("embed", src=True):
            self._add(tag["src"], base)
        for tag in soup.find_all("track", src=True):
            self._add(tag["src"], base)
        for tag in soup.find_all("input", src=True):
            if tag.get("type", "").lower() == "image":
                self._add(tag["src"], base)
        for tag in soup.find_all("area", href=True):
            self._add(tag["href"], base)
        for tag in soup.find_all("form", action=True):
            self._add(tag["action"], base)

        # <meta> og/twitter
        for tag in soup.find_all("meta"):
            prop = tag.get("property", "") or tag.get("name", "")
            if prop.lower() in (
                "og:image", "og:image:url", "og:image:secure_url",
                "og:video", "og:audio",
                "twitter:image", "twitter:image:src",
                "twitter:player:stream",
            ):
                content = tag.get("content")
                if content:
                    self._add(content, base)

        # Generic modern frontend lazy attributes on any tag
        for tag in soup.find_all(True):
            for attr in (
                "data-src", "data-background", "data-lazy", "data-original",
                "data-lazy-src", "data-href", "data-url", "data-bg", "data-poster", "data-image"
            ):
                val = tag.get(attr)
                if val:
                    self._add(val, base)

            # Inline style attribute scanning
            style = tag.get("style")
            if style:
                self._scan_css(style, base)

        # Inline <script> & JSON-LD
        for tag in soup.find_all("script"):
            type_attr = (tag.get("type") or "").lower()
            if "application/ld+json" in type_attr and tag.string:
                try:
                    ld_data = json.loads(tag.string)
                    self._extract_jsonld_urls(ld_data, base)
                except Exception:
                    pass
            elif tag.string:
                self._scan_js(tag.string, base)

        # Inline <style>
        for tag in soup.find_all("style"):
            if tag.string:
                self._scan_css(tag.string, base)

    def _extract_jsonld_urls(self, data: Any, base: str) -> None:
        """Recursively scan JSON-LD objects for image, url, contentUrl, etc."""
        if isinstance(data, dict):
            for k, v in data.items():
                if k.lower() in ("url", "image", "contenturl", "thumbnailurl", "logo") and isinstance(v, str):
                    self._add(v, base)
                else:
                    self._extract_jsonld_urls(v, base)
        elif isinstance(data, list):
            for item in data:
                self._extract_jsonld_urls(item, base)

    # ------------------------------------------------------------------
    # Phase 2b: Recursive crawling
    # ------------------------------------------------------------------

    async def _recursive_crawl(self, session: aiohttp.ClientSession) -> None:
        """Follow <a href> links up to settings.depth levels with concurrency and AutoThrottle."""
        proxy = self._settings.proxy or None
        current_urls = self._extract_page_links(self._root_html, self._base_url)
        origin_parsed = urlparse(self._origin)
        sem = asyncio.Semaphore(max(1, self._settings.workers))

        for depth in range(2, self._settings.depth + 1):
            if self._is_cancelled():
                return

            self._emit_log(f"Crawl depth {depth}: {len(current_urls)} pages to visit")
            next_urls: Set[str] = set()

            async def crawl_page(page_url: str):
                if self._is_cancelled() or page_url in self._visited_pages:
                    return
                if self._pages_crawled >= self._settings.max_files:
                    return
                if not self._is_robot_allowed(page_url):
                    return
                page_parsed = urlparse(page_url)
                if self._settings.same_origin_only:
                    if page_parsed.netloc.lower() != origin_parsed.netloc.lower():
                        return
                else:
                    # Guard against uncontrolled internet escape
                    origin_host = origin_parsed.netloc.lower().split(":")[0]
                    page_host = page_parsed.netloc.lower().split(":")[0]
                    if not (page_host == origin_host or page_host.endswith("." + origin_host)):
                        return

                self._visited_pages.add(page_url)
                page_domain = page_parsed.netloc.lower()

                async with sem:
                    if self._is_cancelled():
                        return
                    # Per-domain pacing lock
                    async with self._domain_locks[page_domain]:
                        last_time = self._domain_last_request.get(page_domain, 0.0)
                        d = self._throttle.delay_for(page_domain, floor=self._settings.delay)
                        elapsed = time.time() - last_time
                        if elapsed < d:
                            await asyncio.sleep(d - elapsed)
                        self._domain_last_request[page_domain] = time.time()

                        t0 = time.time()
                        try:
                            async with session.get(page_url, proxy=proxy) as resp:
                                latency = time.time() - t0
                                await self._throttle.record(
                                    page_domain, latency, resp.status,
                                    dict(resp.headers), floor=self._settings.delay
                                )
                                if resp.status != 200:
                                    return
                                ct = resp.headers.get("Content-Type", "")
                                if "text/html" not in ct.lower():
                                    self._add(page_url, self._base_url)
                                    return
                                page_html = await resp.text(errors="replace")
                                page_headers = {k: v for k, v in resp.headers.items()}
                        except Exception as exc:
                            self._emit_log(f"Crawl error {page_url}: {exc}")
                            return

                self._pages_crawled += 1

                # Save the page
                page_path = _sanitize_path(page_url, self._settings.output_dir)
                try:
                    parent_dir = os.path.dirname(page_path)
                    if os.path.exists(parent_dir) and not os.path.isdir(parent_dir):
                        try:
                            os.rename(parent_dir, parent_dir + "_content.html")
                        except OSError:
                            pass
                    os.makedirs(parent_dir, exist_ok=True)
                    with open(page_path, "w", encoding="utf-8", errors="replace") as f:
                        f.write(page_html)
                except OSError as exc:
                    self._emit_log(f"Failed to write {page_path}: {exc}")
                    return

                page_size = len(page_html.encode("utf-8", errors="replace"))
                self._results.append(FileResult(
                    url=page_url, status=200, size=page_size,
                    content_type=ct, local_path=page_path,
                    response_headers=page_headers,
                ))
                self._downloaded_count += 1
                self._total_bytes += page_size

                # Parse for assets and deeper links
                self._parse_html_content(page_html, page_url)
                extracted = self._extract_page_links(page_html, page_url)
                next_urls.update(extracted)
                self._emit_log(f"Crawled: {page_url}")

            tasks = [crawl_page(u) for u in current_urls if u not in self._visited_pages]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

            current_urls = next_urls - self._visited_pages
            if not current_urls:
                break

        self._emit_log(f"Recursive crawl complete: {self._pages_crawled} pages")

    def _extract_page_links(self, html: str, base_url: str) -> Set[str]:
        """Extract <a href> links from HTML."""
        links: Set[str] = set()
        try:
            soup = BeautifulSoup(html, "lxml")
            for tag in soup.find_all("a", href=True):
                href = (tag.get("href") or "").strip()
                if not href or href.startswith("#"):
                    continue
                href_lower = href.lower()
                if href_lower.startswith(("javascript:", "mailto:", "tel:", "callto:", "sms:", "blob:", "data:")):
                    continue
                normalized = _normalize_url(href, base_url)
                if normalized:
                    links.add(normalized)
        except Exception:
            pass
        return links

    # ------------------------------------------------------------------
    # JS / CSS content scanners
    # ------------------------------------------------------------------

    def _spawn_source_map_task(self, decoded: str, base: str) -> None:
        """Create and track an asynchronous source map decoding task to prevent memory/lifecycle leaks."""
        task = asyncio.create_task(self._handle_source_map(decoded, base))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    def _scan_js(self, text: str, base: str) -> None:
        """Scan JavaScript text for URLs."""
        for pat in (
            _RE_JS_IMPORT_FROM,
            _RE_JS_IMPORT_BARE,
            _RE_JS_DYNAMIC_IMPORT,
            _RE_JS_REQUIRE,
            _RE_JS_FETCH,
        ):
            for m in pat.finditer(text):
                self._add(m.group(1), base)

        for m in _RE_JS_SOURCEMAP.finditer(text):
            sm_val = m.group(1).strip()
            if sm_val.startswith("data:application/json") and "base64," in sm_val:
                import base64
                try:
                    b64_data = sm_val.split("base64,", 1)[1]
                    decoded = base64.b64decode(b64_data).decode("utf-8", errors="replace")
                    self._spawn_source_map_task(decoded, base)
                except Exception:
                    pass
            else:
                self._add(sm_val, base)

        for m in _RE_JS_ASSET_URL.finditer(text):
            candidate = m.group(1)
            if "/" in candidate or candidate.startswith("."):
                self._add(candidate, base)
            elif ASSET_EXTENSIONS.search(candidate):
                self._add(candidate, base)

        # JS redirects (window.location, location.href, location.replace)
        for m in re.finditer(r"""(?:window\.location|location\.href|location\.replace|location\.assign)\s*(?:=|\()\s*['"`]([^'"`]+)['"`]""", text, re.I):
            self._add(m.group(1), base)

        # Common API paths in JS code (/api/..., /v1/..., /graphql...)
        for m in re.finditer(r"""['"`]((?:/api/|/v[1-9]/|/graphql)[^'"`\s\\]+)['"`]""", text, re.I):
            self._add(m.group(1), base)

    def _scan_css(self, text: str, base: str) -> None:
        """Scan CSS text for url() references and @import directives."""
        for m in _RE_CSS_URL.finditer(text):
            val = m.group(1).strip()
            if not val.startswith("data:"):
                self._add(val, base)

        for m in _RE_CSS_IMPORT.finditer(text):
            val = m.group(1) or m.group(2)
            if val:
                self._add(val.strip(), base)

        for m in _RE_CSS_SOURCEMAP.finditer(text):
            sm_val = m.group(1).strip()
            if sm_val.startswith("data:application/json") and "base64," in sm_val:
                import base64
                try:
                    b64_data = sm_val.split("base64,", 1)[1]
                    decoded = base64.b64decode(b64_data).decode("utf-8", errors="replace")
                    self._spawn_source_map_task(decoded, base)
                except Exception:
                    pass
            else:
                self._add(sm_val, base)

    # ------------------------------------------------------------------
    # Phase 5: Probe well-known paths
    # ------------------------------------------------------------------

    async def _probe_well_known(self, session: aiohttp.ClientSession) -> None:
        """HEAD-probe well-known paths, add those returning 200."""
        proxy = self._settings.proxy or None
        for path in WELL_KNOWN_PATHS:
            if self._is_cancelled():
                return
            probe_url = urljoin(self._origin + "/", path.lstrip("/"))
            try:
                async with session.head(probe_url, allow_redirects=True, proxy=proxy) as resp:
                    if resp.status == 200:
                        self._discovered.add(probe_url)
                        self._emit_log(f"Found well-known: {path}")
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Phase 6-7: Deep scan & source maps
    # ------------------------------------------------------------------

    async def _deep_scan(self, session: aiohttp.ClientSession) -> None:
        """Fetch discovered JS/CSS files and scan them for more URLs."""
        to_scan = [u for u in list(self._discovered) if self._is_scannable(u)]
        scanned: Set[str] = set()
        for _pass in range(2):
            batch = [u for u in to_scan if u not in scanned]
            if not batch:
                break
            for url in batch:
                if self._is_cancelled():
                    return
                scanned.add(url)
                try:
                    content = await self._fetch_text(session, url)
                    if content is None:
                        continue
                    path_lower = urlparse(url).path.lower()
                    if path_lower.endswith((".js", ".mjs", ".cjs")):
                        self._scan_js(content, url)
                    elif path_lower.endswith(".css"):
                        self._scan_css(content, url)
                    if path_lower.endswith(".map"):
                        await self._handle_source_map(content, url)
                except Exception as exc:
                    self._emit_log(f"Deep scan error for {url}: {exc}")

            to_scan = [
                u for u in list(self._discovered)
                if self._is_scannable(u) and u not in scanned
            ]

        if self._background_tasks:
            await asyncio.gather(*list(self._background_tasks), return_exceptions=True)

    @staticmethod
    def _is_scannable(url: str) -> bool:
        lower = urlparse(url).path.lower()
        return lower.endswith((".js", ".mjs", ".cjs", ".css", ".map"))

    async def _fetch_text(
        self, session: aiohttp.ClientSession, url: str
    ) -> Optional[str]:
        proxy = self._settings.proxy or None
        max_scan_size = 10 * 1024 * 1024  # 10MB safety cap for scannable assets
        try:
            async with session.get(url, proxy=proxy) as resp:
                if resp.status != 200:
                    return None
                cl = resp.headers.get("Content-Length")
                if cl and int(cl) > max_scan_size:
                    return None
                sm_hdr = resp.headers.get("SourceMap") or resp.headers.get("X-SourceMap")
                if sm_hdr:
                    self._add(sm_hdr.strip(), url)
                chunks = []
                total = 0
                async for chunk in resp.content.iter_chunked(65536):
                    total += len(chunk)
                    if total > max_scan_size:
                        return None
                    chunks.append(chunk)
                return b"".join(chunks).decode("utf-8", errors="replace")
        except Exception:
            return None

    async def _handle_source_map(self, content: str, map_url: str) -> None:
        """Parse a source map JSON; save embedded sourcesContent to disk."""
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return

        sources = data.get("sources", [])
        sources_content = data.get("sourcesContent", [])
        if not sources_content:
            for src in sources:
                self._add(src, map_url)
            return

        for src_path, src_text in zip(sources, sources_content):
            if src_text is None:
                continue
            resolved = _normalize_url(src_path, map_url)
            if resolved:
                local = _sanitize_path(resolved, self._settings.output_dir)
            else:
                safe_name = _WINDOWS_RESERVED.sub("_", src_path).replace("..", "_").lstrip("/\\")
                parsed_map = urlparse(map_url)
                host = _WINDOWS_RESERVED.sub("_", parsed_map.netloc or "unknown")
                base_out = Path(self._settings.output_dir, host, "_sourcemap").resolve()
                target_path = (base_out / safe_name).resolve()
                try:
                    target_path.relative_to(base_out)
                except ValueError:
                    import hashlib
                    h = hashlib.sha256(src_path.encode("utf-8", errors="replace")).hexdigest()[:12]
                    target_path = base_out / f"safe_src_{h}.txt"
                local = str(target_path)

            try:
                os.makedirs(os.path.dirname(local), exist_ok=True)
                with open(local, "w", encoding="utf-8", errors="replace") as f:
                    f.write(src_text)
                size = len(src_text.encode("utf-8", errors="replace"))
                self._results.append(
                    FileResult(
                        url=src_path,
                        status=200,
                        size=size,
                        content_type="text/plain",
                        local_path=local,
                    )
                )
                self._downloaded_count += 1
                self._total_bytes += size
            except Exception as exc:
                self._emit_log(f"Failed to save source map entry {src_path}: {exc}")

    # ------------------------------------------------------------------
    # Phase 8: Dynamic browser capture (Stealth Playwright + Network Recorder)
    # ------------------------------------------------------------------

    async def _dynamic_capture(self) -> None:
        """Use Playwright with hardened stealth, Shadow DOM extraction and API recording."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            self._emit_log(
                "Playwright not installed — skipping dynamic capture. "
                "Install with: pip install playwright && playwright install chromium"
            )
            return

        from .dependencies import _get_default_browser_dir
        browser_path = str(_get_default_browser_dir())
        if os.path.isdir(browser_path):
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = browser_path

        captured: Set[str] = set()

        try:
            async with async_playwright() as pw:
                launch_options: Dict[str, Any] = {
                    "headless": True,
                    "args": STEALTH_CHROMIUM_ARGS,
                }
                if self._settings.proxy:
                    launch_options["proxy"] = {"server": self._settings.proxy}

                browser = None
                context = None
                page = None
                try:
                    browser = await self._launch_browser(pw, launch_options)

                    headers = generate_browser_headers(
                        user_agent=self._settings.user_agent,
                        custom_headers=self._settings.custom_headers,
                    )
                    if self._settings.auth_token:
                        headers["Authorization"] = f"Bearer {self._settings.auth_token}"

                    context = await browser.new_context(
                        viewport={"width": 1920, "height": 1080},
                        user_agent=headers.get("User-Agent"),
                        extra_http_headers=headers,
                        ignore_https_errors=True,
                    )

                    # Inject stealth anti-fingerprinting and shadow DOM crawler
                    await context.add_init_script(script=STEALTH_INIT_SCRIPT)

                    # Inject custom & auth cookies
                    cookies_to_add = []
                    domain = urlparse(self._base_url).hostname or ""
                    all_cookie_str = "; ".join(filter(None, [self._settings.custom_cookies, self._settings.auth_cookie]))
                    if all_cookie_str and domain:
                        from http.cookies import SimpleCookie
                        sc = SimpleCookie()
                        try:
                            sc.load(all_cookie_str)
                            is_ip_or_local = domain in ("localhost", "127.0.0.1", "::1") or bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", domain))
                            for k, morsel in sc.items():
                                cookie_obj = {
                                    "name": k,
                                    "value": morsel.value,
                                    "path": morsel.get("path") or "/",
                                }
                                if is_ip_or_local:
                                    cookie_obj["url"] = self._base_url
                                else:
                                    cookie_obj["domain"] = domain
                                cookies_to_add.append(cookie_obj)
                            if cookies_to_add:
                                await context.add_cookies(cookies_to_add)
                        except Exception as e:
                            self._emit_log(f"Cookie note: {e}")

                    page = await context.new_page()

                    # Response listener for asset discovery and API capture
                    async def _on_response(response) -> None:
                        try:
                            u = response.url
                            if not u or urlparse(u).scheme not in ("http", "https"):
                                return
                            if is_ad_or_tracker(u):
                                return
                            captured.add(u)

                            ct = response.headers.get("content-type", "").lower()
                            status = response.status
                            req = response.request
                            method = req.method
                            res_type = req.resource_type

                            body_preview = ""
                            if "application/json" in ct or "/api/" in u or "/graphql" in u:
                                try:
                                    body_bytes = await response.body()
                                    body_preview = body_bytes[:4000].decode("utf-8", errors="replace")
                                except Exception:
                                    pass

                            rec_id = self._network_recorder.record_response(
                                url=u, method=method, status=status,
                                resource_type=res_type, content_type=ct,
                                post_data=req.post_data or "",
                                response_preview=body_preview,
                                headers=dict(response.headers),
                            )
                            rec = self._network_recorder._records.get(rec_id)
                            if rec:
                                self._captured_requests.append(rec)
                            if len(self._captured_requests) > self._network_recorder.max_records:
                                self._captured_requests = self._captured_requests[-self._network_recorder.max_records:]
                        except Exception:
                            pass

                    page.on("response", _on_response)

                    if self._is_cancelled():
                        return

                    # Navigate to root page
                    try:
                        await page.goto(
                            self._base_url,
                            wait_until="domcontentloaded",
                            timeout=min(self._settings.timeout * 1000, 30000),
                        )
                    except Exception as e:
                        self._emit_log(f"Navigation note: {e}")

                    if self._is_cancelled():
                        return

                    # Wait up to 5s for network idle
                    try:
                        await page.wait_for_load_state("networkidle", timeout=5000)
                    except Exception:
                        pass

                    if self._is_cancelled():
                        return

                    # Auto-scroll to trigger lazy loading / IntersectionObservers
                    try:
                        await page.evaluate("""
                            async () => {
                                await new Promise((resolve) => {
                                    let totalHeight = 0;
                                    const distance = 400;
                                    const timer = setInterval(() => {
                                        const scrollHeight = document.body ? document.body.scrollHeight : 1000;
                                        window.scrollBy(0, distance);
                                        totalHeight += distance;
                                        if (totalHeight >= scrollHeight || totalHeight > 8000) {
                                            clearInterval(timer);
                                            resolve();
                                        }
                                    }, 80);
                                });
                            }
                        """)
                        await asyncio.sleep(0.5)
                    except Exception:
                        pass

                    if self._is_cancelled():
                        return

                    # Extract URLs from Shadow DOM
                    try:
                        shadow_urls = await page.evaluate(
                            "window.__extract_shadow_dom_urls ? window.__extract_shadow_dom_urls() : []"
                        )
                        for s_url in shadow_urls:
                            norm = _normalize_url(s_url, page.url)
                            if norm:
                                captured.add(norm)
                    except Exception:
                        pass

                    # Parse dynamic rendered HTML content
                    try:
                        rendered_html = await page.content()
                        if rendered_html:
                            self._parse_html_content(rendered_html, page.url)
                    except Exception:
                        pass

                finally:
                    if page:
                        try:
                            await page.close()
                        except Exception:
                            pass
                    if context:
                        try:
                            await context.close()
                        except Exception:
                            pass
                    if browser:
                        try:
                            await browser.close()
                        except Exception:
                            pass

            before = len(self._discovered)
            for url in captured:
                normalized = _normalize_url(url, self._base_url)
                if normalized:
                    if is_ad_or_tracker(normalized):
                        continue
                    self._discovered.add(normalized)
            new_count = len(self._discovered) - before
            self._emit_log(
                f"Stealth capture found {len(captured)} requests "
                f"({len(self._captured_requests)} APIs recorded, {new_count} new URLs)"
            )
        except Exception as exc:
            self._emit_log(f"Dynamic capture error (continuing): {exc}")

    # ------------------------------------------------------------------
    # Phase 9: Deduplicate & filter
    # ------------------------------------------------------------------

    def _filter_urls(self) -> List[str]:
        """Apply same-origin, external filters, tracker filters, and max_files cap."""
        origin_parsed = urlparse(self._origin)
        origin_netloc = origin_parsed.netloc.lower()
        filtered: list[str] = []
        for url in sorted(self._discovered):
            parsed = urlparse(url)
            if self._settings.same_origin_only:
                if parsed.netloc.lower() != origin_netloc:
                    if not self._settings.include_external:
                        continue
            # Drop known ad/tracker telemetry domains unless explicitly allowed
            if not self._settings.include_external and is_ad_or_tracker(url):
                continue
            # Check robots.txt
            if not self._is_robot_allowed(url):
                continue
            filtered.append(url)

        if len(filtered) > self._settings.max_files:
            self._emit_log(
                f"Capping downloads from {len(filtered)} to "
                f"{self._settings.max_files}"
            )
            filtered = filtered[: self._settings.max_files]

        return filtered

    # ------------------------------------------------------------------
    # Phase 10: Download all assets (concurrent + AutoThrottle)
    # ------------------------------------------------------------------

    async def _download_all(
        self, session: aiohttp.ClientSession, urls: List[str]
    ) -> None:
        """Download URLs concurrently with adaptive AutoThrottle rate limiting and bounded task queue."""
        if not urls:
            return
        total = len(urls) + self._downloaded_count
        worker_count = min(max(1, self._settings.workers), len(urls))
        queue: asyncio.Queue[str] = asyncio.Queue()
        for u in urls:
            queue.put_nowait(u)

        async def _worker() -> None:
            while not self._is_cancelled():
                try:
                    url = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

                domain = urlparse(url).netloc.lower()

                # Per-domain pacing lock — reserve timing slot
                async with self._domain_locks[domain]:
                    last_time = self._domain_last_request.get(domain, 0.0)
                    d = self._throttle.delay_for(domain, floor=self._settings.delay)
                    elapsed = time.time() - last_time
                    if elapsed < d:
                        await asyncio.sleep(d - elapsed)
                    self._domain_last_request[domain] = time.time()

                # Perform actual network download OUTSIDE lock for true worker concurrency
                result = await self._download_one(session, url)

                self._results.append(result)
                queue.task_done()

                if result.error:
                    self._failed_count += 1
                    self._callback(
                        ProgressEvent(
                            event_type=EventType.FILE_FAILED,
                            message=f"Failed: {url} — {result.error}",
                            downloaded=self._downloaded_count,
                            failed=self._failed_count,
                            total=total,
                        )
                    )
                else:
                    self._downloaded_count += 1
                    self._total_bytes += result.size
                    self._callback(
                        ProgressEvent(
                            event_type=EventType.FILE_DOWNLOADED,
                            message=(
                                f"Downloaded: {url} "
                                f"({_format_size(result.size)})"
                            ),
                            downloaded=self._downloaded_count,
                            failed=self._failed_count,
                            total=total,
                        )
                    )

        tasks = [asyncio.create_task(_worker()) for _ in range(worker_count)]
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

    async def _download_one(
        self, session: aiohttp.ClientSession, url: str
    ) -> FileResult:
        """Download a single URL to disk with AutoThrottle and exponential rate-limit backoff."""
        local_path = _sanitize_path(url, self._settings.output_dir)
        proxy = self._settings.proxy or None
        domain = urlparse(url).netloc.lower()

        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                t0 = time.time()
                async with session.get(url, proxy=proxy) as resp:
                    latency = time.time() - t0
                    await self._throttle.record(
                        domain, latency, resp.status, dict(resp.headers), floor=self._settings.delay
                    )

                    if resp.status in (429, 503) and attempt < max_attempts - 1:
                        retry_after = parse_retry_after(dict(resp.headers))
                        if retry_after is not None and retry_after > 0:
                            wait_sec = min(retry_after, 15.0)
                        else:
                            import random
                            wait_sec = min((2.0 ** (attempt + 1)) + random.uniform(0.1, 0.5), 15.0)
                        self._emit_log(f"Rate limited on {url} (HTTP {resp.status}) — backing off {wait_sec:.1f}s (attempt {attempt+1}/{max_attempts})")
                        await asyncio.sleep(wait_sec)
                        continue

                    if resp.status != 200:
                        return FileResult(
                            url=url,
                            status=resp.status,
                            error=f"HTTP {resp.status}",
                        )

                    content_type = resp.headers.get("Content-Type", "")
                    resp_headers = {k: v for k, v in resp.headers.items()}
                    max_file_size = 100 * 1024 * 1024  # 100MB safety cap

                    content_length = resp.headers.get("Content-Length")
                    if content_length and int(content_length) > max_file_size:
                        return FileResult(
                            url=url,
                            status=resp.status,
                            error=f"File exceeds max size limit ({content_length} bytes)",
                        )

                    parent_dir = os.path.dirname(local_path)
                    if os.path.exists(parent_dir) and not os.path.isdir(parent_dir):
                        try:
                            os.rename(parent_dir, parent_dir + "_content.html")
                        except OSError:
                            pass
                    os.makedirs(parent_dir, exist_ok=True)
                    if os.path.isdir(local_path):
                        local_path = os.path.join(local_path, "index.html")

                    size = 0
                    with open(local_path, "wb") as f:
                        async for chunk in resp.content.iter_chunked(65536):
                            size += len(chunk)
                            if size > max_file_size:
                                try:
                                    f.close()
                                    if os.path.exists(local_path):
                                        os.remove(local_path)
                                except OSError:
                                    pass
                                return FileResult(
                                    url=url,
                                    status=resp.status,
                                    error="File exceeded max size limit",
                                )
                            f.write(chunk)

                    return FileResult(
                        url=url,
                        status=200,
                        size=size,
                        content_type=content_type,
                        local_path=local_path,
                        response_headers=resp_headers,
                    )

            except asyncio.TimeoutError:
                return FileResult(url=url, error="Timeout")
            except aiohttp.ClientSSLError as exc:
                return FileResult(url=url, error=f"SSL error: {exc}")
            except aiohttp.ClientError as exc:
                return FileResult(url=url, error=f"Network error: {exc}")
            except OSError as exc:
                return FileResult(url=url, error=f"File write error: {exc}")
            except Exception as exc:
                return FileResult(url=url, error=str(exc))

        return FileResult(url=url, error="Rate limited after retry")

    # ------------------------------------------------------------------
    # Phase 11: Write report.json
    # ------------------------------------------------------------------

    def _write_report(self, report: RipReport) -> None:
        try:
            if self._settings.output_dir:
                os.makedirs(self._settings.output_dir, exist_ok=True)
                report_path = os.path.join(self._settings.output_dir, "report.json")
            else:
                report_path = "report.json"
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report.to_json(indent=2))
            self._emit_log(f"Report saved to {report_path}")
        except Exception as exc:
            self._emit_log(f"Failed to write report: {exc}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _add(self, raw_url: str, base: str) -> None:
        normalized = _normalize_url(raw_url, base)
        if normalized:
            if not self._settings.include_external and is_ad_or_tracker(normalized):
                return
            self._discovered.add(normalized)

    def _is_cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def _emit_phase(self, phase: str) -> None:
        self._callback(
            ProgressEvent(
                event_type=EventType.PHASE_CHANGE,
                message=phase,
                downloaded=self._downloaded_count,
                failed=self._failed_count,
                total=len(self._discovered),
                phase=phase,
            )
        )

    def _emit_log(self, message: str) -> None:
        logger.info(message)
        self._callback(
            ProgressEvent(
                event_type=EventType.LOG,
                message=message,
                downloaded=self._downloaded_count,
                failed=self._failed_count,
                total=len(self._discovered),
            )
        )

    def _build_report(
        self, start: datetime, *, cancelled: bool = False
    ) -> RipReport:
        return RipReport(
            url=self._base_url,
            start_time=start.isoformat(),
            end_time=datetime.now(timezone.utc).isoformat(),
            settings=self._settings.to_dict(),
            files=list(self._results),
            total_downloaded=self._downloaded_count,
            total_failed=self._failed_count,
            total_size=self._total_bytes,
            pages_crawled=self._pages_crawled,
            captured_requests=list(self._captured_requests),
        )

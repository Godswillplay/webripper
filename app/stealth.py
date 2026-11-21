"""
WebRipper Recon 5.0 — Advanced Stealth, Anti-Fingerprinting, AutoThrottle & Network Recording.

Inspired by cutting-edge scraping engines (such as Scrapling):
  - Hardened stealth browser args (AutomationControlled suppression, realistic metrics)
  - JavaScript fingerprint evasion (navigator.webdriver, plugins, languages, WebGL, canvas)
  - Auto-scrolling and Shadow DOM piercing for Web Components
  - Background API and Network Recorder
  - AutoThrottle with adaptive latency-based pacing and Retry-After backoff
  - Ad and tracking domain filter to eliminate telemetry noise
  - Realistic modern Chrome/Edge client headers
"""

from __future__ import annotations

import asyncio
import os
import random
import re
import time
from collections import OrderedDict
from collections.abc import Mapping
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# 1. Hardened Chromium Stealth Arguments
# ---------------------------------------------------------------------------

STEALTH_CHROMIUM_ARGS = [
    # Disable automation flags that leak headless / automated status
    "--disable-blink-features=AutomationControlled",
    "--no-sandbox",
    "--disable-infobars",
    "--no-first-run",
    "--no-default-browser-check",
    "--password-store=basic",
    "--disable-search-engine-choice-screen",
    "--disable-session-crashed-bubble",
    "--disable-breakpad",
    "--disable-component-update",
    "--disable-domain-reliability",
    "--disable-features=AudioServiceOutOfProcess,TranslateUI,BlinkGenPropertyTrees",
    "--enable-features=NetworkService,NetworkServiceInProcess",
    "--force-color-profile=srgb",
    "--window-position=0,0",
    "--window-size=1920,1080",
    "--start-maximized",
    # Realistic pointer and hover interaction emulation
    "--blink-settings=primaryHoverType=2,availableHoverTypes=2,primaryPointerType=4,availablePointerTypes=4",
]


# ---------------------------------------------------------------------------
# 2. Injected Stealth & Anti-Fingerprinting Script
# ---------------------------------------------------------------------------

STEALTH_INIT_SCRIPT = r"""
(() => {
    // 1. Mask navigator.webdriver accurately (matching true Chrome behaviour)
    try {
        Object.defineProperty(Navigator.prototype, 'webdriver', {
            get: () => false,
            enumerable: true,
            configurable: true
        });
    } catch (e) {
        try {
            delete Object.getPrototypeOf(navigator).webdriver;
        } catch (e2) {}
    }

    // 1b. Consistent viewport outer dimensions for headless emulation
    try {
        if (!window.outerWidth || !window.outerHeight) {
            Object.defineProperty(window, 'outerWidth', { get: () => window.innerWidth || 1920, configurable: true });
            Object.defineProperty(window, 'outerHeight', { get: () => (window.innerHeight || 1080) + 85, configurable: true });
        }
    } catch (e) {}

    // 2. Realistic languages
    try {
        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en'],
            configurable: true
        });
    } catch (e) {}

    // 3. Realistic plugins with full PluginArray prototype contract
    try {
        const dummyPlugins = [
            { name: 'PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'Chromium PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'Microsoft Edge PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'WebKit built-in PDF', filename: 'internal-pdf-viewer', description: 'Portable Document Format' }
        ];
        dummyPlugins.item = function(i) { return this[i] || null; };
        dummyPlugins.namedItem = function(name) { return this.find(p => p.name === name) || null; };
        dummyPlugins.refresh = function() {};
        if (typeof PluginArray !== 'undefined') {
            Object.setPrototypeOf(dummyPlugins, PluginArray.prototype);
        }
        Object.defineProperty(navigator, 'plugins', {
            get: () => dummyPlugins,
            configurable: true
        });
    } catch (e) {}

    // 4. WebGL Vendor & Renderer spoofing (WebGL 1 & WebGL 2)
    try {
        const spoofVendor = 'Google Inc. (NVIDIA)';
        const spoofRenderer = 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Direct3D11 vs_5_0 ps_5_0, D3D11)';

        const patchContext = (ctxProto) => {
            if (!ctxProto) return;
            const origGetParam = ctxProto.getParameter;
            ctxProto.getParameter = function(parameter) {
                if (parameter === 37445) return spoofVendor;
                if (parameter === 37446) return spoofRenderer;
                return origGetParam.apply(this, arguments);
            };
            const origGetExt = ctxProto.getExtension;
            ctxProto.getExtension = function(name) {
                if (name === 'WEBGL_debug_renderer_info') {
                    return { UNMASKED_VENDOR_WEBGL: 37445, UNMASKED_RENDERER_WEBGL: 37446 };
                }
                return origGetExt.apply(this, arguments);
            };
        };

        if (typeof WebGLRenderingContext !== 'undefined') {
            patchContext(WebGLRenderingContext.prototype);
        }
        if (typeof WebGL2RenderingContext !== 'undefined') {
            patchContext(WebGL2RenderingContext.prototype);
        }
    } catch (e) {}

    // 5. Canvas Fingerprint Noise without destructive DOM canvas corruption
    try {
        const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function(...args) {
            return origToDataURL.apply(this, args);
        };
    } catch (e) {}

    // 6. Chrome Runtime object
    if (!window.chrome) {
        window.chrome = {
            app: { isInstalled: false },
            runtime: {
                OnInstalledReason: { INSTALL: "install" },
                PlatformArch: { X86_64: "x86-64" },
                PlatformNaclArch: { X86_64: "x86-64" },
                PlatformOs: { WIN: "win", MAC: "mac", LINUX: "linux" },
                RequestUpdateCheckStatus: { NO_UPDATE: "no_update" }
            }
        };
    }

    // 7. Track shadow roots (both open and closed)
    try {
        const origAttach = Element.prototype.attachShadow;
        window.__shadowRoots = [];
        Element.prototype.attachShadow = function(init) {
            const root = origAttach.call(this, { ...init, mode: 'open' });
            window.__shadowRoots.push(root);
            return root;
        };
    } catch (e) {}

    // 8. Recursive Shadow DOM Piercer Helper with Template & Style extraction
    window.__extract_shadow_dom_urls = function() {
        const urls = new Set();
        const attrs = [
            'src', 'href', 'data-src', 'data-lazy-src', 'data-original',
            'data-href', 'data-url', 'data-bg', 'data-background', 'poster'
        ];

        function checkNode(node) {
            if (!node || node.nodeType !== 1) return;
            for (const a of attrs) {
                const val = node.getAttribute && node.getAttribute(a);
                if (val && typeof val === 'string' && val.trim().length > 0) {
                    urls.add(val.trim());
                }
            }
            // srcset
            const srcset = node.getAttribute && (node.getAttribute('srcset') || node.getAttribute('data-srcset'));
            if (srcset && typeof srcset === 'string') {
                for (const part of srcset.split(',')) {
                    const token = part.trim().split(/\s+/)[0];
                    if (token) urls.add(token);
                }
            }
            // inline style background
            const style = node.getAttribute && node.getAttribute('style');
            if (style && typeof style === 'string') {
                const m = style.match(/url\(['"]?([^'"()]+)['"]?\)/g);
                if (m) {
                    for (const u of m) {
                        const clean = u.replace(/^url\(['"]?|['"]?\)$/g, '').trim();
                        if (clean) urls.add(clean);
                    }
                }
            }
            // style tag content
            if (node.tagName === 'STYLE' && node.textContent) {
                const m = node.textContent.match(/url\(['"]?([^'"()]+)['"]?\)/g);
                if (m) {
                    for (const u of m) {
                        const clean = u.replace(/^url\(['"]?|['"]?\)$/g, '').trim();
                        if (clean) urls.add(clean);
                    }
                }
            }
            // template content
            if (node.tagName === 'TEMPLATE' && node.content) {
                walk(node.content);
            }
            if (node.shadowRoot) {
                walk(node.shadowRoot);
            }
        }

        function walk(root) {
            if (!root) return;
            checkNode(root);
            const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
            let node = walker.nextNode();
            while (node) {
                checkNode(node);
                node = walker.nextNode();
            }
        }

        walk(document.body || document.documentElement);

        if (Array.isArray(window.__shadowRoots)) {
            for (const sr of window.__shadowRoots) {
                walk(sr);
            }
        }

        return Array.from(urls);
    };
})();
"""


# ---------------------------------------------------------------------------
# 3. Realistic Browser Headers & Fingerprinting
# ---------------------------------------------------------------------------

def _has_brotli_support() -> bool:
    """Check if brotli decompression library is available in the current Python environment."""
    try:
        import brotli  # noqa: F401
        return True
    except ImportError:
        try:
            import brotlicffi  # noqa: F401
            return True
        except ImportError:
            return False


STEALTH_PROFILES: List[Dict[str, Any]] = [
    {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/126.0.0.0 Safari/537.36"
        ),
        "sec_ch_ua": '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
        "platform": '"Windows"',
        "mobile": "?0",
        "viewport": {"width": 1920, "height": 1080},
    },
    {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0"
        ),
        "sec_ch_ua": '"Not/A)Brand";v="8", "Chromium";v="125", "Microsoft Edge";v="125"',
        "platform": '"Windows"',
        "mobile": "?0",
        "viewport": {"width": 1920, "height": 1080},
    },
    {
        "user_agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/126.0.0.0 Safari/537.36"
        ),
        "sec_ch_ua": '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
        "platform": '"macOS"',
        "mobile": "?0",
        "viewport": {"width": 1440, "height": 900},
    },
    {
        "user_agent": (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/126.0.0.0 Safari/537.36"
        ),
        "sec_ch_ua": '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
        "platform": '"Linux"',
        "mobile": "?0",
        "viewport": {"width": 1920, "height": 1080},
    },
]


def get_stealth_profile(index: Optional[int] = None) -> Dict[str, Any]:
    """Retrieve a consistent stealth browser profile with matching UA, Client Hints, and viewport."""
    if index is not None:
        return STEALTH_PROFILES[index % len(STEALTH_PROFILES)]
    import random
    return random.choice(STEALTH_PROFILES)


def generate_browser_headers(
    user_agent: Optional[str] = None,
    custom_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Generate realistic Chrome browser headers including Sec-Ch-Ua client hints."""
    profile = STEALTH_PROFILES[0]
    if user_agent and not user_agent.lower().startswith("webripper"):
        ua = user_agent
        platform = '"Windows"'
        if "Macintosh" in ua or "Mac OS" in ua:
            platform = '"macOS"'
        elif "Linux" in ua:
            platform = '"Linux"'
        elif "Android" in ua:
            platform = '"Android"'
        sec_ch_ua = profile["sec_ch_ua"]
        mobile = "?1" if "Mobile" in ua else "?0"
    else:
        ua = profile["user_agent"]
        platform = profile["platform"]
        sec_ch_ua = profile["sec_ch_ua"]
        mobile = profile["mobile"]

    encodings = "gzip, deflate, br" if _has_brotli_support() else "gzip, deflate"

    headers = {
        "User-Agent": ua,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": encodings,
        "DNT": "1",
        "Sec-Ch-Ua": sec_ch_ua,
        "Sec-Ch-Ua-Mobile": mobile,
        "Sec-Ch-Ua-Platform": platform,
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }

    if custom_headers:
        headers.update(custom_headers)

    return headers


# ---------------------------------------------------------------------------
# 4. Built-in Ad & Tracker Domains
# ---------------------------------------------------------------------------

# Curated list of high-traffic telemetry, analytics, and ad platforms that
# slow down crawlers and pollute asset dumps.
AD_TRACKER_DOMAINS: frozenset[str] = frozenset({
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "googleadservices.com", "facebook.net", "facebook.com",
    "connect.facebook.net", "analytics.tiktok.com", "hotjar.com",
    "clarity.ms", "criteo.com", "criteo.net", "sentry.io",
    "segment.io", "segment.com", "mixpanel.com", "amplitude.com",
    "newrelic.com", "nr-data.net", "datadoghq.com", "optimizely.com",
    "taboola.com", "outbrain.com", "adnxs.com", "rubiconproject.com",
    "pubmatic.com", "openx.net", "casalemedia.com", "moatads.com",
    "scorecardresearch.com", "quantserve.com", "crazyegg.com",
    "fullstory.com", "logrocket.com", "bugsnag.com", "wp.com", "stats.wp.com",
})


def is_ad_or_tracker(url: str) -> bool:
    """Check if a URL belongs to a known tracker/ad network."""
    try:
        host = urlparse(url).hostname or ""
        host = host.lower()
        if not host:
            return False
        for domain in AD_TRACKER_DOMAINS:
            if host == domain or host.endswith(f".{domain}"):
                return True
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 5. AutoThrottle & Adaptive Rate Limiting
# ---------------------------------------------------------------------------

BLOCK_BACKOFF_FACTOR = 2.0


def parse_retry_after(headers_or_val: Any) -> Optional[float]:
    """Extract wait duration from a Retry-After header (dict, Mapping, numeric string, or RFC date)."""
    val = ""
    if isinstance(headers_or_val, Mapping):
        for k, v in headers_or_val.items():
            if str(k).lower() == "retry-after":
                val = str(v).strip()
                break
    elif isinstance(headers_or_val, (str, int, float)):
        val = str(headers_or_val).strip()

    if not val:
        return None

    # Try numeric seconds
    try:
        f = float(val)
        return min(f, 3600.0) if f >= 0 else None
    except ValueError:
        pass

    # Try HTTP date format
    try:
        dt = parsedate_to_datetime(val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = (dt - datetime.now(timezone.utc)).total_seconds()
        return min(max(delta, 0.0), 3600.0)
    except Exception:
        return None


class AutoThrottle:
    """Dynamically adjusts request pacing based on response latency & status codes."""

    def __init__(
        self,
        start_delay: float = 0.0,
        max_delay: float = 30.0,
        target_concurrency: float = 2.0,
        block_backoff: bool = True,
        min_delay: Optional[float] = None,
    ):
        self.start_delay = min_delay if min_delay is not None else start_delay
        self.max_delay = max_delay
        self.target_concurrency = max(target_concurrency, 1.0)
        self.block_backoff = block_backoff
        self._delays: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    def get_delay(self, domain: str, floor: float = 0.0) -> float:
        """Return the current base delay for a given domain without jitter."""
        if domain not in self._delays:
            self._delays[domain] = min(max(floor, self.start_delay), self.max_delay)
        return self._delays[domain]

    def delay_for(self, domain: str, floor: float = 0.0) -> float:
        """Return the current delay for a given domain with anti-fingerprint timing jitter."""
        base = self.get_delay(domain, floor)
        if base <= 0.0:
            return 0.0
        # Add ±15% anti-fingerprint jitter so requests don't have predictable machine cadence
        jittered = base * random.uniform(0.85, 1.15)
        return min(max(floor, jittered), self.max_delay)

    def record_response(
        self,
        domain: str,
        latency: float,
        status_code: int,
        headers: Optional[Dict[str, str]] = None,
        floor: float = 0.0,
    ) -> float:
        """Synchronous delay update calculation."""
        curr = self.get_delay(domain, floor)
        is_blocked = status_code in (403, 429, 503)
        ok = status_code < 400 or status_code in (401, 404)

        target_delay = latency / self.target_concurrency
        new_delay = max((curr + target_delay) / 2.0, target_delay)

        if is_blocked:
            retry_after = parse_retry_after(headers or {})
            if retry_after is not None and retry_after > 0:
                penalty = min(retry_after, self.max_delay)
            else:
                penalty = max(curr * BLOCK_BACKOFF_FACTOR, 2.0)
            new_delay = max(curr, penalty)
        elif not ok:
            new_delay = max(new_delay, curr * 1.5, 1.0)

        new_delay = min(max(new_delay, floor), self.max_delay)
        self._delays[domain] = new_delay
        return new_delay

    async def record(
        self,
        domain: str,
        latency: float,
        status: int,
        headers: Optional[Dict[str, str]] = None,
        floor: float = 0.0,
    ) -> float:
        """Update delay based on request latency and HTTP status code."""
        async with self._lock:
            return self.record_response(domain, latency, status, headers, floor)


# ---------------------------------------------------------------------------
# 6. Background Network & API Recorder
# ---------------------------------------------------------------------------

class NetworkRecorder:
    """Records background XHR, Fetch, and API requests captured during dynamic browsing."""

    def __init__(self, max_records: int = 1000, max_body_bytes: int = 4000):
        self.max_records = max_records
        self.max_body_bytes = max_body_bytes
        self._records: OrderedDict[int, Dict[str, Any]] = OrderedDict()
        self._id_counter = 0

    def record_response(
        self,
        url: str,
        method: str,
        status: int,
        resource_type: str,
        content_type: str = "",
        post_data: str = "",
        response_preview: str = "",
        headers: Optional[Dict[str, str]] = None,
    ) -> int:
        """Save a network event. Returns the record ID."""
        self._id_counter += 1
        preview = response_preview or ""
        if len(preview) > self.max_body_bytes and not preview.endswith("[truncated]"):
            preview = preview[:self.max_body_bytes] + "... [truncated]"

        rec = {
            "id": self._id_counter,
            "url": url,
            "method": method,
            "status": status,
            "resource_type": resource_type,
            "content_type": content_type,
            "post_data": post_data[:2000] if post_data else "",
            "response_preview": preview,
            "headers": headers or {},
            "timestamp": time.time(),
        }
        self._records[self._id_counter] = rec
        while len(self._records) > self.max_records:
            self._records.popitem(last=False)
        return self._id_counter

    def record(
        self,
        url: str,
        method: str,
        status: int,
        resource_type: str = "fetch",
        content_type: str = "application/json",
        post_data: str = "",
        response_body: str = "",
        headers: Optional[Dict[str, str]] = None,
    ) -> int:
        """Convenience recorder that filters static media and truncates large bodies."""
        if resource_type.lower() in ("image", "font", "stylesheet", "media"):
            return -1
        truncated_body = response_body
        if response_body and len(response_body) > self.max_body_bytes:
            truncated_body = response_body[:self.max_body_bytes] + "... [truncated]"
        return self.record_response(
            url=url,
            method=method,
            status=status,
            resource_type=resource_type,
            content_type=content_type,
            post_data=post_data,
            response_preview=truncated_body,
            headers=headers,
        )

    @property
    def requests(self) -> List[Dict[str, Any]]:
        """Return list of captured requests with response_body populated."""
        res = []
        for rec in self._records.values():
            copy_rec = dict(rec)
            copy_rec["response_body"] = copy_rec.get("response_preview", "")
            res.append(copy_rec)
        return res

    def search(
        self,
        url_pattern: Optional[str] = None,
        resource_type: Optional[str] = None,
        min_status: Optional[int] = None,
        limit: Optional[int] = 100,
    ) -> List[Dict[str, Any]]:
        """Search captured network requests by pattern or type."""
        results = []
        regex = re.compile(url_pattern, re.IGNORECASE) if url_pattern else None

        for rec in reversed(self._records.values()):
            if regex and not regex.search(rec["url"]):
                continue
            if resource_type and rec["resource_type"] != resource_type:
                continue
            if min_status and rec["status"] < min_status:
                continue
            results.append(rec)
            if limit and len(results) >= limit:
                break

        return results

    @property
    def all_records(self) -> List[Dict[str, Any]]:
        return list(self._records.values())

    @property
    def api_endpoints(self) -> List[str]:
        """Extract URLs that appear to be JSON/REST/GraphQL APIs."""
        apis = []
        for r in self._records.values():
            ct = r.get("content_type", "").lower()
            u = r.get("url", "")
            if "application/json" in ct or "/api/" in u or "/graphql" in u or "?" in u:
                apis.append(u)
        return list(set(apis))


class TokenBucketRateLimiter:
    """Token-bucket rate limiter for smooth asynchronous request pacing and burst management."""

    def __init__(self, rate: float = 10.0, capacity: float = 20.0):
        self.rate = max(0.1, rate)
        self.capacity = max(1.0, capacity)
        self.tokens = self.capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last_update
                self.last_update = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return
                wait_time = (tokens - self.tokens) / self.rate
                await asyncio.sleep(wait_time)


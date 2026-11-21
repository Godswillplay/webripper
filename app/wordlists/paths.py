"""
Curated sensitive-path wordlist + SecLists downloader.

Provides:
    - BUILTIN_PATHS: ~150 commonly exposed paths (always available)
    - download_seclists(): downloads SecLists Discovery/Web-Content to %APPDATA%
    - load_wordlist(): returns paths from custom file, SecLists, or builtin fallback
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path
from typing import Callable, List, Optional
from urllib.request import urlretrieve

# ---------------------------------------------------------------------------
# Curated built-in wordlist (~150 most impactful paths)
# ---------------------------------------------------------------------------

BUILTIN_PATHS: List[str] = [
    # Version control exposure
    "/.git/HEAD",
    "/.git/config",
    "/.git/index",
    "/.gitignore",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.hg/dirstate",
    "/.bzr/README",

    # Environment & config files
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.env.staging",
    "/.env.backup",
    "/.env.bak",
    "/.env.old",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/config.xml",
    "/config.php",
    "/config.js",
    "/settings.json",
    "/settings.py",
    "/application.yml",
    "/application.properties",
    "/appsettings.json",
    "/web.config",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/database.yml",
    "/credentials.json",

    # Backups & archives
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.sql",
    "/backup.sql.gz",
    "/db.sql",
    "/dump.sql",
    "/database.sql",
    "/site.zip",
    "/www.zip",
    "/html.zip",
    "/public.zip",

    # Admin panels
    "/admin",
    "/admin/",
    "/administrator",
    "/administrator/",
    "/wp-admin/",
    "/wp-login.php",
    "/phpmyadmin/",
    "/phpMyAdmin/",
    "/adminer.php",
    "/cpanel",
    "/webmail",
    "/login",
    "/auth/login",
    "/dashboard",
    "/panel",
    "/console",
    "/manage",

    # Debug & status endpoints
    "/_debug",
    "/_debugbar",
    "/debug/vars",
    "/debug/pprof",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/elmah.axd",
    "/trace.axd",
    "/_profiler",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/configprops",
    "/health",
    "/healthz",
    "/status",
    "/metrics",
    "/__debug__/",

    # API documentation (exposed = attack surface map)
    "/swagger",
    "/swagger/",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/api-docs/",
    "/openapi.json",
    "/openapi.yaml",
    "/redoc",
    "/graphql",
    "/graphql/playground",
    "/graphiql",
    "/_graphql",
    "/api/v1/",
    "/api/v2/",

    # Well-known & metadata
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/.well-known/change-password",
    "/security.txt",
    "/humans.txt",
    "/manifest.json",
    "/manifest.webmanifest",
    "/browserconfig.xml",
    "/favicon.ico",

    # Package & dependency files (tech disclosure)
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/composer.json",
    "/composer.lock",
    "/Gemfile",
    "/Gemfile.lock",
    "/requirements.txt",
    "/Pipfile",
    "/Pipfile.lock",
    "/go.mod",
    "/go.sum",
    "/Cargo.toml",
    "/pom.xml",
    "/build.gradle",

    # WordPress specific
    "/xmlrpc.php",
    "/wp-json/",
    "/wp-json/wp/v2/users",
    "/wp-content/debug.log",
    "/wp-includes/",
    "/readme.html",
    "/license.txt",

    # Source & dev artifacts
    "/.DS_Store",
    "/Thumbs.db",
    "/.htaccess",
    "/.htpasswd",
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/.dockerignore",
    "/Makefile",
    "/Rakefile",
    "/Gruntfile.js",
    "/gulpfile.js",
    "/webpack.config.js",
    "/tsconfig.json",
    "/.babelrc",
    "/.eslintrc",
    "/.npmrc",
    "/id_rsa",
    "/id_rsa.pub",
    "/.ssh/authorized_keys",

    # Error & log files
    "/error.log",
    "/access.log",
    "/debug.log",
    "/app.log",
    "/errors.log",

    # Service workers & JS maps
    "/service-worker.js",
    "/sw.js",
    "/precache-manifest.js",

    # Cloud metadata & credentials
    "/.aws/credentials",
    "/.aws/config",
    "/latest/meta-data/",
    "/v1/meta-data/",
]

# ---------------------------------------------------------------------------
# SecLists integration
# ---------------------------------------------------------------------------

SECLISTS_DIR_NAME = "SecLists"
SECLISTS_WEB_CONTENT_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/"
    "master/Discovery/Web-Content/common.txt"
)
SECLISTS_RAFT_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/"
    "master/Discovery/Web-Content/raft-medium-files.txt"
)


def get_seclists_dir() -> Path:
    """Return the SecLists storage directory under %APPDATA%."""
    appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
    return Path(appdata) / "WebRipper" / SECLISTS_DIR_NAME


def is_seclists_installed() -> bool:
    """Check if SecLists common wordlists are downloaded."""
    d = get_seclists_dir()
    return (d / "common.txt").exists()


def download_seclists(
    progress_callback: Optional[Callable[[str], None]] = None,
) -> bool:
    """Download SecLists common + raft-medium wordlists.

    Returns True on success, False on failure.
    """
    cb = progress_callback or (lambda s: None)
    dest = get_seclists_dir()
    dest.mkdir(parents=True, exist_ok=True)

    files = [
        ("common.txt", SECLISTS_WEB_CONTENT_URL),
        ("raft-medium-files.txt", SECLISTS_RAFT_URL),
    ]

    for name, url in files:
        target = dest / name
        if target.exists():
            cb(f"Already downloaded: {name}")
            continue
        try:
            cb(f"Downloading {name}...")
            urlretrieve(url, str(target))
            cb(f"Saved: {target}")
        except Exception as exc:
            cb(f"Failed to download {name}: {exc}")
            return False

    return True


def get_seclists_size_estimate() -> str:
    """Return estimated download size."""
    return "~2 MB"


def load_wordlist(custom_path: str = "") -> List[str]:
    """Load paths for probing.

    Priority:
        1. Custom wordlist file (if provided)
        2. SecLists common.txt (if downloaded)
        3. Built-in curated list (always available)

    Returns deduplicated list of paths.
    """
    paths: List[str] = []

    # 1. Custom wordlist
    if custom_path and os.path.isfile(custom_path):
        with open(custom_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if not line.startswith("/"):
                        line = "/" + line
                    paths.append(line)
        return list(dict.fromkeys(paths))  # dedupe preserving order

    # 2. SecLists
    seclists_common = get_seclists_dir() / "common.txt"
    if seclists_common.exists():
        with open(seclists_common, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if not line.startswith("/"):
                        line = "/" + line
                    paths.append(line)
        # Also add our curated paths that SecLists might miss
        for p in BUILTIN_PATHS:
            if p not in paths:
                paths.append(p)
        return list(dict.fromkeys(paths))

    # 3. Builtin fallback
    return list(BUILTIN_PATHS)

"""
Secret & leak scanner for WebRipper Recon.

Scans downloaded files for API keys, tokens, passwords, cloud credentials,
internal IPs, and other sensitive data exposure.
"""

from __future__ import annotations

import os
import re
import time
from typing import List, Tuple

from .base import BaseScanner
from ..models import Finding, ScanResult, Severity

# ---------------------------------------------------------------------------
# File extensions to scan
# ---------------------------------------------------------------------------

_TEXT_EXTENSIONS = (
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte",
    ".json", ".html", ".htm", ".css", ".xml", ".txt", ".yml", ".yaml",
    ".env", ".config", ".cfg", ".ini", ".properties", ".map", ".md",
    ".php", ".py", ".rb", ".java", ".go", ".rs", ".sh", ".bat", ".ps1",
    ".sql", ".graphql", ".gql", ".toml",
)

# Max file size to scan (500 KB for minified, 2 MB for others)
_MAX_MINIFIED_SIZE = 500_000
_MAX_FILE_SIZE = 2_000_000

# ---------------------------------------------------------------------------
# False-positive values for password/secret patterns
# ---------------------------------------------------------------------------

_PASSWORD_FP_VALUES = {
    # Validation & form keywords
    "required", "optional", "true", "false", "null", "undefined", "none",
    "password", "your_password", "your-password", "yourpassword",
    "placeholder", "enter password", "enter_password",
    "change_me", "changeme", "change-me",
    # Common defaults & examples
    "example", "test", "demo", "admin", "root", "user",
    "password123", "1234", "12345", "123456",
    "xxxx", "****", "string", "text", "value",
    # Schema / type keywords
    "string", "number", "boolean", "object", "array", "integer",
    "type", "format", "minlength", "maxlength", "pattern",
    # Variable references (not actual values)
    "process.env", "os.environ", "env.", "config.",
}

# Context patterns that indicate form validation, not hardcoded creds
_PASSWORD_FP_CONTEXT = re.compile(
    r"""(?:validate|rules|validator|required|minlength|maxlength|"""
    r"""pattern|schema|propTypes|yup\.|zod\.|\.validate|"""
    r"""\.required|form\.|\$\(|jQuery|angular|v-model|ng-model|"""
    r"""placeholder|label|aria-|type=|htmlFor)""",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Pattern definitions: (name, regex, severity, remediation)
# ---------------------------------------------------------------------------

def _build_patterns() -> List[Tuple[str, re.Pattern, Severity, str]]:
    """Build compiled regex patterns for secret detection."""
    _rotate = "Rotate this key immediately. Move to environment variables or a secrets manager."
    _remove = "Remove hardcoded credentials. Use environment variables or a vault."
    _internal = "Internal network addresses should not be exposed in client-side code."

    return [
        # --- API Keys (CRITICAL) ---
        ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL, _rotate),
        ("AWS Secret Key", re.compile(r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|aws_secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", re.IGNORECASE), Severity.CRITICAL, _rotate),
        ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), Severity.CRITICAL, _rotate),
        ("Google OAuth Client", re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"), Severity.HIGH, _rotate),
        ("Firebase URL", re.compile(r"[a-z0-9-]+\.firebaseio\.com"), Severity.MEDIUM, "Verify Firebase security rules are properly configured."),
        ("Stripe Live Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), Severity.CRITICAL, _rotate),
        ("Stripe Live Publishable Key", re.compile(r"pk_live_[0-9a-zA-Z]{24,}"), Severity.LOW, "Publishable key is intended to be public, but verify it's expected here."),
        ("GitHub Token", re.compile(r"gh[ps]_[0-9a-zA-Z]{36,}"), Severity.CRITICAL, _rotate),
        ("GitHub PAT", re.compile(r"github_pat_[0-9a-zA-Z_]{20,}"), Severity.CRITICAL, _rotate),
        ("GitLab Token", re.compile(r"glpat-[0-9a-zA-Z\-]{20,}"), Severity.CRITICAL, _rotate),
        ("Slack Token", re.compile(r"xox[bprs]-[0-9a-zA-Z\-]{10,}"), Severity.CRITICAL, _rotate),
        ("Slack Webhook", re.compile(r"hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{24}"), Severity.HIGH, _rotate),
        ("Twilio Account SID", re.compile(r"AC[0-9a-f]{32}"), Severity.HIGH, _rotate),
        ("Twilio API Key", re.compile(r"SK[0-9a-f]{32}"), Severity.CRITICAL, _rotate),
        ("SendGrid API Key", re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"), Severity.CRITICAL, _rotate),
        ("Mailgun API Key", re.compile(r"key-[0-9a-zA-Z]{32}"), Severity.CRITICAL, _rotate),
        ("NPM Token", re.compile(r"npm_[0-9a-zA-Z]{36}"), Severity.CRITICAL, _rotate),
        ("PyPI Token", re.compile(r"pypi-[0-9a-zA-Z\-_]{50,}"), Severity.CRITICAL, _rotate),

        # --- Tokens & Auth (HIGH) ---
        ("JSON Web Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"), Severity.HIGH, "JWTs in source code may contain sensitive claims. Verify token handling."),
        ("Bearer Token", re.compile(r"[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}=*"), Severity.HIGH, _remove),
        ("Basic Auth", re.compile(r"[Bb]asic\s+[A-Za-z0-9+/]{20,}={0,2}"), Severity.HIGH, "Basic auth credentials are base64-encoded and easily decoded."),
        ("Authorization Header", re.compile(r"""['"]?[Aa]uthorization['"]?\s*[:=]\s*['"](?:Bearer|Basic|Token)\s"""), Severity.HIGH, _remove),
        ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), Severity.CRITICAL, "Private keys must never be in client-side code. Revoke and regenerate immediately."),

        # --- Passwords & Secrets (HIGH) — filtered for false positives ---
        ("Hardcoded Password", re.compile(r"""(?:password|passwd|pwd|pass|secret|api_key|apikey|api-key|access_key|auth_token)\s*[:=]\s*['"]([^'"]{4,})['"]""", re.IGNORECASE), Severity.HIGH, _remove),
        ("Database Connection String", re.compile(r"(?:mysql|postgres|postgresql|mongodb|mongodb\+srv|redis|amqp|mssql)://[^\s'\"]+", re.IGNORECASE), Severity.CRITICAL, _remove),
        ("Database URL Variable", re.compile(r"""(?:DATABASE_URL|DB_URL|REDIS_URL|MONGO_URI|MONGODB_URI)\s*[:=]\s*['"][^'"]+""", re.IGNORECASE), Severity.HIGH, _remove),

        # --- Cloud & Infrastructure (MEDIUM-HIGH) ---
        ("AWS S3 Bucket", re.compile(r"[a-z0-9.-]+\.s3\.amazonaws\.com"), Severity.MEDIUM, "Verify S3 bucket permissions. Ensure no sensitive data is publicly accessible."),
        ("S3 Protocol URL", re.compile(r"s3://[a-z0-9.-]+"), Severity.MEDIUM, "Verify S3 bucket permissions."),
        ("Azure Connection String", re.compile(r"DefaultEndpointsProtocol=https;AccountName=[a-zA-Z0-9]+"), Severity.HIGH, _remove),
        ("GCP Service Account", re.compile(r"[0-9]+-[a-z0-9]+@[a-z]+\.iam\.gserviceaccount\.com"), Severity.MEDIUM, "Service account emails should not be exposed in client-side code."),

        # --- Information Leakage (MEDIUM/LOW) ---
        ("Internal IP Address", re.compile(r"(?<![0-9])(?:10\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}(?![0-9])"), Severity.LOW, _internal),
        ("Internal/Staging URL", re.compile(r"(?:staging|internal|dev|test|local|debug|preprod)\.[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE), Severity.MEDIUM, "Internal URLs should not be exposed in production code."),
        ("Debug Mode Enabled", re.compile(r"""(?:DEBUG|DEVELOPMENT|DEV_MODE)\s*[:=]\s*(?:true|True|1|['"]true['"])"""), Severity.MEDIUM, "Ensure debug mode is disabled in production."),
        ("TODO with Secret Reference", re.compile(r"(?:TODO|FIXME|HACK|XXX).*(?:password|secret|key|token|credential)", re.IGNORECASE), Severity.LOW, "Review and address this TODO. Remove any sensitive references."),
    ]


# Exploit intelligence lookup per secret type
_EXPLOIT_INFO = {
    "AWS Access Key": {"exploit": "Attacker uses the key with AWS CLI: aws configure set aws_access_key_id AKIAXXXXXXX && aws s3 ls — lists all S3 buckets. Then: aws s3 cp s3://bucket/secrets.db . — downloads everything. Can also spin up crypto miners on EC2.", "impact": "Full AWS account compromise — data theft, resource hijacking, crypto mining, service disruption", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~2 minutes"},
    "AWS Secret Key": {"exploit": "Combined with Access Key, gives full programmatic access to AWS. Attacker can read S3, query databases, create admin users, and exfiltrate all data.", "impact": "Complete AWS account takeover", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~2 minutes"},
    "Google API Key": {"exploit": "Attacker uses key to call Google APIs at your expense. Depending on enabled APIs: read Maps data, access Cloud resources, or run up massive billing charges.", "impact": "Unauthorized API usage, potential data access, billing fraud (charges can reach $10K+ overnight)", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~1 minute"},
    "Google OAuth Client": {"exploit": "Attacker creates phishing page using your OAuth client ID to trick users into authorizing their app, stealing OAuth tokens.", "impact": "OAuth phishing, user token theft", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~15 minutes"},
    "Firebase URL": {"exploit": "Attacker accesses Firebase REST API: curl https://PROJECT.firebaseio.com/.json — if rules are misconfigured, reads/writes entire database.", "impact": "Database read/write access if rules are open", "cwe": "CWE-284", "owasp": "A01:2021 Broken Access Control", "time_to_exploit": "~1 minute"},
    "Stripe Live Secret Key": {"exploit": "Attacker uses key to read all customers, charges, and payment methods: curl https://api.stripe.com/v1/customers -u sk_live_XXX: — can also issue refunds and create charges.", "impact": "Financial data theft, fraudulent charges/refunds, PCI compliance violation", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~1 minute"},
    "GitHub Token": {"exploit": "Attacker clones private repos, reads org secrets, pushes malicious code: git clone https://TOKEN@github.com/org/private-repo. Can also create backdoor commits.", "impact": "Source code theft, supply chain attacks, secret extraction from CI/CD", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~2 minutes"},
    "GitHub PAT": {"exploit": "Same as GitHub Token — full API access to repos, issues, actions, and organization settings.", "impact": "Source code theft, CI/CD compromise", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~2 minutes"},
    "GitLab Token": {"exploit": "Attacker uses token for GitLab API: reads private repos, pipelines, CI/CD variables (which often contain more secrets).", "impact": "Source code theft, CI/CD secret extraction", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~2 minutes"},
    "Slack Token": {"exploit": "Attacker reads all accessible Slack channels, DMs, and files: curl -H 'Authorization: Bearer xoxb-XXX' https://slack.com/api/conversations.list. Can post messages as the bot.", "impact": "Internal communication exposure, social engineering, data exfiltration via Slack", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~2 minutes"},
    "Slack Webhook": {"exploit": "Attacker posts messages to your Slack channel: curl -X POST -d '{\"text\":\"PHISHING LINK\"}' WEBHOOK_URL. Can be used for social engineering or spreading malware.", "impact": "Social engineering via spoofed Slack messages", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~1 minute"},
    "Twilio Account SID": {"exploit": "Combined with auth token, attacker sends SMS/calls as your account, reads message logs, and runs up charges.", "impact": "SMS/voice abuse, billing fraud, message log access", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~5 minutes"},
    "Twilio API Key": {"exploit": "Full Twilio API access — send SMS, make calls, read logs, access recordings.", "impact": "Communication abuse, billing fraud", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~2 minutes"},
    "SendGrid API Key": {"exploit": "Attacker sends emails as your domain: curl -X POST https://api.sendgrid.com/v3/mail/send -H 'Authorization: Bearer SG.XXX'. Mass phishing from your trusted domain.", "impact": "Email spoofing from trusted domain, phishing, reputation damage", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~2 minutes"},
    "Mailgun API Key": {"exploit": "Same as SendGrid — send emails as your domain, read email logs, access stored messages.", "impact": "Email spoofing, phishing, email data theft", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~2 minutes"},
    "NPM Token": {"exploit": "Attacker publishes malicious version of your npm packages: npm publish --token=npm_XXX. Supply chain attack affecting all users who install/update.", "impact": "Supply chain attack — malicious code in all downstream projects", "cwe": "CWE-798", "owasp": "A08:2021 Software and Data Integrity Failures", "time_to_exploit": "~5 minutes"},
    "PyPI Token": {"exploit": "Same as NPM — publish backdoored Python packages.", "impact": "Supply chain attack via PyPI", "cwe": "CWE-798", "owasp": "A08:2021 Software and Data Integrity Failures", "time_to_exploit": "~5 minutes"},
    "JSON Web Token": {"exploit": "Attacker decodes JWT payload (base64) to read claims: user ID, role, email. If signing key is weak, attacker forges tokens with elevated privileges.", "impact": "Information disclosure, potential authentication bypass if key is cracked", "cwe": "CWE-312", "owasp": "A02:2021 Cryptographic Failures", "time_to_exploit": "~5 minutes to decode, ~1 hour to crack weak key"},
    "Bearer Token": {"exploit": "Attacker replays the token in API requests: curl -H 'Authorization: Bearer TOKEN' https://api.target.com/user — accesses the API as the token's owner.", "impact": "Authenticated API access as the token owner", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~1 minute"},
    "Basic Auth": {"exploit": "Attacker base64-decodes the credentials: echo 'ENCODED' | base64 -d — reveals username:password in plaintext. Then logs in directly.", "impact": "Direct credential exposure — immediate account access", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~30 seconds"},
    "Authorization Header": {"exploit": "Attacker extracts and replays the authorization header to access authenticated APIs.", "impact": "API authentication bypass", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~1 minute"},
    "Private Key": {"exploit": "Attacker uses the private key to: decrypt TLS traffic (if it's the server key), SSH into servers, sign code/commits, or impersonate the key owner in mutual TLS.", "impact": "Server impersonation, SSH access, code signing forgery, TLS decryption", "cwe": "CWE-321", "owasp": "A02:2021 Cryptographic Failures", "time_to_exploit": "~2 minutes"},
    "Hardcoded Password": {"exploit": "Attacker uses the credential to log in directly to the application, database, or service. Credentials are often reused across environments.", "impact": "Direct access to authenticated systems", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~1 minute"},
    "Database Connection String": {"exploit": "Attacker connects directly to the database using the full connection string (host, port, user, password). Dumps all tables: mysqldump -h HOST -u USER -pPASS dbname > dump.sql", "impact": "Complete database access — read/modify/delete all data", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~2 minutes"},
    "Database URL Variable": {"exploit": "Contains database credentials in URL format. Attacker parses the URL and connects with native client.", "impact": "Database compromise", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~2 minutes"},
    "AWS S3 Bucket": {"exploit": "Attacker checks bucket permissions: aws s3 ls s3://BUCKET --no-sign-request. If public, downloads all contents. Common finds: database backups, user uploads, logs with PII.", "impact": "Data exposure if bucket is misconfigured", "cwe": "CWE-200", "owasp": "A01:2021 Broken Access Control", "time_to_exploit": "~1 minute"},
    "S3 Protocol URL": {"exploit": "Same as S3 Bucket — check for public access and enumerate contents.", "impact": "Data exposure", "cwe": "CWE-200", "owasp": "A01:2021 Broken Access Control", "time_to_exploit": "~1 minute"},
    "Azure Connection String": {"exploit": "Attacker uses Azure Storage Explorer or CLI with the connection string to access blobs, tables, and queues.", "impact": "Azure Storage data theft", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "time_to_exploit": "~2 minutes"},
    "GCP Service Account": {"exploit": "Attacker targets this service account for privilege escalation within GCP. May craft requests impersonating the SA.", "impact": "GCP resource enumeration, potential privilege escalation", "cwe": "CWE-200", "owasp": "A01:2021 Broken Access Control", "time_to_exploit": "~10 minutes"},
    "Internal IP Address": {"exploit": "Reveals internal network topology. Attacker maps the network structure and targets internal services via SSRF or after gaining foothold.", "impact": "Network reconnaissance, SSRF targeting", "cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration", "time_to_exploit": "Varies"},
    "Internal/Staging URL": {"exploit": "Attacker accesses staging/dev environment which typically has: weaker auth, debug mode, test credentials (admin/admin), verbose errors revealing stack traces.", "impact": "Access to less-secured environments, potential pivot to production", "cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration", "time_to_exploit": "~5 minutes"},
    "Debug Mode Enabled": {"exploit": "Debug mode exposes: stack traces with source paths, environment variables, SQL queries, and sometimes an interactive debugger (Django, Flask debug console = RCE).", "impact": "Information disclosure, potential RCE via debug console", "cwe": "CWE-215", "owasp": "A05:2021 Security Misconfiguration", "time_to_exploit": "~2 minutes if debug console is exposed"},
    "TODO with Secret Reference": {"exploit": "Indicates developers are aware of a credential issue but haven't fixed it. May point to temporary hardcoded values still in use.", "impact": "Potential credential exposure in referenced code", "cwe": "CWE-615", "owasp": "A05:2021 Security Misconfiguration", "time_to_exploit": "Varies"},
    "Email Address Exposed": {"exploit": "Attacker uses exposed emails for: targeted phishing/spear-phishing, credential stuffing (check if email/password combos exist in breach databases), social engineering.", "impact": "Phishing, credential stuffing, social engineering", "cwe": "CWE-200", "owasp": "A01:2021 Broken Access Control", "time_to_exploit": "~5 minutes to craft phishing email"},
    "Stripe Live Publishable Key": {"exploit": "Publishable key is meant to be public but confirms Stripe integration. Attacker knows to look for payment-related vulnerabilities.", "impact": "Low — key is designed to be public", "cwe": "", "owasp": "", "time_to_exploit": "N/A"},
}


PATTERNS = _build_patterns()

# Email pattern (handled separately due to false-positive filtering)
_RE_EMAIL = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_EMAIL_FP_DOMAINS = {"example.com", "example.org", "test.com", "localhost", "placeholder.com", "email.com", "domain.com", "yoursite.com", "sentry.io", "w3.org"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EXAMPLE_CREDENTIAL_PATTERNS = [
    re.compile(r"^AKIAIOSFODNN7EXAMPLE$", re.IGNORECASE),
    re.compile(r"^eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJzdWIiOiIxMjM0NTY3ODkw"),
]


def _is_example_credential(evidence: str) -> bool:
    """Check if matched secret is a known documentation or sample credential."""
    for pat in _EXAMPLE_CREDENTIAL_PATTERNS:
        if pat.search(evidence):
            return True
    return False


def _is_binary(filepath: str) -> bool:
    """Check if a file appears to be binary."""
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(512)
            return b"\x00" in chunk
    except (OSError, IOError):
        return True


def _is_minified(filepath: str) -> bool:
    """Check if a JS file appears to be minified (very long lines)."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            first_line = f.readline()
            return len(first_line) > 5000
    except (OSError, IOError):
        return False


def _is_password_false_positive(match_text: str, full_line: str) -> bool:
    """Check if a password/secret match is a false positive."""
    # Extract the captured value (group 1 if available)
    # The password pattern captures the value in group 1
    # but we receive the full match text, so parse it
    # Find the value between quotes
    for quote in ("'", '"'):
        idx = match_text.rfind(quote)
        if idx > 0:
            start = match_text.rfind(quote, 0, idx)
            if start >= 0:
                value = match_text[start + 1:idx]
                break
    else:
        value = match_text

    # Check against known false positive values
    if value.lower().strip() in _PASSWORD_FP_VALUES:
        return True

    # Check if line contains form validation context
    if _PASSWORD_FP_CONTEXT.search(full_line):
        return True

    # Variable reference, not a literal
    if value.startswith(("process.env", "os.environ", "config.", "env.", "${", "{{", "<%")):
        return True

    return False


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class SecretScanner(BaseScanner):
    """Scans downloaded files for leaked secrets and sensitive data."""

    @property
    def name(self) -> str:
        return "secrets"

    @property
    def description(self) -> str:
        return "Scans for leaked API keys, tokens, passwords, and sensitive data"

    def scan(self) -> ScanResult:
        """Scan all downloaded text files for secret patterns."""
        start = time.time()
        files = self._get_scannable_files()
        self._log(f"Scanning {len(files)} files for secrets...")

        for file_result in files:
            self._scan_file(file_result.local_path, file_result.url)

        self._log(f"Secret scan complete: {len(self._findings)} findings")
        return self._build_result(
            start,
            files_scanned=len(files),
            patterns_checked=len(PATTERNS),
        )

    def _get_scannable_files(self) -> list:
        """Get files suitable for secret scanning."""
        results = []
        for f in self._report.files:
            if f.error or not f.local_path:
                continue
            if not os.path.isfile(f.local_path):
                continue
            lower = f.local_path.lower()
            ct = getattr(f, "content_type", "").lower()
            is_text_ext = any(lower.endswith(ext) for ext in _TEXT_EXTENSIONS)
            is_text_ct = any(t in ct for t in ("text/", "html", "javascript", "json", "xml"))
            has_no_ext = "." not in os.path.basename(f.local_path)
            if not (is_text_ext or is_text_ct or has_no_ext):
                continue
            try:
                size = os.path.getsize(f.local_path)
            except (OSError, IOError):
                continue
            if size > _MAX_FILE_SIZE:
                continue
            if size > _MAX_MINIFIED_SIZE and _is_minified(f.local_path):
                continue
            if _is_binary(f.local_path):
                continue
            results.append(f)
        return results

    def _scan_file(self, filepath: str, url: str) -> None:
        """Scan a single file for secret patterns."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    self._check_line(line, filepath, url, line_num)
        except (OSError, IOError):
            pass

    def _check_line(self, line: str, filepath: str, url: str, line_num: int) -> None:
        """Check a single line against all patterns."""
        for pattern_name, regex, severity, remediation in PATTERNS:
            for match in regex.finditer(line):
                evidence = match.group(0).strip()

                # Check if this is a known documentation / example key
                if _is_example_credential(evidence):
                    self._add_finding(Finding(
                        severity=Severity.INFO,
                        category="secrets",
                        title=f"Example / Documentation Credential: {pattern_name}",
                        description=f"Public example or documentation credential pattern detected: {pattern_name}. This is recognized as non-functional documentation sample data.",
                        evidence=evidence,
                        file_path=filepath,
                        line_number=line_num,
                        url=url,
                        remediation="Verify this is documentation sample code and not an active production key.",
                        confidence="INFO",
                        metadata={"example_credential": True},
                    ))
                    continue

                # Apply false-positive filtering for password patterns
                if pattern_name == "Hardcoded Password":
                    if _is_password_false_positive(evidence, line):
                        continue

                # Show the full surrounding line as context (trimmed)
                context_line = line.strip()
                if len(context_line) > 300:
                    # Show around the match
                    start = max(0, match.start() - 50)
                    end = min(len(line), match.end() + 50)
                    context_line = "..." + line[start:end].strip() + "..."

                ei = _EXPLOIT_INFO.get(pattern_name, {})
                self._add_finding(Finding(
                    severity=severity,
                    category="secrets",
                    title=pattern_name,
                    description=f"{pattern_name} found in {os.path.basename(filepath)}",
                    evidence=evidence,
                    file_path=filepath,
                    line_number=line_num,
                    url=url,
                    remediation=remediation,
                    metadata={
                        "context": context_line,
                        "exploit": ei.get("exploit", ""),
                        "impact": ei.get("impact", ""),
                        "cwe": ei.get("cwe", ""),
                        "owasp": ei.get("owasp", ""),
                        "time_to_exploit": ei.get("time_to_exploit", ""),
                    },
                ))

        # Email addresses (separate handling for false-positive filtering)
        _IMG_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".avif", ".ico", ".woff", ".woff2", ".ttf", ".eot")
        for match in _RE_EMAIL.finditer(line):
            email = match.group(0)
            if any(email.lower().endswith(ext) for ext in _IMG_EXTS):
                continue
            domain = email.split("@")[1].lower()
            if domain in _EMAIL_FP_DOMAINS:
                continue
            ei = _EXPLOIT_INFO.get("Email Address Exposed", {})
            self._add_finding(Finding(
                severity=Severity.LOW,
                category="secrets",
                title="Email Address Exposed",
                description=f"Email address found in {os.path.basename(filepath)}",
                evidence=email,
                file_path=filepath,
                line_number=line_num,
                url=url,
                remediation="Review whether this email should be exposed in client-side code.",
                metadata={
                    "exploit": ei.get("exploit", ""),
                    "impact": ei.get("impact", ""),
                    "cwe": ei.get("cwe", ""),
                    "owasp": ei.get("owasp", ""),
                    "time_to_exploit": ei.get("time_to_exploit", ""),
                },
            ))

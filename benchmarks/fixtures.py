"""
WebRipper Recon 5.0 — Benchmark Testbed Ground Truth & Simulated Fixtures.

Defines canonical ground-truth vulnerabilities and deterministic fixture suites
for standard security testbeds:
  - OWASP Juice Shop (Web / Modern SPA / API)
  - WebGoat (Classic Enterprise Java Web / Training App)
  - crAPI (Completely Ridiculous API / REST & Microservices)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.models import Finding, Severity


@dataclass
class GroundTruthItem:
    """A known ground-truth vulnerability defined in a benchmark testbed."""
    id: str
    testbed: str
    vuln_class: str
    title: str
    endpoint: str
    severity: str = "HIGH"
    cwe: str = ""
    identifiers: List[str] = field(default_factory=list)
    expected_verified: bool = True
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "testbed": self.testbed,
            "vuln_class": self.vuln_class,
            "title": self.title,
            "endpoint": self.endpoint,
            "severity": self.severity,
            "cwe": self.cwe,
            "identifiers": self.identifiers,
            "expected_verified": self.expected_verified,
            "description": self.description,
        }


# ===========================================================================
# 1. OWASP Juice Shop Ground Truth
# ===========================================================================

GROUND_TRUTH_JUICE_SHOP: List[GroundTruthItem] = [
    # Injection
    GroundTruthItem(
        id="JUICE-INJ-001",
        testbed="juice-shop",
        vuln_class="Injection",
        title="SQL Injection in User Authentication",
        endpoint="/rest/user/login",
        severity="CRITICAL",
        cwe="CWE-89",
        identifiers=["sql", "login", "authentication"],
        expected_verified=True,
        description="SQL injection in email field allows authentication bypass as administrator.",
    ),
    GroundTruthItem(
        id="JUICE-INJ-002",
        testbed="juice-shop",
        vuln_class="Injection",
        title="Reflected Cross-Site Scripting (XSS) in Product Search",
        endpoint="/rest/products/search",
        severity="HIGH",
        cwe="CWE-79",
        identifiers=["xss", "search", "cross-site"],
        expected_verified=True,
        description="Reflected XSS via q parameter in product search endpoint.",
    ),
    GroundTruthItem(
        id="JUICE-INJ-003",
        testbed="juice-shop",
        vuln_class="Injection",
        title="Server-Side Template Injection (SSTI) in Order Tracking",
        endpoint="/rest/track-order",
        severity="HIGH",
        cwe="CWE-1336",
        identifiers=["ssti", "template", "track-order"],
        expected_verified=False,
        description="Template injection in order tracking view evaluating arbitrary expressions.",
    ),

    # Auth/IDOR
    GroundTruthItem(
        id="JUICE-AUTH-001",
        testbed="juice-shop",
        vuln_class="Auth/IDOR",
        title="BOLA/IDOR Insecure Basket Direct Object Reference",
        endpoint="/rest/basket/5",
        severity="HIGH",
        cwe="CWE-639",
        identifiers=["basket", "idor", "bola"],
        expected_verified=True,
        description="Viewing another user's shopping basket by incrementing numeric ID in path.",
    ),
    GroundTruthItem(
        id="JUICE-AUTH-002",
        testbed="juice-shop",
        vuln_class="Auth/IDOR",
        title="Privilege Escalation via Unrestricted Admin Registration",
        endpoint="/api/Users",
        severity="CRITICAL",
        cwe="CWE-269",
        identifiers=["admin", "registration", "privilege"],
        expected_verified=True,
        description="Setting role=admin during user registration payload promotes account to admin.",
    ),
    GroundTruthItem(
        id="JUICE-AUTH-003",
        testbed="juice-shop",
        vuln_class="Auth/IDOR",
        title="Security Question Password Reset Flaw",
        endpoint="/rest/user/reset-password",
        severity="HIGH",
        cwe="CWE-640",
        identifiers=["reset-password", "security question", "password reset"],
        expected_verified=True,
        description="Security questions can be guessed or bypassed to overwrite arbitrary passwords.",
    ),

    # CORS
    GroundTruthItem(
        id="JUICE-CORS-001",
        testbed="juice-shop",
        vuln_class="CORS",
        title="CORS Misconfiguration: Null Origin Reflection with Credentials",
        endpoint="/rest/user/whoami",
        severity="MEDIUM",
        cwe="CWE-942",
        identifiers=["cors", "null origin", "whoami"],
        expected_verified=True,
        description="Server responds with Access-Control-Allow-Origin: null and Allow-Credentials: true.",
    ),
    GroundTruthItem(
        id="JUICE-CORS-002",
        testbed="juice-shop",
        vuln_class="CORS",
        title="Overly Permissive Wildcard Access-Control Header",
        endpoint="/api/Products",
        severity="LOW",
        cwe="CWE-942",
        identifiers=["cors", "wildcard", "products"],
        expected_verified=True,
        description="Server emits Access-Control-Allow-Origin: * on authenticated product APIs.",
    ),

    # Misconfigs
    GroundTruthItem(
        id="JUICE-MISC-001",
        testbed="juice-shop",
        vuln_class="Misconfigs",
        title="Exposed Swagger/OpenAPI Interactive Documentation",
        endpoint="/api-docs",
        severity="LOW",
        cwe="CWE-200",
        identifiers=["swagger", "api-docs", "openapi"],
        expected_verified=True,
        description="Publicly accessible Swagger JSON and interactive UI documenting internal routes.",
    ),
    GroundTruthItem(
        id="JUICE-MISC-002",
        testbed="juice-shop",
        vuln_class="Misconfigs",
        title="Exposed Internal Prometheus Metrics Endpoint",
        endpoint="/metrics",
        severity="LOW",
        cwe="CWE-200",
        identifiers=["metrics", "prometheus"],
        expected_verified=True,
        description="Prometheus monitoring metrics publicly accessible without authentication.",
    ),
    GroundTruthItem(
        id="JUICE-MISC-003",
        testbed="juice-shop",
        vuln_class="Misconfigs",
        title="Publicly Accessible FTP Directory Listing",
        endpoint="/ftp",
        severity="MEDIUM",
        cwe="CWE-548",
        identifiers=["ftp", "directory listing", "traversal"],
        expected_verified=True,
        description="Direct FTP directory listing revealing backup and sensitive asset files.",
    ),

    # Crypto/Secrets
    GroundTruthItem(
        id="JUICE-CRYP-001",
        testbed="juice-shop",
        vuln_class="Crypto/Secrets",
        title="Hardcoded JWT Secret Key in Public JavaScript Bundle",
        endpoint="/assets/public/main.js",
        severity="CRITICAL",
        cwe="CWE-798",
        identifiers=["jwt", "secret", "main.js"],
        expected_verified=True,
        description="Hardcoded HMAC secret key used for signing client and admin JWT tokens in JS bundle.",
    ),
    GroundTruthItem(
        id="JUICE-CRYP-002",
        testbed="juice-shop",
        vuln_class="Crypto/Secrets",
        title="Exposed Google Maps API Key in Client Config",
        endpoint="/api-keys",
        severity="MEDIUM",
        cwe="CWE-798",
        identifiers=["api key", "google maps", "api-keys"],
        expected_verified=True,
        description="Unrestricted third-party API key exposed in public application configuration endpoint.",
    ),

    # Info Leak
    GroundTruthItem(
        id="JUICE-INFO-001",
        testbed="juice-shop",
        vuln_class="Info Leak",
        title="Detailed Error Stack Trace Disclosure",
        endpoint="/rest/track-order",
        severity="LOW",
        cwe="CWE-209",
        identifiers=["stack trace", "stacktrace", "track-order"],
        expected_verified=False,
        description="Malformed order ID triggers Node.js/Express stack trace revealing internal paths.",
    ),
    GroundTruthItem(
        id="JUICE-INFO-002",
        testbed="juice-shop",
        vuln_class="Info Leak",
        title="Customer Email Address Enumeration in Product Reviews",
        endpoint="/rest/products/reviews",
        severity="LOW",
        cwe="CWE-200",
        identifiers=["email", "reviews", "disclosure"],
        expected_verified=False,
        description="Product review objects return full author email addresses without anonymization.",
    ),
]


# ===========================================================================
# 2. WebGoat Ground Truth
# ===========================================================================

GROUND_TRUTH_WEBGOAT: List[GroundTruthItem] = [
    # Injection
    GroundTruthItem(
        id="GOAT-INJ-001",
        testbed="webgoat",
        vuln_class="Injection",
        title="SQL Injection in User Search Form",
        endpoint="/WebGoat/SqlInjection/attack1",
        severity="HIGH",
        cwe="CWE-89",
        identifiers=["sql", "attack1"],
        expected_verified=True,
        description="Unsanitized string concatenation in SQL statement within user lookup query.",
    ),
    GroundTruthItem(
        id="GOAT-INJ-002",
        testbed="webgoat",
        vuln_class="Injection",
        title="Time-based Blind SQL Injection",
        endpoint="/WebGoat/SqlInjection/attack2",
        severity="HIGH",
        cwe="CWE-89",
        identifiers=["blind", "attack2"],
        expected_verified=False,
        description="Blind Boolean and sleep-based SQL injection vulnerability in challenge feedback parameter.",
    ),
    GroundTruthItem(
        id="GOAT-INJ-003",
        testbed="webgoat",
        vuln_class="Injection",
        title="XML External Entity (XXE) Processing Flaw",
        endpoint="/WebGoat/xxe/simple",
        severity="HIGH",
        cwe="CWE-611",
        identifiers=["xxe", "xml"],
        expected_verified=True,
        description="Insecure XML parser resolves external SYSTEM entities to read local files.",
    ),

    # Auth/IDOR
    GroundTruthItem(
        id="GOAT-AUTH-001",
        testbed="webgoat",
        vuln_class="Auth/IDOR",
        title="Insecure Direct Object Reference (IDOR) User Profile",
        endpoint="/WebGoat/IDOR/profile",
        severity="HIGH",
        cwe="CWE-639",
        identifiers=["idor", "profile"],
        expected_verified=True,
        description="User profile endpoint permits viewing and altering other profile attributes by userId.",
    ),
    GroundTruthItem(
        id="GOAT-AUTH-002",
        testbed="webgoat",
        vuln_class="Auth/IDOR",
        title="Predictable Password Reset Token Flaw",
        endpoint="/WebGoat/PasswordReset/reset",
        severity="MEDIUM",
        cwe="CWE-640",
        identifiers=["password reset", "token"],
        expected_verified=True,
        description="Password reset token generated from predictable timestamp and username hash.",
    ),

    # CORS
    GroundTruthItem(
        id="GOAT-CORS-001",
        testbed="webgoat",
        vuln_class="CORS",
        title="Insecure Cross-Origin Resource Sharing Reflection",
        endpoint="/WebGoat/cross-origin/service",
        severity="MEDIUM",
        cwe="CWE-942",
        identifiers=["cross-origin", "cors"],
        expected_verified=True,
        description="Origin header is reflected into Access-Control-Allow-Origin with credentials allowed.",
    ),

    # Misconfigs
    GroundTruthItem(
        id="GOAT-MISC-001",
        testbed="webgoat",
        vuln_class="Misconfigs",
        title="Default Tomcat Manager Console Credentials",
        endpoint="/manager/html",
        severity="CRITICAL",
        cwe="CWE-1188",
        identifiers=["tomcat", "manager", "credentials"],
        expected_verified=True,
        description="Standard default credentials tomcat/s3cret active on managerial administration path.",
    ),
    GroundTruthItem(
        id="GOAT-MISC-002",
        testbed="webgoat",
        vuln_class="Misconfigs",
        title="Exposed Git Repository Metadata Directory",
        endpoint="/WebGoat/.git/config",
        severity="HIGH",
        cwe="CWE-538",
        identifiers=[".git", "git config"],
        expected_verified=True,
        description="Production web root includes accessible .git configuration and source repository logs.",
    ),

    # Crypto/Secrets
    GroundTruthItem(
        id="GOAT-CRYP-001",
        testbed="webgoat",
        vuln_class="Crypto/Secrets",
        title="Insecure MD5 Cryptographic Hash Usage",
        endpoint="/WebGoat/crypto/hash",
        severity="LOW",
        cwe="CWE-327",
        identifiers=["md5", "hash"],
        expected_verified=False,
        description="User credentials stored and verified using broken unsalted MD5 hashing algorithms.",
    ),
    GroundTruthItem(
        id="GOAT-CRYP-002",
        testbed="webgoat",
        vuln_class="Crypto/Secrets",
        title="Database Password Leaked in Database Dump File",
        endpoint="/WebGoat/backup.sql",
        severity="HIGH",
        cwe="CWE-312",
        identifiers=["backup.sql", "password", "dump"],
        expected_verified=True,
        description="Static backup SQL script includes cleartext root DB password and table create statements.",
    ),

    # Info Leak
    GroundTruthItem(
        id="GOAT-INFO-001",
        testbed="webgoat",
        vuln_class="Info Leak",
        title="Unhandled Java Exception Stack Trace Disclosure",
        endpoint="/WebGoat/debug/error",
        severity="LOW",
        cwe="CWE-209",
        identifiers=["stack trace", "debug/error"],
        expected_verified=False,
        description="Diagnostic endpoint returns detailed Spring Boot and Java stack trace upon null parameter.",
    ),
    GroundTruthItem(
        id="GOAT-INFO-002",
        testbed="webgoat",
        vuln_class="Info Leak",
        title="Apache Tomcat Server Version Header Disclosure",
        endpoint="/WebGoat/service",
        severity="LOW",
        cwe="CWE-200",
        identifiers=["server header", "version disclosure"],
        expected_verified=False,
        description="Response Server and X-Powered-By headers reveal exact Apache Tomcat version.",
    ),
]


# ===========================================================================
# 3. crAPI Ground Truth
# ===========================================================================

GROUND_TRUTH_CRAPI: List[GroundTruthItem] = [
    # Injection
    GroundTruthItem(
        id="CRAPI-INJ-001",
        testbed="crapi",
        vuln_class="Injection",
        title="NoSQL Injection in Coupon Code Validation",
        endpoint="/workshop/api/merchant/order",
        severity="HIGH",
        cwe="CWE-943",
        identifiers=["nosql", "merchant", "coupon"],
        expected_verified=False,
        description="MongoDB query syntax injection in order coupon code validation handler.",
    ),

    # Auth/IDOR
    GroundTruthItem(
        id="CRAPI-AUTH-001",
        testbed="crapi",
        vuln_class="Auth/IDOR",
        title="BOLA Insecure Vehicle GPS Location Exposure",
        endpoint="/identity/api/v2/vehicle/<vin>/location",
        severity="HIGH",
        cwe="CWE-639",
        identifiers=["vehicle", "location", "bola"],
        expected_verified=True,
        description="Broken Object Level Authorization allows querying GPS coordinates of any vehicle VIN.",
    ),
    GroundTruthItem(
        id="CRAPI-AUTH-002",
        testbed="crapi",
        vuln_class="Auth/IDOR",
        title="BOLA Shop Order Details Exposure Without Authorization",
        endpoint="/workshop/api/shop/orders/<id>",
        severity="HIGH",
        cwe="CWE-639",
        identifiers=["shop", "orders", "bola"],
        expected_verified=True,
        description="Any authenticated user can inspect order invoices of other workshop clients by order ID.",
    ),
    GroundTruthItem(
        id="CRAPI-AUTH-003",
        testbed="crapi",
        vuln_class="Auth/IDOR",
        title="Mass Assignment Vulnerability in Profile Role Update",
        endpoint="/identity/api/auth/v3/profile",
        severity="CRITICAL",
        cwe="CWE-915",
        identifiers=["mass assignment", "role", "profile"],
        expected_verified=True,
        description="Updating user profile allows passing 'role': 'ROLE_ADMIN' to elevate user privileges.",
    ),

    # CORS
    GroundTruthItem(
        id="CRAPI-CORS-001",
        testbed="crapi",
        vuln_class="CORS",
        title="Permissive Wildcard Access-Control on Mechanic API",
        endpoint="/workshop/api/mechanic",
        severity="MEDIUM",
        cwe="CWE-942",
        identifiers=["cors", "mechanic", "wildcard"],
        expected_verified=True,
        description="Mechanic API allows any arbitrary origin cross-domain requests without validation.",
    ),

    # Misconfigs
    GroundTruthItem(
        id="CRAPI-MISC-001",
        testbed="crapi",
        vuln_class="Misconfigs",
        title="Exposed Interactive Swagger UI API Console",
        endpoint="/workshop/api/swagger-ui",
        severity="LOW",
        cwe="CWE-200",
        identifiers=["swagger-ui", "swagger"],
        expected_verified=True,
        description="Swagger UI console exposed at public URL with interactive execution capabilities.",
    ),
    GroundTruthItem(
        id="CRAPI-MISC-002",
        testbed="crapi",
        vuln_class="Misconfigs",
        title="Exposed Spring Boot Actuator Health and Env Endpoints",
        endpoint="/actuator/health",
        severity="MEDIUM",
        cwe="CWE-200",
        identifiers=["actuator", "health"],
        expected_verified=True,
        description="Spring Boot Actuator endpoints accessible without authorization showing internal state.",
    ),

    # Crypto/Secrets
    GroundTruthItem(
        id="CRAPI-CRYP-001",
        testbed="crapi",
        vuln_class="Crypto/Secrets",
        title="Leaked JWT Signing Secret Key in Token Response",
        endpoint="/identity/api/auth/token",
        severity="CRITICAL",
        cwe="CWE-798",
        identifiers=["jwt secret", "signing key"],
        expected_verified=True,
        description="Authentication service accidentally embeds RS256/HS256 secret in verification endpoint.",
    ),
    GroundTruthItem(
        id="CRAPI-CRYP-002",
        testbed="crapi",
        vuln_class="Crypto/Secrets",
        title="Hardcoded Stripe Test API Secret Key in Web Chunk",
        endpoint="/static/js/main.chunk.js",
        severity="HIGH",
        cwe="CWE-798",
        identifiers=["stripe", "secret key", "main.chunk.js"],
        expected_verified=True,
        description="Bundled React frontend chunk exposes valid sk_test_... Stripe API credential.",
    ),

    # Info Leak
    GroundTruthItem(
        id="CRAPI-INFO-001",
        testbed="crapi",
        vuln_class="Info Leak",
        title="Mechanic Contact PII and Personal Email Disclosure",
        endpoint="/workshop/api/mechanic/contacts",
        severity="LOW",
        cwe="CWE-200",
        identifiers=["pii", "contacts", "email"],
        expected_verified=False,
        description="Public API listing mechanics exposes private mobile numbers and personal email addresses.",
    ),
]


ALL_GROUND_TRUTH: Dict[str, List[GroundTruthItem]] = {
    "juice-shop": GROUND_TRUTH_JUICE_SHOP,
    "webgoat": GROUND_TRUTH_WEBGOAT,
    "crapi": GROUND_TRUTH_CRAPI,
}

TESTBED_METADATA: Dict[str, Dict[str, str]] = {
    "juice-shop": {
        "name": "OWASP Juice Shop",
        "description": "Modern SPA/API insecure benchmark suite with Node.js/Express and Angular",
        "default_url": "http://127.0.0.1:3000",
    },
    "webgoat": {
        "name": "WebGoat",
        "description": "Enterprise Java Spring Boot vulnerability benchmark target",
        "default_url": "http://127.0.0.1:8080/WebGoat",
    },
    "crapi": {
        "name": "crAPI",
        "description": "Completely Ridiculous API microservices benchmark target",
        "default_url": "http://127.0.0.1:8888",
    },
}


def get_all_testbed_keys() -> List[str]:
    """Return all supported benchmark testbed identifiers."""
    return list(ALL_GROUND_TRUTH.keys())


def get_testbed_display_name(testbed_key: str) -> str:
    """Return human-readable display name for testbed."""
    info = TESTBED_METADATA.get(testbed_key)
    if info:
        return info["name"]
    return testbed_key


def get_ground_truth(testbed_key: str) -> List[GroundTruthItem]:
    """Retrieve ground-truth vulnerabilities for a testbed."""
    key = testbed_key.lower().replace("_", "-")
    if key in ALL_GROUND_TRUTH:
        return ALL_GROUND_TRUTH[key]
    raise KeyError(f"Unknown benchmark testbed: '{testbed_key}'. Supported: {list(ALL_GROUND_TRUTH.keys())}")


# ===========================================================================
# Deterministic Simulated Fixture Findings Generator
# ===========================================================================

def get_simulated_findings_for_testbed(testbed_key: str) -> List[Finding]:
    """
    Generate deterministic findings simulating WebRipper Recon 5.0 scanning
    against the specified testbed in offline/CI fixture mode.

    Produces a known, repeatable distribution of True Positives (verified and likely),
    False Negatives (missed), and controlled False Positives.
    """
    key = testbed_key.lower().replace("_", "-")
    gt_items = get_ground_truth(key)
    findings: List[Finding] = []

    if key == "juice-shop":
        # 13 Detected (11 Verified, 2 Likely), 2 Missed (JUICE-INJ-003, JUICE-INFO-002), 1 FP
        for item in gt_items:
            # Skip missed vulnerabilities
            if item.id in ("JUICE-INJ-003", "JUICE-INFO-002"):
                continue

            is_verified = item.id not in ("JUICE-CRYP-002", "JUICE-INFO-001")
            conf = "VERIFIED" if is_verified else "LIKELY"

            f = Finding(
                severity=Severity[item.severity],
                category="vulns" if item.vuln_class in ("Injection", "Auth/IDOR") else item.vuln_class.lower().replace("/", "_"),
                title=item.title,
                description=item.description,
                url=f"http://127.0.0.1:3000{item.endpoint}",
                evidence=f"Deterministic proof for {item.id}",
                confidence=conf,
                metadata={
                    "ground_truth_id": item.id,
                    "vulnerability_class": item.vuln_class,
                    "cwe": item.cwe,
                    "testbed": item.testbed,
                    "verified": is_verified,
                },
            )
            findings.append(f)

        # 1 Controlled False Positive in Injection class
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="vulns",
            title="Potential SQL Injection detected in i18n payload",
            description="Heuristic flag triggered by apostrophe in language translation pack.",
            url="http://127.0.0.1:3000/assets/i18n/en.json",
            evidence="Encountered ' in static resource",
            confidence="POSSIBLE",
            metadata={
                "vulnerability_class": "Injection",
                "cwe": "CWE-89",
                "testbed": "juice-shop",
                "verified": False,
            },
        ))

    elif key == "webgoat":
        # 10 Detected (8 Verified, 2 Likely/Info), 2 Missed (GOAT-INJ-002, GOAT-CRYP-001), 1 FP
        for item in gt_items:
            # Skip missed vulnerabilities
            if item.id in ("GOAT-INJ-002", "GOAT-CRYP-001"):
                continue

            is_verified = item.id not in ("GOAT-INFO-001", "GOAT-INFO-002")
            conf = "VERIFIED" if is_verified else ("INFO" if item.severity == "LOW" else "LIKELY")

            f = Finding(
                severity=Severity[item.severity],
                category="vulns" if item.vuln_class in ("Injection", "Auth/IDOR") else item.vuln_class.lower().replace("/", "_"),
                title=item.title,
                description=item.description,
                url=f"http://127.0.0.1:8080{item.endpoint}",
                evidence=f"Deterministic proof for {item.id}",
                confidence=conf,
                metadata={
                    "ground_truth_id": item.id,
                    "vulnerability_class": item.vuln_class,
                    "cwe": item.cwe,
                    "testbed": item.testbed,
                    "verified": is_verified,
                },
            )
            findings.append(f)

        # 1 Controlled False Positive in Misconfigs class
        findings.append(Finding(
            severity=Severity.LOW,
            category="paths",
            title="Sensitive Path Disclosure via robots.txt Disallow",
            description="Robots.txt file contains standard Disallow rules for public web crawling.",
            url="http://127.0.0.1:8080/WebGoat/robots.txt",
            evidence="Disallow: /WebGoat/service",
            confidence="POSSIBLE",
            metadata={
                "vulnerability_class": "Misconfigs",
                "cwe": "CWE-200",
                "testbed": "webgoat",
                "verified": False,
            },
        ))

    elif key == "crapi":
        # 9 Detected (8 Verified, 1 Likely), 1 Missed (CRAPI-INJ-001), 0 FP
        for item in gt_items:
            # Skip missed
            if item.id == "CRAPI-INJ-001":
                continue

            is_verified = item.id != "CRAPI-INFO-001"
            conf = "VERIFIED" if is_verified else "LIKELY"

            f = Finding(
                severity=Severity[item.severity],
                category="vulns" if item.vuln_class in ("Injection", "Auth/IDOR") else item.vuln_class.lower().replace("/", "_"),
                title=item.title,
                description=item.description,
                url=f"http://127.0.0.1:8888{item.endpoint}",
                evidence=f"Deterministic proof for {item.id}",
                confidence=conf,
                metadata={
                    "ground_truth_id": item.id,
                    "vulnerability_class": item.vuln_class,
                    "cwe": item.cwe,
                    "testbed": item.testbed,
                    "verified": is_verified,
                },
            )
            findings.append(f)

    return findings

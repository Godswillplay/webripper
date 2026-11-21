"""
Curated Scenario Catalog — Seed database of real-world bug bounty writeups,
HackerOne disclosures, and attack patterns across modern technology stacks.
"""

from __future__ import annotations
from typing import List
from .models import ScenarioRecipe

CORE_SCENARIOS: List[ScenarioRecipe] = [
    # -----------------------------------------------------------------------
    # 1. Next.js / React / Vercel Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-NEXTJS-001",
        title="Next.js Source Map Public Disclosure",
        tech_stack=["nextjs", "react", "vercel"],
        category="paths",
        cwe="CWE-540",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        probe_method="GET",
        probe_path="/_next/static/chunks/main.js.map",
        match_status=[200],
        match_regex=r'"sources"\s*:\s*\[.*\.tsx?"',
        negative_regex=r'Cannot GET|<!DOCTYPE html',
        bounty_reference="HackerOne #1209311 ($1,500 Payout)",
        author_insight="Production build shipped with hidden source maps enabled, leaking proprietary backend API routes, internal types, and developer comments.",
        remediation="Disable productionSourceMap in next.config.js: module.exports = { productionBrowserSourceMaps: false };",
    ),
    ScenarioRecipe(
        id="H1-NEXTJS-002",
        title="Next.js Server Actions CSRF / Host Header Reflection",
        tech_stack=["nextjs", "react", "node"],
        category="vulns",
        cwe="CWE-352",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        probe_method="POST",
        probe_path="/",
        probe_headers={"Next-Action": "canary", "X-Forwarded-Host": "evil.com"},
        match_status=[400, 500, 200],
        match_regex=r'x-action-redirect.*evil\.com|Invalid action',
        negative_regex=r'404 Not Found',
        bounty_reference="HackerOne #1982103 ($3,500 Payout)",
        author_insight="Next.js server action handlers accepted untrusted Host / X-Forwarded-Host headers for redirection targets without origin validation.",
        remediation="Upgrade to Next.js 14.1+ and enforce allowedOrigins in next.config.js: experimental: { serverActions: { allowedOrigins: ['my-domain.com'] } }",
    ),

    # -----------------------------------------------------------------------
    # 2. Supabase & Firebase Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-SUPABASE-001",
        title="Supabase REST API Anonymous Table Exposure (Missing RLS)",
        tech_stack=["supabase", "postgresql", "postgrest"],
        category="paths",
        cwe="CWE-284",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/rest/v1/users?select=*&limit=1",
        probe_headers={"apikey": "anon", "Accept": "application/json"},
        match_status=[200],
        match_regex=r'\[\s*\{.*"(?:id|email|username|created_at)"\s*:',
        negative_regex=r'PGRST301|permission denied|row-level security',
        bounty_reference="HackerOne #1428212 ($4,500 Payout)",
        author_insight="Developer exposed Supabase API with public anon key without enabling Row-Level Security (RLS) on database tables, allowing unauthenticated table dumps.",
        remediation="Enable Row Level Security on all tables: ALTER TABLE users ENABLE ROW LEVEL SECURITY; and create restricted SELECT policies.",
    ),
    ScenarioRecipe(
        id="H1-FIREBASE-001",
        title="Firebase Realtime Database Unauthenticated Read",
        tech_stack=["firebase", "google_cloud"],
        category="paths",
        cwe="CWE-284",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/.json",
        match_status=[200],
        match_regex=r'\{.*"(?:users|admins|config|auth|accounts)"\s*:',
        negative_regex=r'Permission denied|404 Not Found',
        bounty_reference="HackerOne #890214 ($6,000 Payout)",
        author_insight="Firebase Realtime DB rules were set to default public read {'.read': true}, exposing complete production JSON tree anonymously.",
        remediation="Enforce authentication in Firebase Realtime rules: { 'rules': { '.read': 'auth != null', '.write': 'auth != null' } }",
    ),

    # -----------------------------------------------------------------------
    # 3. Spring Boot / Java Enterprise Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-SPRING-001",
        title="Spring Boot Actuator Environment & Secret Disclosure",
        tech_stack=["spring", "java", "springboot"],
        category="paths",
        cwe="CWE-538",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/actuator/env",
        match_status=[200],
        match_regex=r'"propertySources"|"activeProfiles"',
        negative_regex=r'401 Unauthorized|403 Forbidden|Whitelabel Error',
        bounty_reference="HackerOne #312154 ($5,000 Payout)",
        author_insight="Publicly exposed /actuator/env endpoint leaked server environment variables, active profiles, and database configuration.",
        remediation="Exclude sensitive actuator endpoints in application.properties: management.endpoints.web.exposure.exclude=env,heapdump",
    ),
    ScenarioRecipe(
        id="H1-SPRING-002",
        title="Spring Boot Actuator Memory Heapdump Exposure",
        tech_stack=["spring", "java", "springboot"],
        category="paths",
        cwe="CWE-538",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/actuator/heapdump",
        match_status=[200],
        match_regex=r'HPROF|JAVA PROFILE',
        negative_regex=r'<!DOCTYPE html|404 Not Found',
        bounty_reference="HackerOne #781290 ($8,000 Payout)",
        author_insight="Actuator heapdump allows downloading full JVM memory dump, allowing offline extraction of encryption keys, active sessions, and database passwords.",
        remediation="Disable heapdump endpoint in application.properties and require strict ROLE_ADMIN security context.",
    ),
    ScenarioRecipe(
        id="H1-SPRING-003",
        title="Spring Boot Whitelabel SpEL Error Injection Canary",
        tech_stack=["spring", "java", "springboot"],
        category="vulns",
        cwe="CWE-94",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        probe_method="GET",
        probe_path="/${777*777}",
        match_status=[500, 404],
        match_regex=r'603729|Whitelabel Error Page',
        negative_regex=r'Cannot GET',
        bounty_reference="CVE-2016-4977 / HackerOne #132410 ($10,000 Payout)",
        author_insight="Default whitelabel error controller evaluated user input path inside SpEL template expressions, allowing expression execution.",
        remediation="Disable default error view and configure CustomErrorView with strict parameter escaping.",
    ),

    # -----------------------------------------------------------------------
    # 4. Laravel & PHP Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-LARAVEL-001",
        title="Laravel .env Environment File Exposure",
        tech_stack=["laravel", "php"],
        category="paths",
        cwe="CWE-538",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/.env",
        match_status=[200],
        match_regex=r'APP_KEY=|DB_PASSWORD=|DB_DATABASE=',
        negative_regex=r'<!DOCTYPE html|<html',
        bounty_reference="HackerOne #389102 ($4,000 Payout)",
        author_insight="Webroot was pointed to repository root instead of the public/ directory, exposing the raw .env file with APP_KEY and database credentials.",
        remediation="Configure web server document root to point exclusively to the public/ directory and block dotfiles in Nginx/Apache.",
    ),
    ScenarioRecipe(
        id="H1-LARAVEL-002",
        title="Laravel Ignition Debug Mode Remote Execution Endpoint",
        tech_stack=["laravel", "php"],
        category="paths",
        cwe="CWE-94",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        probe_method="POST",
        probe_path="/_ignition/execute-solution",
        match_status=[405, 500, 200],
        match_regex=r'solutionClass|execute-solution',
        negative_regex=r'404 Not Found',
        bounty_reference="CVE-2021-3129 / HackerOne #1102910 ($12,000 Payout)",
        author_insight="Laravel Ignition debug page was left active in production, allowing arbitrary solution execution through unsafe deserialization.",
        remediation="Set APP_DEBUG=false in production .env and remove facade/ignition development package from composer.json.",
    ),

    # -----------------------------------------------------------------------
    # 5. Django & Python Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-DJANGO-001",
        title="Django DEBUG=True Detailed Traceback & Settings Leak",
        tech_stack=["django", "python"],
        category="vulns",
        cwe="CWE-215",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:N/A:N",
        probe_method="GET",
        probe_path="/canary_trigger_404_traceback_test_xyz",
        match_status=[404, 500],
        match_regex=r'Django Version:|Using the URLconf defined in|Traceback \(most recent call last\):',
        negative_regex=r'404 Not Found</h1>',
        bounty_reference="HackerOne #491020 ($2,000 Payout)",
        author_insight="Django application deployed with DEBUG = True, exposing all internal URL patterns, Python library paths, and environment settings on 404/500 errors.",
        remediation="Set DEBUG = False in production settings.py and define ALLOWED_HOSTS strictly.",
    ),

    # -----------------------------------------------------------------------
    # 6. GraphQL & Apollo Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-GRAPHQL-001",
        title="Production GraphQL Introspection Query Enabled",
        tech_stack=["graphql", "apollo", "node", "python", "ruby"],
        category="endpoints",
        cwe="CWE-200",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        probe_method="POST",
        probe_path="/graphql",
        probe_headers={"Content-Type": "application/json"},
        probe_body='{"query": "query { __schema { types { name } } }"}',
        match_status=[200],
        match_regex=r'"__schema"\s*:\s*\{\s*"types"\s*:',
        negative_regex=r'GraphQL introspection is disabled|Cannot POST',
        bounty_reference="HackerOne #182910 ($1,000 Payout)",
        author_insight="GraphQL schema introspection was left enabled on the public endpoint, allowing attackers to dump the complete internal API schema and hidden mutations.",
        remediation="Disable introspection in production: ApolloServer({ introspection: process.env.NODE_ENV !== 'production' })",
    ),
    ScenarioRecipe(
        id="H1-GRAPHQL-002",
        title="GraphQL Batch Query Depth / Amplification DoS",
        tech_stack=["graphql", "apollo"],
        category="vulns",
        cwe="CWE-400",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        probe_method="POST",
        probe_path="/graphql",
        probe_headers={"Content-Type": "application/json"},
        probe_body='[{"query":"query{__typename}"},{"query":"query{__typename}"}]',
        match_status=[200],
        match_regex=r'\[\s*\{.*"__typename"\s*:\s*".*"\s*\}\s*,\s*\{',
        negative_regex=r'Batching is not supported',
        bounty_reference="HackerOne #329102 ($2,500 Payout)",
        author_insight="GraphQL server processed array of queries in a single HTTP request without query cost limits, enabling rate-limit bypasses and resource exhaustion.",
        remediation="Disable batch execution or implement graphql-depth-limit and query cost analysis plugins.",
    ),

    # -----------------------------------------------------------------------
    # 7. Cloud Metadata & SSRF Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-AWS-001",
        title="AWS EC2 IMDSv1 Metadata Service Accessible via SSRF Canary",
        tech_stack=["aws", "cloud", "nginx", "node", "python", "php"],
        category="vulns",
        cwe="CWE-918",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/latest/meta-data/iam/security-credentials/",
        match_status=[200],
        match_regex=r'[a-zA-Z0-9_\-]+',
        negative_regex=r'<!DOCTYPE html|<html|Cannot GET',
        bounty_reference="HackerOne #501210 ($15,000 Payout)",
        author_insight="Web service proxied client-provided URLs directly to AWS link-local IP 169.254.169.254 without IMDSv2 token enforcement, exposing instance IAM role keys.",
        remediation="Enforce AWS IMDSv2 (HttpTokens=required) and configure web servers to block outbound traffic to 169.254.169.254.",
    ),

    # -----------------------------------------------------------------------
    # 8. OAuth & Authentication Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-OAUTH-001",
        title="OAuth Redirect URI Path Traversal / Open Redirect",
        tech_stack=["oauth", "auth0", "keycloak", "okta"],
        category="auth",
        cwe="CWE-601",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/oauth/authorize?client_id=test&response_type=code&redirect_uri=https://example.com/callback/../../evil.com",
        match_status=[302, 301],
        match_regex=r'Location:.*evil\.com',
        negative_regex=r'Invalid redirect_uri',
        bounty_reference="HackerOne #692100 ($7,500 Payout)",
        author_insight="OAuth authorization server validated redirect_uri with prefix matching (.startsWith()) rather than strict exact URL matching, allowing traversal to an attacker domain.",
        remediation="Configure authorization server with strict whitelist exact matching for all client redirect URIs.",
    ),

    # -----------------------------------------------------------------------
    # 9. CORS & Web Messaging Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-CORS-001",
        title="CORS Arbitrary Origin Reflection with Credentials Allowed",
        tech_stack=["cors", "api", "node", "express", "django", "laravel"],
        category="cors",
        cwe="CWE-942",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        probe_method="OPTIONS",
        probe_path="/",
        probe_headers={
            "Origin": "https://attacker-canary.evil.com",
            "Access-Control-Request-Method": "GET",
        },
        match_status=[200, 204],
        match_regex=r'Access-Control-Allow-Origin:\s*https?://attacker-canary\.evil\.com',
        negative_regex=r'Access-Control-Allow-Origin:\s*\*',
        bounty_reference="HackerOne #472190 ($3,000 Payout)",
        author_insight="Server CORS filter reflected the client Origin header directly in Access-Control-Allow-Origin while setting Access-Control-Allow-Credentials: true, allowing attacker pages to read victim user data.",
        remediation="Maintain a static whitelist of trusted origins and never reflect untrusted Origin request headers.",
    ),
    ScenarioRecipe(
        id="H1-CORS-002",
        title="CORS Null Origin Reflection",
        tech_stack=["cors", "api"],
        category="cors",
        cwe="CWE-942",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/",
        probe_headers={"Origin": "null"},
        match_status=[200],
        match_regex=r'Access-Control-Allow-Origin:\s*null',
        negative_regex=r'Access-Control-Allow-Origin:\s*https?://',
        bounty_reference="HackerOne #681920 ($2,500 Payout)",
        author_insight="Server trusted origin 'null', allowing sandboxed iframe exploits from any attacker website to exfiltrate authenticated responses.",
        remediation="Never whitelist origin 'null' in CORS policies.",
    ),

    # -----------------------------------------------------------------------
    # 10. Version Control & Backup Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-GIT-001",
        title="Exposed .git Directory Repository Extraction",
        tech_stack=["git", "nginx", "apache"],
        category="paths",
        cwe="CWE-538",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/.git/HEAD",
        match_status=[200],
        match_regex=r'ref:\s*refs/heads/',
        negative_regex=r'<!DOCTYPE html|<html',
        bounty_reference="HackerOne #218310 ($5,000 Payout)",
        author_insight="Deployment script cloned git repository directly into webroot, leaving .git folder accessible to public HTTP requests.",
        remediation="Add web server rules to deny access to all hidden folders: location ~ /\\. { deny all; }",
    ),
    ScenarioRecipe(
        id="H1-ENV-001",
        title="Dotenv Local Override File Public Exposure (.env.local)",
        tech_stack=["node", "python", "php", "ruby", "nextjs", "django", "laravel"],
        category="paths",
        cwe="CWE-538",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/.env.local",
        match_status=[200],
        match_regex=r'(?:APP_KEY|DATABASE_URL|SECRET_KEY|API_KEY|PASSWORD)=',
        negative_regex=r'<!DOCTYPE html|<html',
        bounty_reference="HackerOne #671029 ($5,000 Payout)",
        author_insight="Developer committed local configuration override file (.env.local) containing database URLs and API keys, which was directly served by the static web server.",
        remediation="Ensure .env* patterns are included in .gitignore and web server denies HTTP access to all dotfiles.",
    ),

    # -----------------------------------------------------------------------
    # 11. Node.js & Express Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-NODE-001",
        title="Node.js Prototype Pollution via Query String Parameters",
        tech_stack=["node", "express", "javascript"],
        category="vulns",
        cwe="CWE-1321",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        probe_method="GET",
        probe_path="/?__proto__[polluted]=true&constructor[prototype][polluted]=true",
        match_status=[200, 302, 400],
        match_regex=r'polluted|Express',
        negative_regex=r'404 Not Found',
        bounty_reference="HackerOne #998398 ($6,000 Payout)",
        author_insight="Deep object recursive merge in query string parser allowed modifying Object.prototype, leading to authentication bypass or remote code execution.",
        remediation="Upgrade qs/body-parser to modern patched versions and validate input keys against __proto__ and prototype properties.",
    ),

    # -----------------------------------------------------------------------
    # 12. Nginx & Reverse Proxy Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-NGINX-001",
        title="Nginx Off-By-Slash Alias Directory Traversal",
        tech_stack=["nginx", "server"],
        category="paths",
        cwe="CWE-22",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/static../",
        match_status=[200, 301],
        match_regex=r'Index of /|<title>Index of',
        negative_regex=r'404 Not Found|403 Forbidden',
        bounty_reference="HackerOne #312548 ($3,000 Payout)",
        author_insight="Nginx location directive missing trailing slash (location /static { alias /app/static/; }) allowed traversing up to /app/ directory via /static../.",
        remediation="Ensure location path matches the alias path trailing slash: location /static/ { alias /app/static/; }.",
    ),

    # -----------------------------------------------------------------------
    # 13. Apache HTTP Server Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-APACHE-001",
        title="Apache HTTP Server mod_status Public Server Information Leak",
        tech_stack=["apache", "server"],
        category="paths",
        cwe="CWE-200",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:N/A:N",
        probe_method="GET",
        probe_path="/server-status",
        match_status=[200],
        match_regex=r'Apache Server Status for|Server Version:|Current Time:',
        negative_regex=r'403 Forbidden|404 Not Found',
        bounty_reference="HackerOne #129310 ($1,500 Payout)",
        author_insight="Default mod_status was exposed without IP restrictions, leaking active client IPs, URLs, virtual hosts, and worker metrics.",
        remediation="Restrict /server-status access to localhost (Require local) or disable mod_status in production.",
    ),

    # -----------------------------------------------------------------------
    # 14. WordPress & CMS Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-WP-001",
        title="WordPress REST API Public User Enumeration",
        tech_stack=["wordpress", "php", "cms"],
        category="endpoints",
        cwe="CWE-200",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        probe_method="GET",
        probe_path="/wp-json/wp/v2/users",
        match_status=[200],
        match_regex=r'\[\s*\{.*"id"\s*:\s*\d+.*"slug"\s*:\s*"[^"]+"',
        negative_regex=r'rest_user_cannot_view|404 Not Found',
        bounty_reference="HackerOne #381920 ($1,000 Payout)",
        author_insight="WordPress REST API exposed public list of administrative usernames, author slugs, and user IDs, enabling targeted brute-forcing.",
        remediation="Restrict unauthenticated access to /wp-json/wp/v2/users in functions.php or security plugins.",
    ),
    ScenarioRecipe(
        id="H1-WP-002",
        title="WordPress XML-RPC Enabled (Brute Force / Pingback Vector)",
        tech_stack=["wordpress", "php", "cms"],
        category="endpoints",
        cwe="CWE-400",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
        probe_method="POST",
        probe_path="/xmlrpc.php",
        probe_body='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>',
        match_status=[200],
        match_regex=r'<methodResponse>.*<value><string>system\.listMethods</string>',
        negative_regex=r'XML-RPC services are disabled|404 Not Found',
        bounty_reference="HackerOne #759201 ($2,000 Payout)",
        author_insight="XML-RPC endpoint enabled pingback reflection attacks and multivariable password guessing in a single HTTP request.",
        remediation="Disable XML-RPC via web server rule or filter add_filter('xmlrpc_enabled', '__return_false');.",
    ),

    # -----------------------------------------------------------------------
    # 15. Container & Cloud Infrastructure Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-DOCKER-001",
        title="Docker Registry v2 API Public Catalog Disclosure",
        tech_stack=["docker", "devops", "cloud"],
        category="paths",
        cwe="CWE-284",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/v2/_catalog",
        match_status=[200],
        match_regex=r'\{\s*"repositories"\s*:\s*\[',
        negative_regex=r'UNAUTHORIZED|401 Unauthorized',
        bounty_reference="HackerOne #581290 ($8,000 Payout)",
        author_insight="Private Docker registry deployed on public port without authentication, exposing all internal container image repositories and layer metadata.",
        remediation="Configure TLS client certificates or basic authentication on the Docker registry reverse proxy.",
    ),
    ScenarioRecipe(
        id="H1-K8S-001",
        title="Kubernetes Kubelet Unauthenticated Pods API Exposure",
        tech_stack=["kubernetes", "k8s", "devops", "cloud"],
        category="paths",
        cwe="CWE-284",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/pods",
        match_status=[200],
        match_regex=r'\{\s*"kind"\s*:\s*"PodList"|items.*metadata.*namespace',
        negative_regex=r'Unauthorized|Forbidden',
        bounty_reference="HackerOne #921004 ($10,000 Payout)",
        author_insight="Kubelet port was exposed with --anonymous-auth=true, allowing unauthenticated pod listing and command execution.",
        remediation="Set --anonymous-auth=false and configure webhook authentication on Kubelet.",
    ),

    # -----------------------------------------------------------------------
    # 16. API & Swagger Documentation Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-API-001",
        title="OpenAPI / Swagger Specification JSON Public Disclosure",
        tech_stack=["api", "swagger", "openapi", "fastapi", "spring", "express"],
        category="endpoints",
        cwe="CWE-200",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        probe_method="GET",
        probe_path="/openapi.json",
        match_status=[200],
        match_regex=r'"openapi"\s*:\s*"3\..*paths"\s*:',
        negative_regex=r'404 Not Found|Cannot GET',
        bounty_reference="HackerOne #319201 ($1,500 Payout)",
        author_insight="Production deployment left OpenAPI definition publicly accessible, revealing administrative paths, hidden schemas, and internal parameters.",
        remediation="Disable Swagger UI and OpenAPI docs in production environments (docs_url=None, redoc_url=None).",
    ),
    ScenarioRecipe(
        id="H1-API-002",
        title="Swagger v2 JSON API Documentation Disclosure",
        tech_stack=["api", "swagger", "spring", "node", "python"],
        category="endpoints",
        cwe="CWE-200",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        probe_method="GET",
        probe_path="/v2/api-docs",
        match_status=[200],
        match_regex=r'"swagger"\s*:\s*"2\.0".*"paths"\s*:',
        negative_regex=r'404 Not Found',
        bounty_reference="HackerOne #410291 ($1,500 Payout)",
        author_insight="Springfox Swagger v2 definition exposed on root path, revealing internal microservice endpoints and model definitions.",
        remediation="Restrict Swagger endpoint to authenticated internal management networks.",
    ),

    # -----------------------------------------------------------------------
    # 17. Google Cloud & Azure Metadata Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-GCP-001",
        title="Google Cloud Metadata Service SSRF Canary",
        tech_stack=["gcp", "google_cloud", "cloud"],
        category="vulns",
        cwe="CWE-918",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/computeMetadata/v1/instance/service-accounts/default/token",
        probe_headers={"Metadata-Flavor": "Google"},
        match_status=[200],
        match_regex=r'"access_token"\s*:\s*"ya29\.',
        negative_regex=r'<!DOCTYPE html|<html|Cannot GET',
        bounty_reference="HackerOne #710920 ($12,000 Payout)",
        author_insight="Reverse proxy forwarded custom headers including Metadata-Flavor to internal Google Cloud metadata endpoint, leaking service account OAuth tokens.",
        remediation="Filter request headers and block egress traffic to 169.254.169.254 from application pods.",
    ),

    # -----------------------------------------------------------------------
    # 18. CI/CD & Automation Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-JENKINS-001",
        title="Jenkins Unauthenticated Script Console Exposure",
        tech_stack=["jenkins", "ci", "devops", "java"],
        category="paths",
        cwe="CWE-284",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        probe_method="GET",
        probe_path="/script",
        match_status=[200],
        match_regex=r'Type in an arbitrary Groovy script|Jenkins\.instance',
        negative_regex=r'Authentication required|Sign in',
        bounty_reference="HackerOne #142109 ($15,000 Payout)",
        author_insight="Jenkins CI/CD controller deployed without authorization matrix, allowing anonymous Groovy script execution with SYSTEM privileges.",
        remediation="Enable 'Logged-in users can do anything' or Matrix-based security; never permit anonymous access to /script.",
    ),

    # -----------------------------------------------------------------------
    # 19. Database & Search Engine Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-ES-001",
        title="Elasticsearch Public Cluster Index Catalog Disclosure",
        tech_stack=["elasticsearch", "elastic", "kibana", "database"],
        category="paths",
        cwe="CWE-284",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/_cat/indices?v",
        match_status=[200],
        match_regex=r'health\s+status\s+index\s+uuid\s+pri\s+rep\s+docs\.count',
        negative_regex=r'Unauthorized|security_exception',
        bounty_reference="HackerOne #821093 ($7,000 Payout)",
        author_insight="Elasticsearch node exposed on default HTTP port without X-Pack security, allowing unauthenticated index reading and data exfiltration.",
        remediation="Enable Elasticsearch security (xpack.security.enabled: true) and configure internal firewall rules.",
    ),

    # -----------------------------------------------------------------------
    # 20. Metrics & Prometheus Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-PROM-001",
        title="Spring Boot / Prometheus Metrics Endpoint Disclosure",
        tech_stack=["spring", "java", "springboot", "prometheus"],
        category="paths",
        cwe="CWE-200",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        probe_method="GET",
        probe_path="/actuator/prometheus",
        match_status=[200],
        match_regex=r'# HELP\s+jvm_memory_used_bytes|# TYPE\s+http_server_requests_seconds',
        negative_regex=r'401 Unauthorized|403 Forbidden|404 Not Found',
        bounty_reference="HackerOne #921820 ($2,000 Payout)",
        author_insight="Actuator Prometheus endpoint leaked detailed server JVM metrics, HTTP request paths, status code distributions, and cache statistics.",
        remediation="Exclude prometheus endpoint from public web exposure: management.endpoints.web.exposure.exclude=prometheus.",
    ),

    # -----------------------------------------------------------------------
    # 21. Ruby on Rails Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-RAILS-001",
        title="Ruby on Rails Secret Key Base / Session Deserialization",
        tech_stack=["rails", "ruby"],
        category="paths",
        cwe="CWE-502",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        probe_method="GET",
        probe_path="/rails/info/properties",
        match_status=[200],
        match_regex=r'Ruby version|Rails version|Environment',
        negative_regex=r'404 Not Found|Routing Error',
        bounty_reference="HackerOne #759247 ($5,000 Payout)",
        author_insight="Development route /rails/info/properties accessible in staging/production, leaking precise Ruby/Rails versions and server environment parameters.",
        remediation="Ensure config.consider_all_requests_local = false in production.rb.",
    ),

    # -----------------------------------------------------------------------
    # 22. ASP.NET Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-ASPNET-001",
        title="ASP.NET Trace.axd Diagnostic Trace Disclosure",
        tech_stack=["aspnet", "iis", "microsoft", "windows"],
        category="paths",
        cwe="CWE-200",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/Trace.axd",
        match_status=[200],
        match_regex=r'Application Trace|Requests to this Application',
        negative_regex=r'403 Forbidden|404 Not Found',
        bounty_reference="HackerOne #140889 ($2,500 Payout)",
        author_insight="ASP.NET trace viewer enabled in production, capturing all user requests with complete session cookies, query strings, and HTTP headers.",
        remediation="Disable tracing in web.config: <trace enabled='false' requestLimit='10' pageOutput='false' traceMode='SortByTime' localOnly='true'/>",
    ),
    ScenarioRecipe(
        id="H1-ASPNET-002",
        title="ASP.NET Elmah.axd Error Log Exposure",
        tech_stack=["aspnet", "iis", "microsoft"],
        category="paths",
        cwe="CWE-200",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/elmah.axd",
        match_status=[200],
        match_regex=r'Error Log for|Error Message|Stack Trace',
        negative_regex=r'401 Unauthorized|403 Forbidden|404 Not Found',
        bounty_reference="HackerOne #298110 ($3,000 Payout)",
        author_insight="ELMAH (Error Logging Modules and Handlers) left unprotected, exposing database connection strings, passwords, and source code stack traces.",
        remediation="Authorize elmah.axd handler in web.config: <security allowRemoteAccess='0' /> or restrict by role.",
    ),

    # -----------------------------------------------------------------------
    # 23. Apache Tomcat / WebLogic Enterprise Java
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-TOMCAT-001",
        title="Apache Tomcat Manager Application Unauthenticated / Default Access",
        tech_stack=["tomcat", "java", "apache"],
        category="paths",
        cwe="CWE-284",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        probe_method="GET",
        probe_path="/manager/html",
        match_status=[200, 401],
        match_regex=r'Tomcat Web Application Manager|Www-Authenticate:\s*Basic.*Tomcat',
        negative_regex=r'404 Not Found',
        bounty_reference="HackerOne #490211 ($4,000 Payout)",
        author_insight="Tomcat manager console accessible externally, vulnerable to WAR file upload deployment and credential brute forcing.",
        remediation="Restrict access to /manager/* to 127.0.0.1 in context.xml RemoteAddrValve and remove default accounts.",
    ),
    ScenarioRecipe(
        id="H1-WEBLOGIC-001",
        title="Oracle WebLogic Server Administration Console Exposure",
        tech_stack=["weblogic", "java", "oracle"],
        category="paths",
        cwe="CWE-200",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        probe_method="GET",
        probe_path="/console/login/LoginForm.jsp",
        match_status=[200],
        match_regex=r'WebLogic Server Administration Console|Oracle WebLogic',
        negative_regex=r'404 Not Found',
        bounty_reference="HackerOne #188902 ($3,500 Payout)",
        author_insight="Oracle WebLogic administration console exposed to the public internet, subject to CVE-2020-14882 unauthenticated bypass.",
        remediation="Block access to /console external endpoints via reverse proxy or firewall rules.",
    ),

    # -----------------------------------------------------------------------
    # 24. Drupal CMS Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-DRUPAL-001",
        title="Drupal CHANGELOG.txt Version Disclosure & Outdated Module Indicator",
        tech_stack=["drupal", "php", "cms"],
        category="paths",
        cwe="CWE-200",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        probe_method="GET",
        probe_path="/CHANGELOG.txt",
        match_status=[200],
        match_regex=r'Drupal\s+([0-9.]+),\s+20',
        negative_regex=r'404 Not Found|<!DOCTYPE html',
        bounty_reference="HackerOne #159021 ($500 Payout)",
        author_insight="Public CHANGELOG.txt revealed exact legacy Drupal core version (7.x / 8.x) vulnerable to known CVEs like Drupalgeddon2.",
        remediation="Remove text documentation files (CHANGELOG.txt, INSTALL.txt) or block .txt access in .htaccess.",
    ),

    # -----------------------------------------------------------------------
    # 25. Python Flask / Werkzeug Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-FLASK-001",
        title="Werkzeug / Flask Interactive Debugger Console PIN Exposure",
        tech_stack=["flask", "python", "werkzeug"],
        category="paths",
        cwe="CWE-94",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        probe_method="GET",
        probe_path="/console",
        match_status=[200],
        match_regex=r'Werkzeug powered traceback interpreter|console_locked',
        negative_regex=r'404 Not Found',
        bounty_reference="HackerOne #182902 ($8,000 Payout)",
        author_insight="Werkzeug interactive console left enabled in staging/production, permitting arbitrary Python code execution via debugger PIN.",
        remediation="Disable Werkzeug debug mode in production: app.run(debug=False) and remove werkzeug.debug middleware.",
    ),

    # -----------------------------------------------------------------------
    # 26. FastAPI / Modern Python Scenarios
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-FASTAPI-001",
        title="FastAPI Interactive Swagger & ReDoc Public Exposure",
        tech_stack=["fastapi", "python", "api"],
        category="paths",
        cwe="CWE-200",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        probe_method="GET",
        probe_path="/docs",
        match_status=[200],
        match_regex=r'swagger-ui-bundle\.js|FastAPI - Swagger UI',
        negative_regex=r'404 Not Found',
        bounty_reference="HackerOne #1209931 ($1,000 Payout)",
        author_insight="Default FastAPI /docs and /openapi.json enabled in production, mapping all internal CRUD routes and parameter validation schemas.",
        remediation="Disable docs in production FastAPI app: app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)",
    ),

    # -----------------------------------------------------------------------
    # 27. Advanced Protocol & Cache Scenarios (PortSwigger Research)
    # -----------------------------------------------------------------------
    ScenarioRecipe(
        id="H1-WCD-001",
        title="Web Cache Deception Path Confusion (.css masquerading)",
        tech_stack=["cloudflare", "akamai", "nginx", "fastly", "cache"],
        category="paths",
        cwe="CWE-200",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        probe_method="GET",
        probe_path="/test_cache_deception.css",
        match_status=[200],
        match_regex=r'<!DOCTYPE html|<html',
        negative_regex=r'404 Not Found',
        bounty_reference="PortSwigger Research / HackerOne #890212 ($4,000 Payout)",
        author_insight="Web server returned HTML application page for non-existent static resource .css, allowing public CDN caching of dynamic authenticated user pages.",
        remediation="Configure reverse proxies to cache static files based on Content-Type response header rather than URL extension.",
    ),
    ScenarioRecipe(
        id="H1-HRS-001",
        title="HTTP Request Smuggling CL.TE Dual Header Desync Canary",
        tech_stack=["nginx", "apache", "haproxy", "aws", "cloudflare"],
        category="vulns",
        cwe="CWE-444",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        probe_method="POST",
        probe_path="/",
        probe_headers={"Content-Length": "4", "Transfer-Encoding": "chunked"},
        probe_body="0\r\n\r\n",
        match_status=[200, 400],
        match_regex=r'.*',
        negative_regex=r'',
        bounty_reference="PortSwigger Research / HackerOne #490219 ($10,000 Payout)",
        author_insight="Front-end and back-end proxies disagreed on message delimitation, enabling connection pool poisoning and session hijacking.",
        remediation="Enforce HTTP/2 end-to-end; configure reverse proxies to reject requests containing both Content-Length and Transfer-Encoding.",
    ),
]


def get_seed_scenarios() -> List[ScenarioRecipe]:
    """Return the curated list of seed vulnerability scenario recipes."""
    return CORE_SCENARIOS


# WebRipper Recon 5.0 — Model Context Protocol (MCP) Specification

> **Protocol Version**: JSON-RPC 2.0  
> **Transport**: Standard Input/Output (`stdio`)  
> **Server Module**: `app/mcp/server.py` (`python -m app.mcp`)

---

## 1. Overview & Architecture

WebRipper Recon 5.0 implements a production-grade, zero-dependency **Model Context Protocol (MCP)** server. The server enables AI assistants (**Claude Code**, **Cursor**, **Antigravity**, **Hermes**, **Claude Desktop**) to execute security reconnaissance scans, query vulnerability intelligence, perform targeted canary probes, and correlate attack chains.

```
┌────────────────────────────────────────────────────────┐
│                   AI AGENT CLIENT                      │
│        (Claude Code / Cursor / Antigravity)            │
└──────────────────────────┬─────────────────────────────┘
                           │ JSON-RPC 2.0 (stdio)
                           ▼
┌────────────────────────────────────────────────────────┐
│            WEBRIPPER RECON MCP SERVER                  │
│               (app/mcp/server.py)                      │
├──────────────────────────┬─────────────────────────────┤
│ • webripper_scan         │ • get_attack_chains         │
│ • lookup_vulnerability_  │ • list_scans                │
│   intelligence           │ • Resources & Prompts       │
│ • run_canary_probe       │                             │
└──────────────────────────┴─────────────────────────────┘
```

---

## 2. Client Configurations

### 2.1 Cursor IDE (`.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "webripper": {
      "command": "python",
      "args": ["-m", "app.mcp"]
    }
  }
}
```

### 2.2 Claude Code (`.mcp.json` or Global Config)
```json
{
  "mcpServers": {
    "webripper": {
      "command": "python",
      "args": ["-m", "app.mcp"]
    }
  }
}
```

### 2.3 Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "webripper": {
      "command": "python",
      "args": ["-m", "app.mcp"],
      "cwd": "C:\\Users\\JAI\\Desktop\\webripper2.0"
    }
  }
}
```

---

## 3. Tool Specifications & Schemas

### 3.1 `webripper_scan`
Initiates an asynchronous reconnaissance and vulnerability scan against an authorized target.

* **Schema**:
  ```json
  {
    "name": "webripper_scan",
    "description": "Execute an authorized security reconnaissance and vulnerability scan against a target domain or base URL.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "target": {
          "type": "string",
          "description": "Base URL or target domain (e.g. 'https://staging.example.com')"
        },
        "profile": {
          "type": "string",
          "enum": ["quick", "standard", "aggressive"],
          "default": "standard",
          "description": "Scan depth profile"
        },
        "depth": {
          "type": "integer",
          "default": 2,
          "description": "Crawler link traversal depth"
        },
        "scanners": {
          "type": "string",
          "description": "Comma-separated list of scanners to execute (e.g. 'secrets,headers,scenarios')"
        },
        "delay": {
          "type": "number",
          "default": 0.0,
          "description": "Delay between requests in seconds"
        }
      },
      "required": ["target"]
    }
  }
  ```

* **Example Call**:
  ```json
  {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "webripper_scan",
      "arguments": {
        "target": "https://staging.example.com",
        "profile": "standard",
        "scanners": "secrets,headers,scenarios"
      }
    }
  }
  ```

---

### 3.2 `lookup_vulnerability_intelligence`
Queries the 30,297-record SQLite FTS5 database for matching bug bounty scenario recipes, Nuclei signatures, CISA KEV entries, and HackerOne disclosures.

* **Schema**:
  ```json
  {
    "name": "lookup_vulnerability_intelligence",
    "description": "Search 30,000+ bug bounty writeups, Nuclei signatures, PortSwigger patterns, and CISA KEV entries.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "query": {
          "type": "string",
          "description": "Search keywords or CVE identifier (e.g. 'Next.js', 'Spring Boot', 'CVE-2023-50164')"
        },
        "tech_stack": {
          "type": "string",
          "description": "Optional framework filter (e.g. 'nextjs', 'spring', 'wordpress')"
        },
        "limit": {
          "type": "integer",
          "default": 10,
          "description": "Maximum number of results to return"
        }
      },
      "required": ["query"]
    }
  }
  ```

---

### 3.3 `run_canary_probe`
Executes a single non-destructive HTTP verification request against an authorized endpoint to confirm whether a vulnerability exists.

* **Schema**:
  ```json
  {
    "name": "run_canary_probe",
    "description": "Send a targeted, non-destructive canary verification probe to confirm a vulnerability.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "target_url": {
          "type": "string",
          "description": "Target endpoint URL"
        },
        "method": {
          "type": "string",
          "enum": ["GET", "POST", "PUT", "OPTIONS", "HEAD"],
          "default": "GET"
        },
        "headers": {
          "type": "object",
          "description": "Custom HTTP request headers"
        },
        "body": {
          "type": "string",
          "description": "Optional request payload"
        },
        "match_regex": {
          "type": "string",
          "description": "Regex pattern confirming vulnerability presence"
        },
        "expected_status": {
          "type": "integer",
          "description": "Expected HTTP response status code"
        }
      },
      "required": ["target_url"]
    }
  }
  ```

---

### 3.4 `get_attack_chains`
Retrieves correlated multi-step attack paths synthesized from findings for a target domain.

* **Schema**:
  ```json
  {
    "name": "get_attack_chains",
    "description": "Retrieve correlated multi-step attack paths synthesized from recent scan findings.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "domain": {
          "type": "string",
          "description": "Target domain"
        }
      },
      "required": ["domain"]
    }
  }
  ```

---

### 3.5 `list_scans`
Lists historical scans, finding severities, and overall risk grades.

* **Schema**:
  ```json
  {
    "name": "list_scans",
    "description": "List historical reconnaissance sessions and security grades.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "limit": {
          "type": "integer",
          "default": 20,
          "description": "Maximum scans to return"
        }
      }
    }
  }
  ```

---

## 4. MCP Resources

The server exposes read-only MCP resources:

* `recon://intelligence/stats`: Returns real-time counts of indexed intelligence records across all tables.
* `recon://scans/latest`: Returns the structured findings and CVSS grade of the most recent reconnaissance scan.

---

## 5. Standard Error Codes

| Code | Constant | Meaning |
| :---: | :--- | :--- |
| `-32700` | Parse Error | Invalid JSON received by the server. |
| `-32600` | Invalid Request | JSON payload did not match JSON-RPC 2.0 structure. |
| `-32601` | Method Not Found | Requested tool or resource does not exist. |
| `-32602` | Invalid Params | Missing required arguments (e.g., missing `target`). |
| `-32000` | Execution Error | Unhandled runtime exception during scan execution. |

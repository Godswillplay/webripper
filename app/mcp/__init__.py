"""
Model Context Protocol (MCP) Server for WebRipper Recon 5.0.

Provides a native JSON-RPC 2.0 interface over stdio, allowing autonomous AI agents
(Claude Code, Antigravity, Cursor, Codex) to invoke WebRipper tools directly.
"""

from .server import run_mcp_server

__all__ = ["run_mcp_server"]

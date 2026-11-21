"""Entrypoint for py -m app.mcp"""
import sys
from .server import run_mcp_server

if __name__ == "__main__":
    sys.exit(run_mcp_server())

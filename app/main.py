"""
WebRipper Recon 5.0 — Headless Application Entrypoint.

Provides pure-CLI and interactive terminal wizard execution with zero Qt/GUI dependencies:
    Interactive Wizard: py -m app.main (no args) or py -m app.main --wizard
    Headless Agent/CLI: py -m app.main https://target.com [options]
"""

import os
import sys
from pathlib import Path

# Ensure the parent directory is on sys.path so absolute imports work
# both when running as `py -m app.main` and as a packaged binary.
_app_dir = Path(__file__).resolve().parent
_project_dir = _app_dir.parent
if str(_project_dir) not in sys.path:
    sys.path.insert(0, str(_project_dir))


def _install_excepthook():
    """Log any unhandled exception to a crash log file."""
    def excepthook(exc_type, exc_value, exc_traceback):
        import traceback
        log_path = os.path.join(os.getcwd(), "webripper_crash.log")
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"\n--- CRASH: {traceback.format_exc()} ---\n")
        except Exception:
            pass
        sys.__excepthook__(exc_type, exc_value, exc_traceback)

    sys.excepthook = excepthook


def main():
    """Application main entrypoint."""
    _install_excepthook()

    from app.cli import run_cli, run_wizard

    try:
        if len(sys.argv) == 1:
            # No arguments passed: launch the interactive terminal wizard
            if not sys.stdin.isatty():
                print("[!] Error: Interactive wizard requires an interactive TTY terminal.", file=sys.stderr)
                print("    For headless/CI usage, provide a target URL: py -m app.main <target_url> [options]", file=sys.stderr)
                sys.exit(1)
            sys.exit(run_wizard())

        first = sys.argv[1].lower()
        if first in ("--mcp", "-mcp"):
            from app.mcp.server import run_mcp_server
            sys.exit(run_mcp_server())

        if first in ("--wizard", "-w", "--interactive", "-i"):
            if not sys.stdin.isatty():
                print("[!] Error: Interactive wizard requires an interactive TTY terminal.", file=sys.stderr)
                sys.exit(1)
            sys.exit(run_wizard())

        # CLI flag or positional URL provided: execute headless CLI
        sys.exit(run_cli(sys.argv[1:]))

    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by operator.")
        sys.exit(130)


if __name__ == "__main__":
    main()

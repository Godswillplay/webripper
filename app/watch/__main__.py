"""CLI entrypoint for 'python -m app.watch'."""
import sys
from .engine import run_watch_cli

if __name__ == "__main__":
    sys.exit(run_watch_cli())

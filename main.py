"""
WebRipper Recon 5.0 — Root Entry Point.
Delegates to app.main.main().
"""

import sys
from pathlib import Path

# Ensure root directory is in sys.path
_root = Path(__file__).resolve().parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from app.main import main

if __name__ == "__main__":
    main()


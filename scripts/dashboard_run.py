#!/usr/bin/env python3
"""Run the Centralium dashboard: python scripts/dashboard_run.py [--db PATH] [--host H] [--port P]."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dashboard.backend.run import serve


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default=None)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--config", default=None)
    a = ap.parse_args()
    serve(a.db, a.host, a.port, a.config)


if __name__ == "__main__":
    main()

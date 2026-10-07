#!/usr/bin/env python
"""Wrapper: ``python scripts/ml_cli.py <command>`` == ``python -m ml.cli <command>``."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml.cli import app

if __name__ == "__main__":
    app()

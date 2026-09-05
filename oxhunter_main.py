#!/usr/bin/env python3
"""
oxhunter_main.py — Public re-export shim for 0xHunter.
"""

import sys
import os

pkg_dir = os.path.dirname(os.path.abspath(__file__))
if pkg_dir not in sys.path:
    sys.path.insert(0, pkg_dir)

from oxhunter_app import app, console

__all__ = ["app", "console"]


def main():
    app()


if __name__ == "__main__":
    main()

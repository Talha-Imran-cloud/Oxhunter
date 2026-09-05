"""0xhunter.py — thin shim; canonical code lives in oxhunter_app.py (BUG-006 FIX)"""
from oxhunter_app import app
if __name__ == "__main__":
    app()

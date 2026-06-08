#!/usr/bin/env python3
"""
Snypshark development entry point.
Prefer running from the project root: python main.py
"""
import sys
import os

# Allow running directly from this directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Delegate to root entry point
_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'main.py')
_root = os.path.normpath(_root)

if os.path.exists(_root):
    # Re-execute root main with the corrected path in sys.path
    import importlib.util
    spec = importlib.util.spec_from_file_location("__main__", _root)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
else:
    import logging
    logging.getLogger("snypshark").error("Root main.py not found at %s", _root)
    sys.exit(1)

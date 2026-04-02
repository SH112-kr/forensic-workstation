"""Core engine — sets up import paths for forensic-orchestra-mcp modules."""

import sys
import os

# Add core/ to path so internal imports like 'from connectors.base import ...' work
core_dir = os.path.dirname(os.path.abspath(__file__))
if core_dir not in sys.path:
    sys.path.insert(0, core_dir)

#!/usr/bin/env python3
"""
Direct runner for the security check tool.
Usage: python run.py [command] [arguments]
"""

import sys
import os

# Add the parent directory to Python path so we can import sec_ckeck
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from sec_ckeck.cli import main

if __name__ == "__main__":
    main()

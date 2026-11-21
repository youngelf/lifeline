# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.

"""Module entrypoint for `python3 -m lifeline` (dispatches to lifelinectl)."""

import sys

from lifeline.cli import main

if __name__ == "__main__":
    sys.exit(main())

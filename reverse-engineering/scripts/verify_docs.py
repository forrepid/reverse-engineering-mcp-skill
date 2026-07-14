#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from re_core.cli import build_parser


def main() -> int:
    parser = build_parser()
    subparsers = next(
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    commands = set(subparsers.choices)
    tick = chr(96)
    reference = Path(__file__).resolve().parents[1] / "references" / "command-reference.md"
    documented = {
        line[5:-1]
        for line in reference.read_text(encoding="utf-8").splitlines()
        if line.startswith("### " + tick) and line.endswith(tick)
    }
    result = {
        "status": "passed" if commands == documented else "failed",
        "command_count": len(commands),
        "documented_count": len(documented),
        "missing": sorted(commands - documented),
        "extra": sorted(documented - commands),
    }
    print(json.dumps(result, indent=2))
    return 0 if commands == documented else 2


if __name__ == "__main__":
    raise SystemExit(main())

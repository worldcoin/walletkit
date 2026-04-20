#!/usr/bin/env python3
"""Python harness for the host-mediated UniFFI composition experiment."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path


def add_generated_module_paths() -> None:
    """Adds the generated binding root to ``sys.path``."""
    generated_root = Path(__file__).resolve().parent / "generated"
    sys.path.insert(0, str(generated_root))


def alias_external_switchboard_modules() -> None:
    """Reuses one generated switchboard module for all external-type imports."""
    switchboard_module = importlib.import_module("switchboard.switchboard")
    sys.modules["shouty.switchboard"] = switchboard_module
    sys.modules["mirror.switchboard"] = switchboard_module


add_generated_module_paths()
alias_external_switchboard_modules()

from mirror import mirror  # noqa: E402  pylint: disable=wrong-import-position
from shouty import shouty  # noqa: E402  pylint: disable=wrong-import-position
from switchboard import switchboard  # noqa: E402  pylint: disable=wrong-import-position


def build_switchboard() -> switchboard.Switchboard:
    """Constructs the switchboard and registers both runtime-selectable processors."""
    board = switchboard.Switchboard()
    board.register_processor("shouty", shouty.ShoutyProcessor())
    board.register_processor("mirror", mirror.MirrorProcessor())
    return board


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the host-mediated UniFFI experiment with a runtime-selected processor.",
    )
    parser.add_argument("processor", help="The registered processor to invoke (shouty or mirror).")
    parser.add_argument("text", help="The text payload to transform.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    board = build_switchboard()
    processors = board.available_processors()

    if args.processor not in processors:
        print(
            f"Unknown processor '{args.processor}'. Available processors: {', '.join(processors)}",
            file=sys.stderr,
        )
        return 2

    request_json = json.dumps({"text": args.text})
    response_json = board.process_with(args.processor, request_json)
    print(response_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

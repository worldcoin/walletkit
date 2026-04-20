#!/usr/bin/env python3
"""Python harness — adapter approach with real async processor implementations."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path


def add_generated_module_paths() -> None:
    generated_root = Path(__file__).resolve().parent / "generated"
    sys.path.insert(0, str(generated_root))


add_generated_module_paths()

from mirror import mirror  # noqa: E402
from shouty import shouty  # noqa: E402
from switchboard import switchboard  # noqa: E402
from adapters import MirrorAdapter, ShoutyAdapter  # noqa: E402


async def build_switchboard(loop: asyncio.AbstractEventLoop) -> switchboard.Switchboard:
    board = switchboard.Switchboard()
    board.register_processor("shouty", ShoutyAdapter(shouty.ShoutyProcessor(), loop))
    board.register_processor("mirror", MirrorAdapter(mirror.MirrorProcessor(), loop))
    return board


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("processor")
    parser.add_argument("text")
    return parser.parse_args()


async def main() -> int:
    args = parse_args()
    loop = asyncio.get_running_loop()
    board = await build_switchboard(loop)
    processors = board.available_processors()
    if args.processor not in processors:
        print(f"Unknown processor '{args.processor}'. Available: {', '.join(processors)}", file=sys.stderr)
        return 2
    request_json = json.dumps({"text": args.text})
    response_json = await board.process_with(args.processor, request_json)
    print(response_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

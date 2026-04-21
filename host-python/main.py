#!/usr/bin/env python3
"""Python harness — Issuers SDK demo with OrbKit and NfcKit implementations."""
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

from nfc_kit import nfc_kit  # noqa: E402
from orb_kit import orb_kit  # noqa: E402
from issuer_host import issuer_host  # noqa: E402
from adapters import OrbKitAdapter, NfcKitAdapter  # noqa: E402


async def build_host(loop: asyncio.AbstractEventLoop) -> issuer_host.IssuerHost:
    host = issuer_host.IssuerHost()
    host.register_issuer("orb-kit", OrbKitAdapter(orb_kit.OrbIssuer(), loop))
    host.register_issuer("nfc-kit", NfcKitAdapter(nfc_kit.NfcIssuer(), loop))
    return host


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Issuers SDK demo")
    parser.add_argument(
        "issuer",
        help="Issuer to use (orb-kit or nfc-kit)",
    )
    parser.add_argument(
        "user_id",
        help="User identifier to include in the credential request",
    )
    return parser.parse_args()


async def main() -> int:
    args = parse_args()
    loop = asyncio.get_running_loop()
    host = await build_host(loop)

    issuers = host.available_issuers()
    if args.issuer not in issuers:
        print(
            f"Unknown issuer '{args.issuer}'. Available: {', '.join(issuers)}",
            file=sys.stderr,
        )
        return 2

    request_json = json.dumps({"user_id": args.user_id})
    credential_json = await host.fetch_credential_with(args.issuer, request_json)
    print(credential_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

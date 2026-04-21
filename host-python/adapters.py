"""Adapters: Python implements issuer_host.IssuerDriverCallback by bridging to async issuer methods."""

import asyncio

from nfc_kit import nfc_kit
from orb_kit import orb_kit
from issuer_host import issuer_host


class OrbKitAdapter(issuer_host.IssuerDriverCallback):
    """Adapts OrbIssuer's async fetch_credential_async into the synchronous IssuerDriverCallback."""

    def __init__(self, inner: orb_kit.OrbIssuer, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__()
        self._inner = inner
        self._loop = loop

    def fetch_credential(self, request_json: str) -> str:
        # Called on a tokio blocking thread; schedule the async work on the asyncio event loop.
        future = asyncio.run_coroutine_threadsafe(
            self._inner.fetch_credential_async(request_json),
            self._loop,
        )
        return future.result()


class NfcKitAdapter(issuer_host.IssuerDriverCallback):
    """Adapts NfcIssuer's async fetch_credential_async into the synchronous IssuerDriverCallback."""

    def __init__(self, inner: nfc_kit.NfcIssuer, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__()
        self._inner = inner
        self._loop = loop

    def fetch_credential(self, request_json: str) -> str:
        future = asyncio.run_coroutine_threadsafe(
            self._inner.fetch_credential_async(request_json),
            self._loop,
        )
        return future.result()

"""Adapters: Python implements issuer_sdk.IssuerDriver by bridging to async issuer methods.

`IssuerDriver` is now a proper first-class UniFFI callback interface exported
by `issuer_sdk` (the SDK cdylib), so adapters subclass it from the `issuer_sdk`
generated module rather than from a twin defined inside `issuer_host`.
"""

import asyncio

from nfc_kit import nfc_kit
from orb_kit import orb_kit
from issuer_sdk import issuer_sdk


class OrbKitAdapter(issuer_sdk.IssuerDriver):
    """Adapts OrbIssuer's async fetch_credential_async into the synchronous IssuerDriver."""

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


class NfcKitAdapter(issuer_sdk.IssuerDriver):
    """Adapts NfcIssuer's async fetch_credential_async into the synchronous IssuerDriver."""

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

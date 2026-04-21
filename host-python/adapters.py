"""Adapters: Python implements issuer_sdk.IssuerDriver by bridging to async issuer methods.

UniFFI generates `IssuerMsg` as a class with SCREAMING_SNAKE_CASE nested variant
classes (e.g. `IssuerMsg.FETCH_CREDENTIAL`), and `IssuerValue` similarly
(e.g. `IssuerValue.CREDENTIAL`).

The adapter's single `handle_message` method dispatches on the message variant
and returns the appropriate value variant, bridging synchronously into the
issuer's async `fetch_credential_async` method via asyncio.
"""

import asyncio

from issuer_sdk import issuer_sdk
from nfc_kit import nfc_kit
from orb_kit import orb_kit


class OrbKitAdapter(issuer_sdk.IssuerDriver):
    """Adapts OrbIssuer's async pathway into the synchronous IssuerDriver.

    Subclasses issuer_sdk.IssuerDriver — the proper first-class UniFFI
    callback interface owned by issuer-sdk.
    """

    def __init__(self, inner: orb_kit.OrbIssuer, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__()
        self._inner = inner
        self._loop = loop

    def handle_message(self, msg: issuer_sdk.IssuerMsg) -> issuer_sdk.IssuerValue:
        if isinstance(msg, issuer_sdk.IssuerMsg.FETCH_CREDENTIAL):
            future = asyncio.run_coroutine_threadsafe(
                self._inner.fetch_credential_async(msg.request_json),
                self._loop,
            )
            json = future.result()
            return issuer_sdk.IssuerValue.CREDENTIAL(json=json)
        err = issuer_sdk.SdkError.UnsupportedMessage()
        raise err


class NfcKitAdapter(issuer_sdk.IssuerDriver):
    """Adapts NfcIssuer's async pathway into the synchronous IssuerDriver.

    Subclasses issuer_sdk.IssuerDriver — the proper first-class UniFFI
    callback interface owned by issuer-sdk.
    """

    def __init__(self, inner: nfc_kit.NfcIssuer, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__()
        self._inner = inner
        self._loop = loop

    def handle_message(self, msg: issuer_sdk.IssuerMsg) -> issuer_sdk.IssuerValue:
        if isinstance(msg, issuer_sdk.IssuerMsg.FETCH_CREDENTIAL):
            future = asyncio.run_coroutine_threadsafe(
                self._inner.fetch_credential_async(msg.request_json),
                self._loop,
            )
            json = future.result()
            return issuer_sdk.IssuerValue.CREDENTIAL(json=json)
        err = issuer_sdk.SdkError.UnsupportedMessage()
        raise err

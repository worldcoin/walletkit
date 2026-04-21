"""Trivial async delegate adapters for the Issuers SDK Python host.

Because IssuerDriver.handle_message is now async, and OrbIssuer / NfcIssuer
export their own async handle_message (which delegates to the Rust blanket impl),
the Python adapter is a one-liner: just await the inner issuer's handle_message.

All routing (IssuerMsg::FetchCredential → fetch_credential) happens in Rust
inside the blanket impl<T: Issuer> IssuerDriver for T in issuer-sdk.
"""

from issuer_sdk import issuer_sdk
from nfc_kit import nfc_kit
from orb_kit import orb_kit


class OrbKitAdapter(issuer_sdk.IssuerDriver):
    def __init__(self, inner: orb_kit.OrbIssuer) -> None:
        super().__init__()
        self._inner = inner

    async def handle_message(self, msg: issuer_sdk.IssuerMsg) -> issuer_sdk.IssuerValue:
        return await self._inner.handle_message(msg)


class NfcKitAdapter(issuer_sdk.IssuerDriver):
    def __init__(self, inner: nfc_kit.NfcIssuer) -> None:
        super().__init__()
        self._inner = inner

    async def handle_message(self, msg: issuer_sdk.IssuerMsg) -> issuer_sdk.IssuerValue:
        return await self._inner.handle_message(msg)

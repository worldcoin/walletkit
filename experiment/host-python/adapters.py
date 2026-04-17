"""Host-language adapters that bridge switchboard foreign traits to concrete Rust processors."""

import mirror
import shouty
import switchboard


class ShoutyAdapter(switchboard.ProcessorDriver):
    """Adapts a concrete shouty processor to the switchboard foreign trait."""

    def __init__(self, inner: shouty.ShoutyProcessor) -> None:
        super().__init__()
        self._inner = inner

    def process(self, request_json: str) -> str:
        return self._inner.process(request_json)


class MirrorAdapter(switchboard.ProcessorDriver):
    """Adapts a concrete mirror processor to the switchboard foreign trait."""

    def __init__(self, inner: mirror.MirrorProcessor) -> None:
        super().__init__()
        self._inner = inner

    def process(self, request_json: str) -> str:
        return self._inner.process(request_json)

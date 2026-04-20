"""Adapters: Python implements switchboard.ProcessorDriver by bridging to async processor methods."""

import asyncio

from mirror import mirror
from shouty import shouty
from switchboard import switchboard


class ShoutyAdapter(switchboard.ProcessorDriver):
    def __init__(self, inner: shouty.ShoutyProcessor, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__()
        self._inner = inner
        self._loop = loop

    def process(self, request_json: str) -> str:
        # Called on a tokio blocking thread; schedule the async work on the asyncio event loop.
        future = asyncio.run_coroutine_threadsafe(
            self._inner.process_async(request_json),
            self._loop,
        )
        return future.result()


class MirrorAdapter(switchboard.ProcessorDriver):
    def __init__(self, inner: mirror.MirrorProcessor, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__()
        self._inner = inner
        self._loop = loop

    def process(self, request_json: str) -> str:
        future = asyncio.run_coroutine_threadsafe(
            self._inner.process_async(request_json),
            self._loop,
        )
        return future.result()

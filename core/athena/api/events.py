"""SSE relay.

Postgres LISTEN/NOTIFY feeds an in-process broker; clients receive identity only and
refetch through the normal API, so authorisation is re-checked on the read path.
"""

from __future__ import annotations

import asyncio
import contextlib
import json

import psycopg
import structlog

from athena.config import get_settings

log = structlog.get_logger(__name__)

CHANNEL = "athena_events"


class Broker:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[str]] = set()
        self._task: asyncio.Task | None = None

    def subscribe(self) -> asyncio.Queue[str]:
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=256)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[str]) -> None:
        self._subscribers.discard(q)

    def _fanout(self, message: str) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                # A slow client is dropped rather than allowed to stall the broker.
                # It reconnects with Last-Event-ID and catches up from the outbox.
                self._subscribers.discard(q)

    async def _listen(self) -> None:
        s = get_settings()
        dsn = (
            f"host={s.db_host} port={s.db_port} dbname={s.db_name} "
            f"user={s.db_user} password={s.db_password}"
        )
        while True:
            try:
                async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as conn:
                    await conn.execute(f"LISTEN {CHANNEL}")
                    log.info("events.listening", channel=CHANNEL)
                    async for notify in conn.notifies():
                        self._fanout(notify.payload)
            except Exception as exc:  # noqa: BLE001 - reconnect rather than die
                log.warning("events.listen_failed", error=str(exc))
                await asyncio.sleep(2)

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._listen())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None


broker = Broker()


async def event_stream(topics: set[str], queue: asyncio.Queue[str]):
    yield ": connected\n\n"
    while True:
        try:
            raw = await asyncio.wait_for(queue.get(), timeout=15.0)
        except TimeoutError:
            yield ": keepalive\n\n"   # keeps proxies from closing an idle stream
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if topics and event.get("topic") not in topics:
            continue
        yield f"id: {event.get('seq')}\nevent: {event.get('topic')}\ndata: {raw}\n\n"

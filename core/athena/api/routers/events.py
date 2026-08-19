from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from athena.api.deps import Principal, current_principal
from athena.api.events import broker, event_stream

router = APIRouter(tags=["events"])


@router.get("/events")
async def events(
    topics: str = Query(default="", description="Comma-separated topic filter"),
    _: Principal = Depends(current_principal),
) -> StreamingResponse:
    wanted = {t.strip() for t in topics.split(",") if t.strip()}
    queue = broker.subscribe()

    async def stream():
        try:
            async for chunk in event_stream(wanted, queue):
                yield chunk
        finally:
            broker.unsubscribe(queue)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

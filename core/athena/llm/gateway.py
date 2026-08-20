"""The only path to a model.

Every outbound call passes through here so that "what has left my network?" is
answerable exactly, from a table, rather than inferred from logs.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from athena.config import get_settings
from athena.llm.classify import classify, find_secrets, redact
from athena.llm.policy import DataClass, EgressBlocked, allowed_classes, is_local_endpoint

log = structlog.get_logger(__name__)


@dataclass
class Completion:
    text: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    duration_ms: int
    endpoint: str
    local: bool
    # True when the answer had to be recovered from the reasoning channel. Recorded
    # rather than hidden: it means the runtime is not labelling output as this code
    # expects, and a future model or runtime change could break it silently.
    from_reasoning: bool = False


class ModelUnavailable(RuntimeError):
    """The model could not be reached or did not answer.

    Deliberately distinct from a refusal: correlation continues and findings stay
    uninvestigated, rather than being presented as though they had been checked.
    """


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def complete(
    *,
    prompt: str,
    system: str | None = None,
    schema: dict[str, Any] | None = None,
    temperature: float = 0.0,
    max_tokens: int = 2048,
    purpose: str = "investigation",
) -> Completion:
    """Send one prompt, after the policy has cleared it.

    `schema` requests a JSON-shaped answer. Structured output is how the model's
    reply becomes data the system can act on rather than prose someone has to parse.
    """
    settings = get_settings()
    base_url = settings.llm_base_url
    payload_text = "\n".join(filter(None, [system, prompt]))

    # A secret in a prompt is blocked outright, not redacted and sent. If one reached
    # this point something upstream is wrong, and continuing would hide it.
    if secrets_found := find_secrets(payload_text):
        _record_egress(
            purpose=purpose, endpoint=base_url, model=settings.llm_model,
            classes={DataClass.SECRETS}, blocked=True,
            reason=f"payload contains {', '.join(secrets_found)}",
            payload_hash=_digest(payload_text), bytes_out=len(payload_text),
        )
        raise EgressBlocked(
            f"Refusing to send a payload containing {', '.join(secrets_found)}. "
            "This is an incident, not a policy tweak: find why a credential reached "
            "a prompt."
        )

    classes = classify(payload_text)
    permitted = allowed_classes(base_url=base_url, mode=settings.ai_mode)
    if disallowed := (classes - permitted):
        _record_egress(
            purpose=purpose, endpoint=base_url, model=settings.llm_model,
            classes=classes, blocked=True,
            reason=f"policy forbids {', '.join(sorted(disallowed))} to this endpoint",
            payload_hash=_digest(payload_text), bytes_out=len(payload_text),
        )
        raise EgressBlocked(
            f"Policy forbids sending {', '.join(sorted(disallowed))} to {base_url}"
        )

    body: dict[str, Any] = {
        "model": settings.llm_model,
        "messages": (
            ([{"role": "system", "content": system}] if system else [])
            + [{"role": "user", "content": prompt}]
        ),
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }
    if schema is not None:
        body["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": "athena_response", "strict": True, "schema": schema},
        }

    started = time.monotonic()
    try:
        with httpx.Client(timeout=httpx.Timeout(settings.llm_timeout, connect=10.0)) as client:
            response = client.post(f"{base_url.rstrip('/')}/v1/chat/completions", json=body)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPError as exc:
        _record_egress(
            purpose=purpose, endpoint=base_url, model=settings.llm_model,
            classes=classes, blocked=False, reason=f"transport error: {exc}",
            payload_hash=_digest(payload_text), bytes_out=len(payload_text),
        )
        raise ModelUnavailable(f"Model at {base_url} unreachable: {exc}") from exc

    duration_ms = int((time.monotonic() - started) * 1000)
    try:
        message = data["choices"][0]["message"]
    except (KeyError, IndexError) as exc:
        raise ModelUnavailable(f"Model returned an unexpected response shape: {exc}") from exc

    text, from_reasoning = _answer_of(message)
    if from_reasoning:
        log.info("llm.answer_from_reasoning", model=settings.llm_model)
    if not text.strip():
        raise ModelUnavailable(
            "Model returned no answer in either the content or reasoning channel"
        )

    usage = data.get("usage") or {}
    completion = Completion(
        text=text,
        model=data.get("model") or settings.llm_model,
        prompt_tokens=int(usage.get("prompt_tokens") or 0),
        completion_tokens=int(usage.get("completion_tokens") or 0),
        duration_ms=duration_ms,
        endpoint=base_url,
        local=is_local_endpoint(base_url),
        from_reasoning=from_reasoning,
    )

    _record_egress(
        purpose=purpose, endpoint=base_url, model=completion.model,
        classes=classes, blocked=False, reason=None,
        payload_hash=_digest(payload_text), bytes_out=len(payload_text),
        prompt_tokens=completion.prompt_tokens,
        completion_tokens=completion.completion_tokens,
        duration_ms=duration_ms,
    )
    return completion


def _answer_of(message: dict[str, Any]) -> tuple[str, bool]:
    """The model's answer, wherever the runtime put it.

    Reasoning models split their output, and some runtimes route everything to the
    reasoning channel and leave `content` empty — LM Studio does this with Qwen3,
    returning a complete schema-conforming answer under `reasoning_content` and
    nothing under `content`. Reading only `content` yields an empty answer that
    looks like the model failing.
    """
    content = (message.get("content") or "").strip()
    if content:
        return content, False
    return (message.get("reasoning_content") or "").strip(), True


def complete_json(
    *, schema: dict[str, Any], **kwargs: Any
) -> tuple[dict[str, Any], Completion]:
    """A completion parsed as JSON.

    Structured output is how a model's reply becomes something the system can act on
    rather than prose someone has to interpret. A reply that will not parse is a
    failure, not something to salvage with a regex over free text.
    """
    completion = complete(schema=schema, **kwargs)
    text = completion.text.strip()

    # Reasoning models often wrap the object in prose or a fenced block.
    if not text.startswith("{"):
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise ModelUnavailable(f"Model reply contained no JSON object: {text[:200]!r}")
        text = text[start : end + 1]

    try:
        return json.loads(text), completion
    except json.JSONDecodeError as exc:
        raise ModelUnavailable(f"Model reply was not valid JSON: {exc}") from exc


def _record_egress(
    *,
    purpose: str,
    endpoint: str,
    model: str,
    classes: set[DataClass],
    blocked: bool,
    reason: str | None,
    payload_hash: str,
    bytes_out: int,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    duration_ms: int = 0,
) -> None:
    """Record the attempt, whatever its outcome.

    Written in its own transaction: a blocked call raises, and the record of the
    block must survive that.
    """
    from athena.db.base import session_scope
    from athena.db.models import EgressLog

    try:
        with session_scope() as session:
            session.add(
                EgressLog(
                    purpose=purpose,
                    endpoint=endpoint,
                    model=model,
                    local=is_local_endpoint(endpoint),
                    data_classes=sorted(str(c) for c in classes),
                    blocked=blocked,
                    reason=redact(reason) if reason else None,
                    payload_hash=payload_hash,
                    bytes_out=bytes_out,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    duration_ms=duration_ms,
                )
            )
    except Exception as exc:  # noqa: BLE001 - never let auditing break the caller
        log.error("egress.audit_failed", error=str(exc), blocked=blocked)


def health() -> dict[str, Any]:
    """Whether the configured model is reachable, and which models it serves."""
    settings = get_settings()
    base_url = settings.llm_base_url
    try:
        with httpx.Client(timeout=httpx.Timeout(10.0, connect=5.0)) as client:
            response = client.get(f"{base_url.rstrip('/')}/v1/models")
            response.raise_for_status()
            models = [m.get("id") for m in (response.json().get("data") or [])]
    except httpx.HTTPError as exc:
        return {
            "reachable": False, "endpoint": base_url, "local": is_local_endpoint(base_url),
            "error": str(exc), "configured_model": settings.llm_model, "models": [],
        }
    return {
        "reachable": True,
        "endpoint": base_url,
        "local": is_local_endpoint(base_url),
        "configured_model": settings.llm_model,
        "model_available": settings.llm_model in models,
        "models": models,
        "mode": settings.ai_mode,
    }

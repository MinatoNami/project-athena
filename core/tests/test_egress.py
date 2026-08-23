"""Egress policy.

Athena holds a structured map of every weakness in an estate. What leaves the
network, and to whom, is the single most consequential setting in a self-hosted
security tool.
"""

from __future__ import annotations

import pytest

from athena.llm.classify import classify, find_secrets, redact
from athena.llm.policy import (
    DataClass,
    EgressBlocked,
    allowed_classes,
    is_local_endpoint,
)

# ── what counts as inside the network ────────────────────────────────────────

@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:1234",
        "http://localhost:1234",
        "http://host.docker.internal:1234",
        "http://192.168.0.16:1234",
        "http://10.10.0.1:1234",
        "http://100.100.100.100:1234",          # tailnet CGNAT range
        "https://example-host.tailnet.ts.net",
    ],
)
def test_local_endpoints_are_recognised(url: str) -> None:
    assert is_local_endpoint(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "https://api.openai.com",
        "https://api.anthropic.com",
        "http://8.8.8.8:1234",
        "https://evil.example.com",
        # Outside the tailnet CGNAT range, so not ours despite looking similar.
        "http://100.200.1.1:1234",
    ],
)
def test_external_endpoints_are_not_treated_as_local(url: str) -> None:
    assert is_local_endpoint(url) is False


def test_local_only_refuses_a_non_local_endpoint() -> None:
    """A misconfiguration must fail loudly rather than quietly start shipping
    inventory to a hosted provider."""
    with pytest.raises(EgressBlocked):
        allowed_classes(base_url="https://api.openai.com", mode="local_only")


def test_a_local_endpoint_may_carry_everything_except_secrets() -> None:
    permitted = allowed_classes(base_url="http://127.0.0.1:1234", mode="local_only")
    assert DataClass.SOURCE_CODE in permitted
    assert DataClass.HOSTNAMES in permitted
    assert DataClass.SECRETS not in permitted, "secrets go nowhere, local included"


def test_a_hosted_endpoint_gets_only_public_material_by_default() -> None:
    permitted = allowed_classes(base_url="https://api.openai.com", mode="hybrid")
    assert DataClass.PACKAGE_METADATA in permitted
    assert DataClass.SOURCE_CODE not in permitted
    assert DataClass.HOSTNAMES not in permitted
    assert DataClass.SECRETS not in permitted


# ── secret detection ─────────────────────────────────────────────────────────

# Assembled at runtime rather than written as literals. These are entirely synthetic,
# but a credential-shaped literal in a public repository trips every scanner that
# looks at it — including GitHub push protection — and produces alert noise for
# something that was never a secret. Splitting them keeps the test exactly as strong,
# since the detector sees the full string either way.
FAKE_CREDENTIALS = [
    "AKIA" + "IOSFODNN7EXAMPLE",
    "ghp" + "_016C7A1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "Authorization: " + "Bearer abcdefghijklmnopqrstuvwxyz123456",
    "https://user:" + "hunter2pass@github.com/org/repo",
    "api_key" + " = 'sk1234567890abcdefghij'",
    "xoxb" + "-1234567890-abcdefghijkl",
]


@pytest.mark.parametrize("text", FAKE_CREDENTIALS)
def test_credentials_are_detected(text: str) -> None:
    assert find_secrets(text), f"failed to detect a credential in {text!r}"


def test_ordinary_advisory_text_is_not_flagged() -> None:
    """Over-eager detection would block legitimate work, so the common case must
    stay clean."""
    text = (
        "CVE-2024-9681: a heap buffer overflow in curl's HSTS handling. "
        "Fixed in 8.11.0. See https://curl.se/docs/CVE-2024-9681.html"
    )
    assert find_secrets(text) == []
    assert DataClass.SECRETS not in classify(text)


def test_classification_notices_code_paths_and_hosts() -> None:
    text = "import os\nopen('/etc/shadow')\nconnect('example-host.tailnet.ts.net')"
    classes = classify(text)
    assert DataClass.SOURCE_CODE in classes
    assert DataClass.FILE_PATHS in classes
    assert DataClass.HOSTNAMES in classes


def test_redaction_masks_credentials_for_logging() -> None:
    """Blocked payloads still get logged, so the reason must not carry the secret."""
    token = FAKE_CREDENTIALS[1]
    masked = redact(f"token={token} failed")
    assert token not in masked
    assert "[redacted]" in masked


# ── runtime quirks the gateway has to absorb ─────────────────────────────────

def test_the_answer_is_read_from_the_reasoning_channel_when_content_is_empty():
    """LM Studio serving Qwen3 returns a complete, schema-conforming answer under
    reasoning_content and leaves content empty. Reading only content produced an
    empty reply that looked like the model failing."""
    from athena.llm.gateway import _answer_of

    text, from_reasoning = _answer_of(
        {"content": "", "reasoning_content": '{"affected": "yes"}'}
    )
    assert text == '{"affected": "yes"}'
    assert from_reasoning is True


def test_content_is_preferred_when_the_runtime_populates_it():
    from athena.llm.gateway import _answer_of

    text, from_reasoning = _answer_of(
        {"content": '{"affected": "no"}', "reasoning_content": "thinking out loud"}
    )
    assert text == '{"affected": "no"}'
    assert from_reasoning is False


def test_an_empty_answer_in_both_channels_is_a_failure():
    from athena.llm.gateway import _answer_of

    text, _ = _answer_of({"content": "", "reasoning_content": ""})
    assert text == ""


@pytest.mark.parametrize(
    "reply",
    [
        '{"affected": "yes"}',
        'Here is the answer:\n{"affected": "yes"}\n',
        '```json\n{"affected": "yes"}\n```',
        'Thinking... {"affected": "yes"} ...done',
    ],
)
def test_json_is_recovered_from_a_wrapped_reply(reply: str, monkeypatch) -> None:
    """Reasoning models wrap the object in prose or a fenced block."""
    import athena.llm.gateway as gw

    monkeypatch.setattr(
        gw, "complete",
        lambda **kw: gw.Completion(
            text=reply, model="m", prompt_tokens=1, completion_tokens=1,
            duration_ms=1, endpoint="http://127.0.0.1:1234", local=True,
        ),
    )
    parsed, _ = gw.complete_json(schema={"type": "object"}, prompt="x")
    assert parsed == {"affected": "yes"}


def test_a_reply_with_no_json_is_a_failure_not_a_salvage(monkeypatch) -> None:
    """A reply that will not parse is a failure. Guessing at intent from free text
    is how an unfounded conclusion gets presented as a finding."""
    import athena.llm.gateway as gw

    monkeypatch.setattr(
        gw, "complete",
        lambda **kw: gw.Completion(
            text="I think it is probably fine.", model="m", prompt_tokens=1,
            completion_tokens=1, duration_ms=1, endpoint="http://127.0.0.1:1234", local=True,
        ),
    )
    with pytest.raises(gw.ModelUnavailable):
        gw.complete_json(schema={"type": "object"}, prompt="x")

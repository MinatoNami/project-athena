from __future__ import annotations

import pytest

from athena.llm.classify import classify, find_secrets, redact
from athena.llm.policy import (
    DataClass,
    EgressBlocked,
    allowed_classes,
    is_local_endpoint,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:1234",
        "http://localhost:1234",
        "http://host.docker.internal:1234",
        "http://192.168.1.10:1234",
        "http://10.10.0.1:1234",
        "http://100.100.100.100:1234",
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
        "http://100.200.1.1:1234",
    ],
)
def test_external_endpoints_are_not_treated_as_local(url: str) -> None:
    assert is_local_endpoint(url) is False


def test_local_only_refuses_a_non_local_endpoint() -> None:
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
    token = FAKE_CREDENTIALS[1]
    masked = redact(f"token={token} failed")
    assert token not in masked
    assert "[redacted]" in masked


def test_the_answer_is_read_from_the_reasoning_channel_when_content_is_empty():
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

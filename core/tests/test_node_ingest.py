"""Host observation ingestion."""

from __future__ import annotations

import pytest

from athena.workers.node_ingest import _distro_release, _process_name


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ({"os_id": "ubuntu", "os_version_id": "24.04"}, ("ubuntu", "24.04")),
        # An agent predating os_id/os_version_id reports only the pretty name.
        # Deriving both keeps it correlatable rather than leaving the distribution
        # unknown, which silently disables distro-specific matching.
        ({"os_version": "Ubuntu 24.04.4 LTS"}, ("ubuntu", "24.04")),
        ({"os_version": "Debian GNU/Linux 12 (bookworm)"}, ("debian", None)),
        ({}, (None, None)),
    ],
)
def test_distro_and_release_are_derived(data: dict, expected: tuple):
    assert _distro_release(data) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('users:(("sshd",pid=123,fd=3))', "sshd"),
        ('users:(("navgraph_visual",pid=78092,fd=44))', "navgraph_visual"),
        # An unprivileged agent cannot see other users' socket owners. Unknown is
        # recorded rather than guessed at.
        (None, None),
        ("", None),
        ("users:(())", None),
    ],
)
def test_process_names_are_extracted_from_ss_output(raw, expected):
    assert _process_name(raw) == expected

from __future__ import annotations

import re
from dataclasses import dataclass

INITIAL_DIGIT, DIGIT, LETTER, SUFFIX, SUFFIX_NO, COMMIT_HASH, REVISION_NO, END, INVALID = range(9)

NO_SUFFIX = 5
SUFFIX_RANK = {
    "alpha": 1,
    "beta": 2,
    "pre": 3,
    "rc": 4,
    "cvs": 6,
    "svn": 7,
    "git": 8,
    "hg": 9,
    "p": 10,
}
NUMERIC_KINDS = {INITIAL_DIGIT, DIGIT, SUFFIX_NO, REVISION_NO}

_DIGITS = re.compile(r"[0-9]+")
_SUFFIX_NAME = re.compile(r"[a-z]*")
_HEX_DIGITS = re.compile(r"[0-9a-f]*")


class InvalidVersion(ValueError):
    pass


@dataclass(frozen=True)
class _Token:
    kind: int
    value: str = ""
    suffix: int = 0


_INVALID = _Token(INVALID)
_END = _Token(END)


def _digits(kind: int, text: str, pos: int) -> tuple[_Token, int]:
    match = _DIGITS.match(text, pos)
    if match is None:
        return _INVALID, pos
    return _Token(kind, match.group()), match.end()


def _next_token(previous: int, text: str, pos: int) -> tuple[_Token, int]:
    if pos == len(text):
        return _END, pos
    char = text[pos]
    if "a" <= char <= "z":
        if previous > DIGIT:
            return _INVALID, pos
        return _Token(LETTER, char), pos + 1
    if char == "." or "0" <= char <= "9":
        if char == ".":
            if previous > DIGIT:
                return _INVALID, pos
            pos += 1
        if previous in (INITIAL_DIGIT, DIGIT):
            return _digits(DIGIT, text, pos)
        if previous == SUFFIX:
            return _digits(SUFFIX_NO, text, pos)
        return _INVALID, pos
    if char == "_":
        if previous > SUFFIX_NO:
            return _INVALID, pos
        name = _SUFFIX_NAME.match(text, pos + 1).group()
        rank = SUFFIX_RANK.get(name)
        if rank is None:
            return _INVALID, pos
        return _Token(SUFFIX, name, rank), pos + 1 + len(name)
    if char == "~":
        if previous >= COMMIT_HASH:
            return _INVALID, pos
        commit = _HEX_DIGITS.match(text, pos + 1).group()
        if not commit:
            return _INVALID, pos
        return _Token(COMMIT_HASH, commit), pos + 1 + len(commit)
    if char == "-":
        if previous >= REVISION_NO or not text.startswith("-r", pos):
            return _INVALID, pos
        return _digits(REVISION_NO, text, pos + 2)
    return _INVALID, pos


def _tokens(version: str) -> list[_Token]:
    text = version.strip()
    token, pos = _digits(INITIAL_DIGIT, text, 0)
    tokens = [token]
    while token.kind < END:
        token, pos = _next_token(token.kind, text, pos)
        tokens.append(token)
    if token.kind == INVALID:
        raise InvalidVersion(f"Not an Alpine package version: {version!r}")
    return tokens


def _sign(a: object, b: object) -> int:
    return (a > b) - (a < b)


def _compare_tokens(a: _Token, b: _Token) -> int:
    if a.kind == DIGIT and (a.value.startswith("0") or b.value.startswith("0")):
        return _sign(a.value, b.value)
    if a.kind in NUMERIC_KINDS:
        return _sign(int(a.value), int(b.value))
    if a.kind == SUFFIX:
        return _sign(a.suffix, b.suffix)
    return _sign(a.value, b.value)


def compare(a: str, b: str) -> int:
    left, right = _tokens(a), _tokens(b)
    index = 0
    while left[index].kind == right[index].kind and left[index].kind < END:
        result = _compare_tokens(left[index], right[index])
        if result:
            return result
        index += 1
    x, y = left[index], right[index]
    if x.kind == y.kind:
        return 0
    if x.kind == SUFFIX and x.suffix < NO_SUFFIX:
        return -1
    if y.kind == SUFFIX and y.suffix < NO_SUFFIX:
        return 1
    return -1 if x.kind > y.kind else 1

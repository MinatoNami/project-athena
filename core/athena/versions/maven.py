from __future__ import annotations

from dataclasses import dataclass

DOT = "."
HYPHEN = "-"

KNOWN_QUALIFIERS = ("alpha", "beta", "milestone", "rc", "snapshot", "", "sp")
QUALIFIER_ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}
SHORT_QUALIFIERS = {"a": "alpha", "b": "beta", "m": "milestone"}
SEPARATORS = {".": DOT, "-": HYPHEN, "_": HYPHEN}


class InvalidVersion(ValueError):
    pass


@dataclass(frozen=True)
class _Token:
    separator: str
    value: int | str

    @property
    def numeric(self) -> bool:
        return isinstance(self.value, int)

    @property
    def null(self) -> bool:
        return self.value == 0 or self.value == ""


def _is_ascii_digit(char: str) -> bool:
    return "0" <= char <= "9"


def _token(separator: str, text: str, followed_by_digit: bool) -> _Token:
    if not text:
        return _Token(separator, 0)
    if _is_ascii_digit(text[0]):
        return _Token(separator, int(text))
    if followed_by_digit and text in SHORT_QUALIFIERS:
        return _Token(separator, SHORT_QUALIFIERS[text])
    return _Token(separator, QUALIFIER_ALIASES.get(text, text))


def _split(version: str) -> list[_Token]:
    text = version.strip().lower()
    if not text:
        raise InvalidVersion("An empty string is not a Maven version")
    tokens: list[_Token] = []
    separator = DOT
    start = 0
    for index, char in enumerate(text):
        if char in SEPARATORS:
            tokens.append(_token(separator, text[start:index], False))
            separator = SEPARATORS[char]
            start = index + 1
        elif index > start and _is_ascii_digit(char) != _is_ascii_digit(text[index - 1]):
            tokens.append(_token(separator, text[start:index], _is_ascii_digit(char)))
            separator = HYPHEN
            start = index
    tokens.append(_token(separator, text[start:], False))
    return tokens


def _trim(tokens: list[_Token]) -> list[_Token]:
    groups: list[list[_Token]] = []
    for token in tokens:
        if token.separator == HYPHEN or not groups:
            groups.append([])
        groups[-1].append(token)
    trimmed: list[_Token] = []
    for group in groups:
        while group and group[-1].null:
            group.pop()
        trimmed.extend(group)
    return trimmed


def _qualifier_rank(value: str) -> tuple[int, str]:
    if value in KNOWN_QUALIFIERS:
        return KNOWN_QUALIFIERS.index(value), ""
    return len(KNOWN_QUALIFIERS), value


def _kind_rank(token: _Token) -> int:
    if not token.numeric:
        return 0
    return 2 if token.separator == DOT else 1


def _sign(a: object, b: object) -> int:
    return (a > b) - (a < b)


def _compare_tokens(a: _Token, b: _Token) -> int:
    if not a.numeric and not b.numeric:
        return _sign(_qualifier_rank(a.value), _qualifier_rank(b.value))
    if a.separator == b.separator and a.numeric and b.numeric:
        return _sign(a.value, b.value)
    return _sign(_kind_rank(a), _kind_rank(b))


def _padding_for(token: _Token) -> _Token:
    return _Token(token.separator, 0 if token.numeric else "")


def canonical_tokens(version: str) -> list[_Token]:
    return _trim(_split(version))


def compare(a: str, b: str) -> int:
    left, right = canonical_tokens(a), canonical_tokens(b)
    for index in range(max(len(left), len(right))):
        x = left[index] if index < len(left) else _padding_for(right[index])
        y = right[index] if index < len(right) else _padding_for(left[index])
        result = _compare_tokens(x, y)
        if result:
            return result
    return 0

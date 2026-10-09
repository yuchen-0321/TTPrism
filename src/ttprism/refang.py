"""Undo and apply IOC "defanging".

Threat reports neutralise IOCs so they cannot be clicked: ``evil[.]com``,
``hxxps://``. Chinese and other East Asian reports also use full-width forms
such as ``evil【.】com``, ``evil．com`` or ``attacker［＠］mail．com``, which
English-oriented extractors miss. :func:`refang` normalises all of these.

Every pattern here is linear: bracketed markers are fixed-width, with at most
one optional space on each side.
"""

from __future__ import annotations

import functools
import re
import unicodedata

from ttprism.models import IOCType

# Compatibility folding is selective: full NFKC would also turn footnote
# superscripts and circled list numbers into digits glued to the IOC ("1.2.3.4²"
# -> "1.2.3.42") and expands some characters up to 18-fold.
_FOLD_TAGS = ("<wide>", "<narrow>", "<small>")
_EXTRA_FOLDS = {
    0x2010: "-",  # hyphen
    0x2011: "-",  # non-breaking hyphen (inserted by word processors)
    0x2212: "-",  # minus sign
    0x2024: ".",  # one dot leader
    **{code: unicodedata.normalize("NFKC", chr(code)) for code in range(0xFB00, 0xFB07)},  # ligatures
}
# Full-width punctuation that can never be part of a URL, kept unfolded so that a URL right before
# it ends there: "hxxp://evil[.]com/a（C2）" or "...x.exe，MD5：..." in Chinese text.
_KEEP_WIDE = (0xFF01, 0xFF08, 0xFF09, 0xFF0C, 0xFF1B)  # ！（），；
# Astral format (Cf) characters, listed so the result does not depend on the
# Unicode version of the running interpreter.
_ASTRAL_FORMAT_RANGES = (
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
)


@functools.cache
def _fold_table() -> dict[int, str | None]:
    """Translation table: drop format characters, fold width variants to ASCII."""
    table: dict[int, str | None] = {}
    for code in range(0x80, 0x10000):
        char = chr(code)
        category = unicodedata.category(char)
        if category == "Cf":
            # Soft hyphen, zero-width and bidi marks inserted inside IOCs.
            table[code] = None
        elif category == "Zs":
            # No-break, thin and other spaces: "evil[\u00a0.\u00a0]com" copied from HTML.
            table[code] = " "
        elif unicodedata.decomposition(char).startswith(_FOLD_TAGS):
            table[code] = unicodedata.normalize("NFKC", char)
    for first, last in _ASTRAL_FORMAT_RANGES:
        table.update(dict.fromkeys(range(first, last + 1)))
    table.update(_EXTRA_FOLDS)
    for code in _KEEP_WIDE:
        del table[code]
    return table


# Bidi controls are deleted inside an IOC ("ev\u200eil.com", "ops@\u200eexample.org"), but next to
# whitespace, the start or end of the text, or a non-ASCII letter (Hebrew text around a name) they
# separate, like a space; so do an isolate or embedding that ends and the next that begins
# ("\u2066evil.com\u2069\u2066example.net\u2069"), and U+2063 INVISIBLE SEPARATOR. Other format
# characters are deleted first, so that "ev\u00ad\u200eil.com" stays one name.
_BIDI_CODES = (0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A))
_BIDI = "\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069"
_INSIDE = "\x21-\x7e\uff01-\uff5e\u3001\u3002\u3008-\u3011\u3014-\u301b" + _BIDI
_BIDI_BREAK_RE = re.compile(
    f"[\u202c\u2069][\u202a-\u202e\u2066-\u2068]|\u2063|(?<![{_INSIDE}])[{_BIDI}]|[{_BIDI}](?![{_INSIDE}])"
)


# Some PDF converters write every hyphen as a soft hyphen. In a GUID, deleting them would leave
# 32 hex digits that read as an MD5: "{92BA1818\u00ad0119\u00ad4F79\u00ad874E\u00adE3BF79C355B8}".
_SOFT_HYPHEN_GUID_RE = re.compile(
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}(?:\u00ad[0-9A-Fa-f]{4}){3}\u00ad[0-9A-Fa-f]{12}(?![0-9A-Fa-f])"
)


def _guid_hyphens(match: re.Match[str]) -> str:
    return match.group(0).replace("\u00ad", "-")


# A soft hyphen at the end of a line is where a word was broken, as a hyphen there is, so it is
# read as one and the line-break rules of the extractor decide what it joins. Between it and the
# line break there may be anything that refang turns into a space or deletes (spaces, zero-width and
# bidi marks), so that the result is the same as for "-". _soft_hyphen_break_re builds the pattern.
_MAX_BREAK_GAP = 1024


def _char_class(codes: set[int]) -> str:
    """The inside of a regex character class that matches exactly ``codes``."""
    parts = []
    ordered = sorted(codes)
    first = previous = ordered[0]
    for code in [*ordered[1:], -1]:
        if code != previous + 1:
            parts.append(f"\\U{first:08x}" if first == previous else f"\\U{first:08x}-\\U{previous:08x}")
            first = code
        previous = code
    return "".join(parts)


@functools.cache
def _soft_hyphen_break_re() -> re.Pattern[str]:
    gap = {0x09, 0x20} | {code for code, value in _fold_table().items() if value in (None, " ")} - {0xAD}
    # Between "\r" and "\n" only characters that are deleted outright, not turned into a space.
    deleted = set(_format_table()) - {0xAD}
    return re.compile(
        f"\\u00ad(?=[{_char_class(gap)}]{{0,{_MAX_BREAK_GAP}}}"
        f"(?:\\r[{_char_class(deleted)}]{{0,{_MAX_BREAK_GAP}}})?\\n)"
    )


def _soft_hyphens_as_hyphens(text: str) -> str:
    """Soft hyphens between the groups of a GUID and at the end of a line become hyphens."""
    text = _SOFT_HYPHEN_GUID_RE.sub(_guid_hyphens, text)
    return _soft_hyphen_break_re().sub("-", text)


# Other soft hyphens are deleted, as break hints. That is wrong when a converter wrote every hyphen
# as one ("KB\u00adAuto" becomes "KBAuto"); show_inner_soft_hyphens gives the reading in which they
# are hyphens, so that the caller can see which extracted values depend on it.
_ASCII_ALNUM = frozenset("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


@functools.cache
def _deleted_run_re() -> re.Pattern[str]:
    deleted = {code for code, value in _fold_table().items() if value is None}
    return re.compile(f"[{_char_class(deleted)}]{{1,64}}")


def _folds_to_alnum(char: str, last: bool) -> bool:
    """True if ``char`` is, or refang folds it to, an ASCII letter or digit (the last one of a
    folded sequence such as the "fi" ligature when ``last``, else the first)."""
    if char in _ASCII_ALNUM:
        return True
    folded = _fold_table().get(ord(char)) if char else None
    return bool(folded) and folded is not None and (folded[-1] if last else folded[0]) in _ASCII_ALNUM


# Characters that refang reads as a space between two names, not as part of one.
_SEPARATING = frozenset(chr(code) for code in (*_BIDI_CODES, 0x2063))


def _inner_run_as_hyphen(match: re.Match[str]) -> str:
    run, text = match.group(0), match.string
    start, end = match.span()
    if (
        "\u00ad" in run
        and _SEPARATING.isdisjoint(run)
        and _folds_to_alnum(text[start - 1 : start], last=True)
        and _folds_to_alnum(text[end : end + 1], last=False)
    ):
        return "-"
    return run


def show_inner_soft_hyphens(text: str) -> str | None:
    """``text`` with each run of deleted characters that holds a soft hyphen and stands between two
    letters or digits written as "-" ("KB\u00adAuto" as "KB-Auto"), or None if there is none. Runs
    with a character that separates two names (U+2063, bidi controls) are left alone."""
    if "\u00ad" not in text:
        return None
    shown = _deleted_run_re().sub(_inner_run_as_hyphen, text)
    return None if shown == text else shown


@functools.cache
def _format_table() -> dict[int, str | None]:
    """Translation table that deletes the format characters other than bidi controls and U+2063."""
    keep = {*_BIDI_CODES, 0x2063}
    return {code: None for code, value in _fold_table().items() if value is None and code not in keep}


# Full-width brackets are folded to ASCII first, so only CJK brackets without an
# ASCII equivalent (and the unfolded full-width parentheses) are listed explicitly.
_OPEN = r"[\[({<【〔〖「『（]"
_CLOSE = r"[\])}>】〕〗」』）]"
_DOT_MARK = r" ?(?:\.|。|dot|點|点) ?"
_AT_MARK = r" ?(?:@|at) ?"

# "evil [.] com", "john (at) evil {dot} com": a marker with one space on each side, only between
# label characters.
_SPACED_DOT_RE = re.compile(rf"(?<=[A-Za-z0-9]) {_OPEN}{_DOT_MARK}{_CLOSE} (?=[A-Za-z0-9])", re.IGNORECASE)
_SPACED_AT_RE = re.compile(rf"(?<=[A-Za-z0-9]) {_OPEN}{_AT_MARK}{_CLOSE} (?=[A-Za-z0-9])", re.IGNORECASE)
_DOT_RE = re.compile(_OPEN + _DOT_MARK + _CLOSE, re.IGNORECASE)
_COLON_RE = re.compile(_OPEN + r" ?(://|:) ?" + _CLOSE)
_SLASH_RE = re.compile(r"\[(//?)\]")
_AT_RE = re.compile(_OPEN + _AT_MARK + _CLOSE, re.IGNORECASE)
_BACKSLASH_DOT_RE = re.compile(r"(?<=[A-Za-z0-9])\\\.(?=[A-Za-z0-9])")
# "hxxp[s]://" and "http(s)://" mean "http or https"; they are read as https.
_HTTP_RE = re.compile(
    r"(?<![A-Za-z])h(?:(?:xx|\*\*|\[xx\]|\[tt\])p(s|\[s\]|[(（]s[)）])?|ttp(\[s\]|[(（]s[)）]))://",
    re.IGNORECASE,
)
_FTP_RE = re.compile(r"(?<![A-Za-z])fxp(s?)://", re.IGNORECASE)
# Word and Markdown typographers turn the "--" of a punycode name into a dash: "xn–80ak6aa92e.com".
_PUNYCODE_DASH_RE = re.compile(r"(?<![A-Za-z0-9-])(xn)[\u2012-\u2015](?=[A-Za-z0-9])", re.IGNORECASE)


def _http_scheme(match: re.Match[str]) -> str:
    return "https://" if match.group(1) or match.group(2) else "http://"


def refang(text: str) -> str:
    """Return ``text`` with common and CJK defanging conventions reversed.

    Format characters (zero-width, soft hyphen, bidi marks) are removed, or
    read as a space between two names; full-width, half-width and small forms
    are folded to their plain equivalents, except full-width punctuation that
    cannot be part of a URL; Unicode spaces become plain spaces. Other
    compatibility characters (superscripts, circled numbers) are kept, so they
    never merge into an adjacent IOC. Soft hyphens between the groups of a GUID
    and at the end of a line become hyphens.
    """
    if "\u00ad" in text:
        text = _soft_hyphens_as_hyphens(text)
    return _refang_rest(text)


def _refang_rest(text: str) -> str:
    """:func:`refang` after the soft hyphens that become hyphens."""
    text = _BIDI_BREAK_RE.sub(" ", text.translate(_format_table())).translate(_fold_table())
    text = _PUNYCODE_DASH_RE.sub(r"\1--", text)
    text = _SPACED_DOT_RE.sub(".", text)
    text = _SPACED_AT_RE.sub("@", text)
    text = _DOT_RE.sub(".", text)
    text = _COLON_RE.sub(r"\1", text)
    text = _SLASH_RE.sub(r"\1", text)
    text = _AT_RE.sub("@", text)
    text = _BACKSLASH_DOT_RE.sub(".", text)
    text = _HTTP_RE.sub(_http_scheme, text)
    return _FTP_RE.sub(r"ftp\1://", text)


_URL_PARTS_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(.*)", re.DOTALL)
_SCHEME_DEFANG = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "ftps": "fxps"}


def defang(value: str, ioc_type: IOCType) -> str:
    """Return a non-clickable form of ``value``.

    Only the URL scheme and ``://``, the dots of hosts and IPv4 addresses, the
    colons of IPv6 addresses and the ``@`` of e-mail addresses are defanged. A
    URL's path and query are left as they are, so :func:`refang` is guaranteed
    to restore the scheme and host only: a path that itself contains defang
    markers such as ``[.]`` or ``(at)`` may not round-trip.
    """
    if ioc_type in (IOCType.DOMAIN, IOCType.IPV4):
        return value.replace(".", "[.]")
    if ioc_type == IOCType.IPV6:
        return value.replace(":", "[:]")
    if ioc_type == IOCType.EMAIL:
        local, _, domain = value.rpartition("@")
        return f"{local}[@]{domain.replace('.', '[.]')}"
    if ioc_type == IOCType.URL:
        match = _URL_PARTS_RE.fullmatch(value)
        if match is None:
            return value.replace(".", "[.]")
        scheme, authority, rest = match.groups()
        scheme = _SCHEME_DEFANG.get(scheme.lower(), scheme)
        if not authority.startswith("["):
            authority = authority.replace(".", "[.]")
        return f"{scheme}[://]{authority}{rest}"
    return value

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
        if unicodedata.category(char) == "Cf":
            # Soft hyphen, zero-width and bidi marks inserted inside IOCs.
            table[code] = None
        elif unicodedata.decomposition(char).startswith(_FOLD_TAGS):
            table[code] = unicodedata.normalize("NFKC", char)
    for first, last in _ASTRAL_FORMAT_RANGES:
        table.update(dict.fromkeys(range(first, last + 1)))
    table.update(_EXTRA_FOLDS)
    return table


# Full-width brackets are folded to ASCII first, so only CJK brackets without an
# ASCII equivalent are listed explicitly.
_OPEN = r"[\[({<【〔〖「『]"
_CLOSE = r"[\])}>】〕〗」』]"

# "evil [.] com", "john [at] evil [dot] com": only between label characters.
_SPACED_DOT_RE = re.compile(r"(?<=[A-Za-z0-9]) (?:\[(?:\.|dot)\]|\(\.\)) (?=[A-Za-z0-9])", re.IGNORECASE)
_SPACED_AT_RE = re.compile(r"(?<=[A-Za-z0-9]) \[at\] (?=[A-Za-z0-9])", re.IGNORECASE)
_DOT_RE = re.compile(_OPEN + r" ?(?:\.|。|dot|點|点) ?" + _CLOSE, re.IGNORECASE)
_COLON_RE = re.compile(_OPEN + r" ?(://|:) ?" + _CLOSE)
_SLASH_RE = re.compile(r"\[(//?)\]")
_AT_RE = re.compile(_OPEN + r" ?(?:@|at) ?" + _CLOSE, re.IGNORECASE)
_BACKSLASH_DOT_RE = re.compile(r"(?<=[A-Za-z0-9])\\\.(?=[A-Za-z0-9])")
# "hxxp[s]://" and "http[s]://" mean "http or https"; they are read as https.
_HTTP_RE = re.compile(r"(?<![A-Za-z])h(?:(?:xx|\*\*|\[xx\]|\[tt\])p(s|\[s\])?|ttp(\[s\]))://", re.IGNORECASE)
_FTP_RE = re.compile(r"(?<![A-Za-z])fxp(s?)://", re.IGNORECASE)


def _http_scheme(match: re.Match[str]) -> str:
    return "https://" if match.group(1) or match.group(2) else "http://"


def refang(text: str) -> str:
    """Return ``text`` with common and CJK defanging conventions reversed.

    Format characters (zero-width, soft hyphen, bidi marks) are removed, and
    full-width, half-width and small forms are folded to their plain
    equivalents. Other compatibility characters (superscripts, circled
    numbers) are kept, so they never merge into an adjacent IOC.
    """
    text = text.translate(_fold_table())
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

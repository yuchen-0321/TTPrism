"""Undo and apply IOC "defanging".

Threat reports neutralise IOCs so they cannot be clicked: ``evil[.]com``,
``hxxps://``. Chinese and other East Asian reports also use full-width forms
such as ``evil【.】com``, ``evil．com`` or ``attacker［＠］mail．com``, which
English-oriented extractors miss. :func:`refang` normalises all of these.

Every pattern here is linear: bracketed markers are fixed-width, with at most
one optional space on each side.
"""

from __future__ import annotations

import re
import unicodedata

from ttprism.models import IOCType

# Zero-width and soft-hyphen characters that PDF converters and some authors
# insert inside IOCs ("evil\u200b.com").
_INVISIBLE = dict.fromkeys(map(ord, "\u00ad\u200b\u200c\u200d\u2060\ufeff"), None)

# NFKC already folds full-width ASCII (［ ］ （ ） ． ： ＠) to plain ASCII, so only
# CJK brackets without an ASCII equivalent are listed explicitly.
_OPEN = r"[\[({<【〔〖「『]"
_CLOSE = r"[\])}>】〕〗」』]"

_DOT_RE = re.compile(_OPEN + r" ?(?:\.|。|dot|點|点) ?" + _CLOSE, re.IGNORECASE)
_COLON_RE = re.compile(_OPEN + r" ?(://|:) ?" + _CLOSE)
_AT_RE = re.compile(_OPEN + r" ?(?:@|at) ?" + _CLOSE, re.IGNORECASE)
_BACKSLASH_DOT_RE = re.compile(r"(?<=[A-Za-z0-9])\\\.(?=[A-Za-z0-9])")
_HTTP_RE = re.compile(r"(?<![A-Za-z])h(?:xx|\*\*|\[xx\]|\[tt\])p(s?)://", re.IGNORECASE)
_FTP_RE = re.compile(r"(?<![A-Za-z])fxp(s?)://", re.IGNORECASE)


def refang(text: str) -> str:
    """Return ``text`` with common and CJK defanging conventions reversed.

    The text is NFKC-normalised first, which also converts full-width letters,
    digits and punctuation to ASCII.
    """
    text = unicodedata.normalize("NFKC", text).translate(_INVISIBLE)
    text = _DOT_RE.sub(".", text)
    text = _COLON_RE.sub(r"\1", text)
    text = _AT_RE.sub("@", text)
    text = _BACKSLASH_DOT_RE.sub(".", text)
    text = _HTTP_RE.sub(r"http\1://", text)
    return _FTP_RE.sub(r"ftp\1://", text)


_URL_PARTS_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(.*)", re.DOTALL)
_SCHEME_DEFANG = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "ftps": "fxps"}


def defang(value: str, ioc_type: IOCType) -> str:
    """Return a non-clickable form of ``value`` that :func:`refang` reverses."""
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

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
    never merge into an adjacent IOC.
    """
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

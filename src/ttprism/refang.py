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
# characters are deleted first, so that "ev\u200b\u200eil.com" stays one name.
_BIDI_CODES = (0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A))
_BIDI = "\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069"
_INSIDE = "\x21-\x7e\uff01-\uff5e\u3001\u3002\u3008-\u3011\u3014-\u301b" + _BIDI
_BIDI_BREAK_RE = re.compile(
    f"[\u202c\u2069][\u202a-\u202e\u2066-\u2068]|\u2063|(?<![{_INSIDE}])[{_BIDI}]|[{_BIDI}](?![{_INSIDE}])"
)


# Soft hyphens (U+00AD). A PDF draws only visible characters, so where text extracted from a PDF has
# a soft hyphen, the page shows a hyphen: pypdf gives U+00AD for a hyphen drawn with code 0xAD in a
# WinAnsi-encoded font, where pdftotext gives "-". Every soft hyphen is therefore read as "-", one
# for one ("xn" + two of them + "bcher" is "xn--bcher"), so that both texts of such a PDF give the
# same IOCs; at the end of a line, the line-break rules of the extractor then decide what it joins.
# It is deleted instead right after a hyphen at the end of a line, so that "KB-Auto-" + soft hyphen
# there does not get two; in a run of deleted characters that holds U+2063 or the end of a bidi
# embedding or isolate, which separate two names; and in a run of more than _MAX_RUN deleted
# characters. Text copied from a web page has soft hyphens as invisible break hints instead (&shy;);
# refang_soft_hyphens_as_hints gives that reading, so that the caller can see which values depend on
# it.
#
# Between a line-end soft hyphen and the line break there may be anything that refang turns into a
# space or deletes (spaces, zero-width and bidi marks), up to _MAX_BREAK_GAP characters, so that the
# result is the same as for "-"; between "\r" and "\n", only characters it deletes.
_MAX_BREAK_GAP = 1024
_MAX_RUN = 64
_SEPARATORS = {0x2063, 0x202C, 0x2069}


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
def _soft_hyphen_res() -> tuple[re.Pattern[str], re.Pattern[str], re.Pattern[str]]:
    """The patterns for a soft hyphen after a hyphen at a line end, one at a line end, and a run of
    deleted characters whose soft hyphens are deleted."""
    table = _fold_table()
    deleted = {code for code, value in table.items() if value is None}
    gap = {0x09, 0x20} | {code for code, value in table.items() if value == " "} | deleted - {0xAD}
    line_end = (
        f"(?=[{_char_class(gap)}]{{0,{_MAX_BREAK_GAP}}}"
        f"(?:\\r[{_char_class(set(_format_table()) - {0xAD})}]{{0,{_MAX_BREAK_GAP}}})?\\n)"
    )
    hyphens = {ord("-")} | {code for code, value in table.items() if value == "-"}
    run = _char_class(deleted)
    # Only the soft hyphen at the line end is deleted: another one before it is a hyphen ("KB-" and
    # two soft hyphens at a line end is "KB--").
    after_hyphen = (
        f"(?<=[{_char_class(hyphens)}])[{_char_class(deleted - {0xAD})}]{{0,{_MAX_RUN}}}\\u00ad{line_end}"
    )
    # A whole run (the lookbehind keeps the search from starting inside one) with a soft hyphen, and a
    # separator or more than _MAX_RUN characters. Each lookahead reads the run once.
    deleted_runs = (
        f"(?<![{run}])(?=[{run}]*\\u00ad)"
        f"(?:(?=[{run}]*[{_char_class(_SEPARATORS)}])|(?=[{run}]{{{_MAX_RUN + 1}}}))[{run}]+"
    )
    return re.compile(after_hyphen), re.compile(f"\\u00ad{line_end}"), re.compile(deleted_runs)


@functools.cache
def blank_run_res() -> tuple[re.Pattern[str], re.Pattern[str]]:
    """Patterns for a run of white space, line breaks and characters that refang deletes or turns
    into a space (the soft hyphen, which it reads as a hyphen, excepted), and for a character in such
    a run that leaves a space or a line break."""
    table = _fold_table()
    spaces = {0x09, 0x0A, 0x0D, 0x20} | {code for code, value in table.items() if value == " "}
    deleted = {code for code, value in table.items() if value is None} - {0xAD}
    return re.compile(f"[{_char_class(spaces | deleted)}]+"), re.compile(f"[{_char_class(spaces)}]")


# Characters that, at the end of a line, may join it to the next.
_LINE_JOINING = frozenset("-\u00ad\u2010\u2011\u2212\ufe63\uff0d")
# Brackets of a spaced defang, which refang joins across the spaces ("evil [.] com", "a [at] b.com").
_OPENING = frozenset("[(\uff08\uff3b\u3010")
_CLOSING = frozenset("])\uff09\uff3d\u3011")


def cut_between_values(text: str, limit: int, window: int) -> str | None:
    """``text`` if it has at most ``limit`` characters, else its start cut where no value can go on,
    or None if there is no such place. The cut is at the start of the last blank run (white space,
    line breaks and what refang deletes) in the last ``window`` characters before the limit that
    leaves a space or line break, and that neither follows a line-end hyphen (the line-break rules
    may join the lines) nor touches a bracket (refang joins a spaced "[.]" or "[at]")."""
    if len(text) <= limit:
        return text
    blank_run, leaves_space = blank_run_res()
    for run in reversed(list(blank_run.finditer(text, max(0, limit - window), limit))):
        start, end = run.span()
        before, after = text[start - 1 : start], text[end : end + 1]
        if not leaves_space.search(run.group()) or before in _CLOSING or after in _OPENING:
            continue
        if "\n" in run.group() and before in _LINE_JOINING:
            continue
        return text[:start]
    return None


def _without_soft_hyphens(match: re.Match[str]) -> str:
    return match.group(0).replace("\u00ad", "")


def _soft_hyphens_read(text: str) -> str:
    """``text`` with its soft hyphens read as hyphens, or deleted where an exception says so."""
    after_hyphen, line_end, deleted_runs = _soft_hyphen_res()
    text = line_end.sub("-", after_hyphen.sub("", text))
    return deleted_runs.sub(_without_soft_hyphens, text).replace("\u00ad", "-")


def refang_soft_hyphens_as_hints(text: str) -> str | None:
    """``text`` refanged with every soft hyphen deleted, as the invisible break hints of a web page
    are, or None if :func:`refang` reads none of them as a hyphen."""
    if "\u00ad" not in text:
        return None
    hinted = text.replace("\u00ad", "")
    if _soft_hyphens_read(text) == hinted:
        return None
    return _refang_rest(hinted)


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
    never merge into an adjacent IOC. Soft hyphens become hyphens, as PDF text
    has them where the page shows a hyphen, with the exceptions described at
    _soft_hyphen_res.
    """
    if "\u00ad" in text:
        text = _soft_hyphens_read(text)
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
    """Return a non-clickable form of ``value``, an IOC of type ``ioc_type``.

    The dots of a domain or an IP address (also the IPv4 part of an IPv6 address such as
    ``::ffff:198.51.100.7``) become ``[.]``, the colons of an IPv6 address ``[:]``, and the ``@``
    of an e-mail address ``[@]``. In a URL, ``http``, ``https``, ``ftp`` and ``ftps`` become
    ``hxxp``, ``hxxps``, ``fxp`` and ``fxps`` (other schemes are kept), ``://`` becomes ``[://]``,
    and every dot before the path becomes ``[.]``: in the host, also a bracketed IPv6 host, whose
    colons are kept, and in the user name and password. The path, query and fragment are left as
    they are, so a URL inside them stays clickable. :func:`refang` restores the value, unless a
    part left as it is, or the user name or password, itself contains a defang marker such as
    ``[.]`` or ``(at)``.
    """
    if ioc_type in (IOCType.DOMAIN, IOCType.IPV4):
        return value.replace(".", "[.]")
    if ioc_type == IOCType.IPV6:
        return value.replace(":", "[:]").replace(".", "[.]")
    if ioc_type == IOCType.EMAIL:
        local, _, domain = value.rpartition("@")
        return f"{local}[@]{domain.replace('.', '[.]')}"
    if ioc_type == IOCType.URL:
        match = _URL_PARTS_RE.fullmatch(value)
        if match is None:
            return value.replace(".", "[.]")
        scheme, authority, rest = match.groups()
        scheme = _SCHEME_DEFANG.get(scheme.lower(), scheme)
        return f"{scheme}[://]{authority.replace('.', '[.]')}{rest}"
    return value

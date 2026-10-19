# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Security fixes are marked **Security** and link to
their advisory.

## [Unreleased]

### Changed

- Input that is not UTF-8 (nor UTF-16/32 with a byte-order mark) is an error without
  `--encoding` (exit code 1), naming the first bad byte and suggesting `--encoding big5`, `cp950`
  or `gb18030`, instead of being read with replacement characters that could change values (Big5
  `網域：c2.example` gave `gc2.example`). `decode_text` and `analyze_file` raise `InputError` for it.
  Input with many NUL bytes gets `--encoding utf-16-le` (or `utf-16-be`, `utf-32`) suggested
  instead, as UTF-16 or UTF-32 without a byte-order mark.
- Values from a CAPE report's `network` section are never dropped as masked names: HTTP URLs were
  checked while hosts, domains, DNS queries and HTTP hosts were not; all are connections the
  sandbox saw.

### Fixed

- CAPE text fields over 8,192 characters are left out and counted (`truncated_fields`) instead of
  being cut, which could report a value cut short (`198.51.100.2` for `198.51.100.23`); a command
  line that long is cut at its last blank at or before that point that refang does not join a
  value across (not one next to a bracket, as in `evil [.] com`, in any width), and left out if
  there is no such place; a command line repeated in the report is cut and counted once.
- That cut keeps a value that ends exactly at the 8,192-character limit (it dropped
  `198.51.100.23`, which 0.1.0 reported), and judges a run of blanks that goes on past the limit
  up to its real end, so a bracket, or a line break after a hyphen, right after the limit no
  longer leaves a value cut short (`c2.example` for `c2.example.net`).
- CAPE drops that were not counted now are: API names over 100 characters (`long_api_names`),
  signatures whose name is over 200 (`long_signature_names`), TTP labels that the 200-character cut
  of a signature name merges with another signature's (`merged_ttps`), and filtered values in HTTP
  URLs (`filename_like_domain` and the other filter counts).
- `--defang` also defangs the URLs, domains, IP addresses and e-mail addresses in JSON technique
  evidence, such as CAPE command lines, which stayed clickable; and the dots of an IPv4 part of an
  IPv6 address (`::ffff:198.51.100.7`, `64:ff9b::198.51.100.7`), also in a bracketed URL host. In
  evidence this covers every URL of a list (`'http://a.example','http://b.example'`), names after
  `\`, `@` or `_` (`...\Domains\evil.example`, `dig @ns1.evil.example`) and names in URL paths and
  queries. The `defang()` docstring now describes what it changes.

### Documentation

- Reorganised the README around common tasks (PDF report to IOC CSV, defanged output for chat, CAPE
  to ATT&CK and STIX, library use, custom allowlists and rules), with a quick start, an options table
  and a separate evaluation summary; every example was run and its output pasted as printed. Links
  are absolute so they work on PyPI.
- Added `README.zh-TW.md`, a full Traditional-Chinese README that replaces the short Chinese
  summary at the end of the English one.
- Corrected README statements that did not match the code: rules match API calls in any order,
  not sequences; the reserved names include `example.net`, `example.org`, `.localhost` and
  `.internal`; `--defang` also changes dots in a URL's user name and password; non-UTF-8 text
  needs `--encoding` with its own codec (`big5` or `gb18030`) unless it is UTF-16 or UTF-32 with
  a byte-order mark; names with other non-ASCII letters are skipped or cut short, while CJK, Thai
  and right-to-left letters usually end an IOC; how CAPE limits count repeated values. The quick
  start now creates a virtual environment, and the PDF example no longer overwrites the quick
  start's `report.txt`.

## [0.1.0] - 2026-10-18

### Added

- IOC extraction from report text and Markdown: URLs, domains, IPv4, IPv6, email addresses,
  MD5/SHA-1/SHA-256 hashes and CVE IDs, with TLD validation against the IANA list.
- URLs with `http(s)`, `ftp(s)`, `sftp`, `ws(s)`, `ldap(s)`, `rmi`, `iiop`, `dns`, `tcp`, `udp`,
  `smb`, `file`, `ssh`, `telnet`, `irc`, `rtsp`, `ssl`, `tls`, `smtp(s)`, `imap(s)`, `pop3(s)`,
  `socks`, `redis`, `mongodb`, `mysql`, `mssql`, `postgres(ql)`, `amqp(s)`, `mqtt(s)`, `rsync`,
  `git`, `svn`, `vnc` and `rdp` schemes, also with a prefix (`stratum+tcp`, `git+https`,
  `mongodb+srv`); integer, hex and octal IPv4 hosts (`http://3221225985/`); hosts in UNC paths
  (`\\host\share`, also WebDAV `\\host@SSL\...` and `file://host@SSL/...`, after a label colon and
  JSON-escaped), protocol-relative URLs and wildcard names (`*.evil.com`);
  URL lists joined by commas or quotes split into separate URLs; open-redirect targets and
  percent-encoded URLs inside a URL's query extracted as well, each query parameter on its own,
  keeping the outer URL.
- Noise filters: file names that look like domains (`payload.zip`, `setup.msi.zip`), COM /
  .NET identifiers (`WScript.Shell`, `System.Net.Security`), bare public suffixes (`co.uk`,
  `com.tw`) and browser versions (`Chrome/120.0.0.0`) are dropped and counted under
  `suppressed`; names glued to non-ASCII letters (IDNs, homographs) are skipped instead of
  truncated, but emoji and right-to-left letters next to a name are not glue. A label before an
  IPv6 address (`C2:2001:db8::1`, `IPv6:2001:db8::1`) is not taken as part of it. A literal `%`
  (`LIKE '%198.51.100.7%'`) is not read as a percent escape.
- Fixes from an evaluation on eight public Chinese-language reports
  (`docs/research/2026-10-real-reports.md`): certificate serial numbers labelled as such
  (`SerialNumber: 00B7...`, `序列号：`, `序號 00B7...`) and GUIDs whose hyphens a PDF converter wrote as
  soft hyphens are no longer read as hashes; names and URLs broken across PDF lines are joined where
  the hyphen at the break cannot be part of them (`evil.-` / `com`, `evil-` / `.com`) or is part of
  a URL (`/KB-Auto-win-` / `update.exe`), and otherwise the rest of a name on the next line is
  dropped as a fragment (`line_wrap_fragment`); masked names (`wiki.xxxx.com`) and antivirus
  detection names (`Backdoor.Win32.Ht`) are dropped (`masked_name`, `detection_name`). Every soft
  hyphen is read as a hyphen, one for one, since text extracted from a PDF has one where the page
  shows a hyphen (`KB\u00adAuto`, `xn\u00ad\u00adbcher`, `/\u00ad/raw/`), so pypdf and
  `pdftotext -raw` text of the same PDF give the same IOCs except where one is deleted; at a line
  end, also before up to 1,024 spaces or format characters, the line-break rules apply to it as to
  `-`. It is deleted right after a hyphen at a line end (where `pdftotext -raw` gives `--`), in a
  run of format characters with U+2063 or the end of a bidi embedding or isolate, and in a run of
  more than 64 format characters. A warning says when deleting every soft hyphen, as the break hints
  of web pages (`&shy;`), would change any value reported (at most the first 8 Mi characters of such
  a text, cut where no value can go on, are extracted a second time to find out; in a longer text
  only values that deleting them would add are found). A line ending in a hyphen is joined with the
  next as part of a URL only when the URL really reaches the hyphen, not when a URL ended earlier on
  the line (Chinese text without spaces) or at its closing quote, and a URL wrapped after its own
  hyphens over several lines is joined at every break, also after a dot wrap; while it is still in
  its host, only a line of host characters, or one going on to a port or path, carries it further.
- Refanging of common and CJK defang styles: `[.]`, `(.)`, `[dot]`, `【.】`, `〔.〕`, `[。]`,
  the same markers with a space on each side (` [.] `, ` (at) `, ` {dot} `), `[/]`, `[//]`,
  full-width characters (`．`, `［＠］`, `１９８．５１…`), `hxxp`, `hxxp[s]`, `hxxp(s)`,
  `http(s)`, `h[tt]p`, `[:]`, `[://]`, Unicode hyphens, minus signs and spaces, `xn–` from
  typographers, and zero-width, bidi and other format characters inserted by PDF converters
  (bidi controls between two names separate them). Only width variants, ligatures, hyphens and
  dot forms are folded (not full NFKC), so superscript footnotes and circled list numbers never
  merge into an IOC, and full-width `（），；！` stay as they are, so they end a URL.
- `--defang` output for safe sharing.
- CAPE `report.json` parser: network IOCs, sample/dropped/payload hashes, URLs on executed
  command lines, signatures, API calls, written registry keys.
- ATT&CK mapping rules in YAML (`rules/attack/`, 111 rules) for CAPE signatures, command lines,
  API call sequences and registry writes, written against Enterprise ATT&CK 19.2, each with a
  confidence level and reference. Command phrases match on word boundaries (`_` counts as part of
  a word; switches such as `-enc` must be a word of their own) in two views of each command, quotes
  removed and quotes as spaces, with glued switches (`del/f/q`) split, so cmd.exe quote, caret and
  switch obfuscation does not hide them. Commands chained with `&`, `&&` or `||` are matched one by
  one, and `chained_commands` covers idioms that span them (`ping ... & del`). `exclude_commands`
  lets a rule ignore commands such as `net user ... /add` or `ipconfig /flushdns`, and `<arg>`
  stands for one argument (`net start <arg>`, `net share <arg>=`). Phrase lists are indexed by the
  word runs every match contains, so each command is tested only against lists that can match it.
- Normalisation of revoked ATT&CK IDs through the revocation history (for example `T1086` →
  `T1059.001`, `T1562.001` → `T1685`), for IDs in reports and in CAPE's own signature TTPs.
- Output as JSON, CSV and STIX 2.1 bundles (indicators, vulnerabilities, attack patterns).
- Default allowlist for platform root domains, sandbox background traffic, OCSP/CRL hosts and
  reference sites, plus custom allowlists; reserved and documentation values filtered by default.
- `ttprism validate-rules` for rule authors.
- Security hardening: linear-time regexes with a ReDoS test suite (pathological 1 MB inputs, cost per MB),
  chunked input reading with a size limit, JSON nesting limit, strict YAML schemas with aliases
  and duplicate keys rejected, per-report caps on rule inputs (IOC extraction and rule matching each
  see at most 8 Mi characters of CAPE command lines, with a warning past that), an indexed IP allowlist, atomic
  `-o` writes (in place where a new file cannot replace the old one), CSV formula escaping,
  control/bidi-character sanitisation of all output and messages, explicit
  reserved-IP tables independent of the Python version (IPv6 outside `2000::/3` is reserved),
  Hypothesis fuzz tests.
- Project governance: security policy with private vulnerability reporting, threat model,
  contributing guide, code of conduct, issue templates.
- An evaluation on public Chinese-language reports against iocextract and ioc-finder, with a
  ground truth reviewed line by line before any tool ran and blinded judging
  (`docs/research/2026-10-real-reports.md`): eight Simplified-Chinese reports with an IOC appendix,
  on which the fixes above were made, and Traditional-Chinese reports held out until the end, in a
  first set of four (one real IOC list, two lists of reference links, one English body) and a
  second set of four real IOC lists in Traditional Chinese chosen under a corrected rule. None of
  them uses full-width or CJK-bracket defanging (two of the second set use ASCII `[.]`), so
  TTPrism's handling of those writings is supported only by synthetic tests.

[Unreleased]: https://github.com/yuchen-0321/TTPrism/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yuchen-0321/TTPrism/releases/tag/v0.1.0

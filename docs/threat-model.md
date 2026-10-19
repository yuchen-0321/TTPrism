# TTPrism threat model

TTPrism reads threat reports, sandbox output, rule files and allowlists, and writes JSON, CSV and
STIX. Report and sandbox content is **attacker-controlled by assumption**: an adversary who knows
analysts use TTPrism can shape the strings their malware produces, or publish a booby-trapped
"report". This document lists what we defend against, how, and which tests keep each defence in
place. It backs the scope section of [SECURITY.md](../SECURITY.md).

## Assets and trust boundaries

| Input | Trust | Notes |
| --- | --- | --- |
| Report text / Markdown / PDF-converted text | Untrusted | Any bytes, any size up to the limit |
| CAPE `report.json` | Untrusted | Produced by a sandbox running hostile code |
| Rule files (`--rules`), allowlists (`--allowlist`) | Semi-trusted | Chosen by the analyst, but may be downloaded from others |
| Command-line arguments, output path | Trusted | Supplied by the analyst |

TTPrism makes no network requests and never executes, decompresses or opens referenced files.

## Threats and mitigations

| Threat | Example | Mitigation | Tests |
| --- | --- | --- | --- |
| ReDoS / super-linear regex | 1 MB of `a1.a1.a1…` makes a naive domain regex backtrack quadratically | Every pattern starts with a negative lookbehind so matches begin only at token boundaries; all repetitions are bounded; no nested ambiguous quantifiers. URL tail clean-up is a single linear pass. | `tests/test_redos.py` (pathological 1 MB report texts and command lines, limits in seconds per MB), `tests/test_fuzz.py` |
| Resource exhaustion: size | A multi-GB "report" | Input is read in 1 MiB chunks up to `--max-size` (default 64 MiB, at most 16 GiB); larger input is rejected before parsing. Rule and allowlist files are capped at 2 MiB. | `test_cli.py::test_max_size`, `test_cli.py::test_max_size_ceiling`, `test_allowlist.py::test_oversized_allowlist_rejected` |
| Resource exhaustion: nesting | `[[[[…` 1 million levels deep | CPython's JSON decoder raises `RecursionError` before exhausting the C stack. The deepest accepted document is about 1,000 levels on Python 3.11, about 10,000 on 3.12–3.13 (C recursion limit), and set by stack-space checks on 3.14+ (about 40,000 with an 8 MiB stack). TTPrism turns it into a clean error. Nesting below that limit is harmless because TTPrism never walks parsed data recursively; an explicit depth check would add a full extra pass over large reports for no added protection. | `test_redos.py::test_malformed_json_fails_fast`, `test_cli.py::test_bad_inputs` |
| Resource exhaustion: huge fields and lists | A 50 MB command line; a million fake API names or commands so that every rule rescans them | Most CAPE string fields over 8,192 characters are left out and counted (`truncated_fields`) rather than cut; a command line that long is instead cut at its last blank before the limit that refang does not join a value across (left out if it has none), and repeated lines are cut once. At most 10,000 commands (each split into at most 32 chained commands), registry keys, signatures, distinct API names and reported (technique, signature) pairs per report go into rule matching, and the overflow is counted under `suppressed` (`truncated_*`). Signature names in reported TTPs are cut to 200 characters. IOC extraction and rule matching each see the first 8 Mi characters of command lines (about 1,000 commands of 8 KiB); the rest are counted as `truncated_ioc_commands` and `truncated_rule_commands` and named in a warning. Network, hash and signature fields are not affected. Each command is normalised once, and tested only against the phrase lists whose word runs it contains; phrases are precompiled regexes over literal text, so near-miss command lines are scanned in C. Everyday command lines cost about 0.03 s/MB (long lines) to 0.09 s/MB (short ones) here, 19 to 28 times less than testing every list on every command; the tests assert at most 0.25 s/MB and at least 10 times less. Case-folded views are computed once per report, not per rule. Evidence strings are capped at 200 characters (`--defang` can make them longer, since it adds brackets) and 20 items per technique; unknown-ID warnings list at most 20 IDs. | `test_cape.py::test_huge_field_values_are_truncated`, `test_cape.py::test_other_fields_over_the_field_limit_are_left_out`, `test_cape.py::test_command_line_over_the_field_limit_is_cut_between_values`, `test_cape.py::test_command_line_is_not_cut_inside_a_spaced_defang`, `test_cape.py::test_fields_of_exactly_the_field_limit_are_kept`, `test_cape.py::test_repeated_long_command_lines_are_cut_once`, `test_redos.py::test_repeated_long_command_lines_are_cut_once`, `test_cape.py::test_oversized_behaviour_lists_are_capped_and_fast`, `test_cape.py::test_reported_ttps_are_capped`, `test_attack.py::test_phrase_matching_is_fast_on_near_misses`, `test_attack.py::test_chained_lines_cost_little_more_than_single_ones`, `test_cape.py::test_rule_matching_sees_a_bounded_amount_of_commands`, `test_cape.py::test_ioc_extraction_sees_a_bounded_amount_of_commands`, `test_redos.py::test_everyday_command_matching_cost`, `test_attack_equivalence.py` (same results as testing every list) |
| Malformed structure | `"hosts": "1.2.3.4"`, `"calls": 5` | The CAPE parser reads only known fields and type-checks each one; anything unexpected is skipped. | `test_cape.py::test_malformed_reports_do_not_crash`, `test_fuzz.py::test_parse_cape_never_crashes` |
| Unsafe deserialization | `!!python/object/apply:os.system` in a rule file | YAML is loaded with a `SafeLoader` subclass (plain scalars, lists and dicts only). Schemas are strict: unknown keys, duplicate keys and non-string values are rejected, and `attack_version` must look like `19.2`. Scalars PyYAML cannot build (a 5,000-digit integer, `2026-02-30`) are a clean error. | `test_allowlist.py::test_invalid_allowlists`, `test_attack.py::test_attack_version_formats`, `test_attack.py::test_invalid_rules`, `test_cli.py::test_config_values_that_yaml_cannot_build` |
| YAML alias expansion and nesting | Nested anchors expanding to 10⁹ items, or to millions of rule phrases; `- - - …` 1,000 levels deep | YAML aliases are rejected outright, so a small file cannot expand. Deep nesting becomes a clean "YAML nesting too deep" error instead of a traceback. | `test_allowlist.py::test_alias_expansion_is_rejected_quickly`, `test_allowlist.py::test_deep_nesting_is_a_clean_error`, `test_cli.py::test_rule_file_aliases_and_deep_nesting` |
| Allowlist lookup cost | 20,000 IPs against an 8,000-range allowlist | IP allowlists are indexed by IP version and prefix length, so a lookup is at most 33 (IPv4) or 129 (IPv6) set probes. The ranges are kept in a tuple, so the index cannot go stale. | `test_allowlist.py::test_ip_lookups_use_an_index`, `test_allowlist.py::test_ip_index_follows_updates` |
| Path traversal / clobbering | Output name derived from report content; a crash half-way through writing `-o` | The output path comes only from `-o`; nothing is derived from input. Writing over the input file is refused. Output is encoded first and written to a temporary file that replaces the target only on success, so an existing file is never left truncated. Where a new file cannot take the old one's place (other hard links, a bind-mounted file, a directory the user cannot write to, an owner or group the new file would not get), the file is overwritten in place, as before. Lone surrogates (from non-UTF-8 file names or JSON escapes) are replaced instead of crashing the encoder. Short writes and closed pipes are handled without tracebacks. | `test_cli.py::test_refuses_to_overwrite_input`, `test_cli.py::test_failed_write_keeps_the_existing_output_file`, `test_cli.py::test_output_is_written_in_place_when_it_cannot_be_replaced`, `test_cli.py::test_unencodable_output_is_replaced`, `test_cli.py::test_closed_pipe_fails_quietly` |
| CSV formula injection | A value starting with `=`, `+`, `-`, `@` opens as a formula in Excel | Cells starting with those characters (or tab/CR/LF) are prefixed with `'`. | `test_export.py`, `test_fuzz.py::test_csv_cells_never_start_a_formula` |
| Terminal escape injection | A command line containing `ESC]0;…BEL`, an IPv6 zone ID or a YAML key carrying escapes, printed to a terminal | One character set (C0 and C1 controls, DEL, lone surrogates, bidi marks, embeddings, overrides and isolates) is replaced with U+FFFD in evidence, in the input file name written to JSON and STIX, and in every message TTPrism or its argument parser prints; unknown config keys are shown with `repr()`; scoped IPv6 addresses (`%zone`) are rejected. JSON output escapes C0 controls anyway, but not C1 or bidi characters. | `test_export.py::test_output_never_contains_raw_control_characters`, `test_cli.py::test_messages_are_safe_for_terminals`, `test_cli.py::test_argument_errors_are_safe_for_terminals`, `test_cli.py::test_input_name_and_evidence_are_safe_for_terminals`, `test_extract.py::test_scoped_addresses_are_rejected` |
| Misleading IOCs from Unicode tricks | `microsоft.com` with a Cyrillic о read as `ft.com`; a superscript footnote `45.77.123.9²` read as `45.77.123.92`; zero-width or bidi marks splitting a name | Only width variants, ligatures, hyphens and a few dot forms are folded to ASCII (not full NFKC), so footnote and list digits stay separate and text never grows more than 3x. Format (Cf) characters are removed inside a name, except that a soft hyphen is read as a hyphen, as text extracted from a PDF has one where the page shows a hyphen; bidi controls between names separate them instead of merging them into one. A name glued to a non-ASCII letter of a space-separated, left-to-right script is dropped instead of truncated; emoji selectors and keycaps are not letters. | `test_refang.py::test_refang_keeps_other_compatibility_characters`, `test_refang.py::test_refang_does_not_expand_text`, `test_extract.py::test_domain_glued_to_other_letters_is_not_truncated`, `test_extract.py::test_bidi_controls_between_names_separate_them`, `test_extract.py::test_emoji_and_right_to_left_letters_next_to_names` |
| STIX pattern injection | A URL containing `'` breaking out of the pattern literal | Values are escaped per the STIX patterning grammar and validated by the `stix2` library in tests. | `test_stix.py::test_pattern_escaping` |
| Hidden characters in our own source | Zero-width or bidi characters that hide code from review (Trojan Source) | Test data spells such characters as escapes; a test fails if any text file contains them. | `tests/test_repo_hygiene.py` |
| Supply chain | Compromised maintainer token or CI action | No long-lived PyPI token (Trusted Publishing); GitHub Actions pinned by commit SHA and updated by Dependabot; least-privilege workflow permissions; one runtime dependency (PyYAML). | `.github/workflows/`, `docs/maintainer-setup.md` |

## Measured cost

Measured in the development container (Linux, x86_64, Python 3.11); other machines may be up to
about twice as slow. Costs are per MB of input.

| Work | Input | Cost |
| --- | --- | --- |
| Rule matching | Everyday command lines of 8 KiB | 0.04 s/MB |
| Rule matching | Short, distinct command lines | 0.10 s/MB |
| Rule matching | Random printable characters | 0.15 s/MB |
| Rule matching | Worst pathological case in `tests/test_redos.py` | 0.9 s/MB |
| IOC extraction | CAPE command lines, everyday content | 0.8–1.1 s/MB |
| IOC extraction | Report text (`tests/data/report_zh.md` repeated) | 0.9–1.2 s/MB |
| IOC extraction | Report text with a soft hyphen read as a hyphen: at most its first 8 Mi characters are extracted a second time | At most about twice the cost of the same text without it (the tests allow 3 times); 5.4 s/MB on the worst pathological case with one added |
| IOC extraction | Worst pathological case in `tests/test_redos.py` | 2.3–3.5 s/MB |

At the default `--max-size` of 64 MiB, a whole analysis (`ttprism extract`, reading and decoding
included) took:

| Input of 64 MiB | Time | Peak memory |
| --- | --- | --- |
| Text report, everyday content (`tests/data/report_zh.md` repeated) | 79 s | 0.4 GB |
| Text report, the worst pathological text of `tests/test_redos.py` repeated | 186 s | 0.3 GB |
| The same with one soft hyphen | 223 s | 0.4 GB |
| Text report of distinct names with a soft hyphen each (`h0\u00adx.example.com …`) | 125 s | 1.5 GB |
| Invalid UTF-8 read with `--encoding utf-8` (every byte `0xFF`, read as U+FFFD) | 130 s | 0.4 GB |
| Distinct short names (`a.0.io a.1.io …`, 5.7 million values) | 345 s | 8.1 GB |
| Distinct short URLs (`http://a.0.io/ …`, 3.4 million URLs and as many hosts) | 379 s | 9.9 GB |
| CAPE report of 8 KiB URIs of pathological text in `network.http` (or paths in `https_ex`) | 151 s | 0.2 GB |
| CAPE report of 4.2 million distinct host addresses, kept (`--include-reserved`) | 186 s | 6.0 GB |
| The same, filtered as reserved (the default) | 79 s | 2.0 GB |
| CAPE report of 1.3 million distinct URLs in `network.http`, kept (`--include-reserved`) | 90 s | 2.1 GB |
| The same, filtered as reserved (the default) | 56 s | 0.9 GB |
| CAPE report of 1.1 million dropped files with distinct hashes | 40 s | 1.8 GB |
| CAPE report of 1.5 million DNS queries with answers, filtered as reserved | 33 s | 1.2 GB |
| CAPE report whose command lines are all pathological text (both 8 Mi caps reached) | 31 s | 0.2 GB |
| CAPE report of 3 million distinct API names | 8 s | 1.0 GB |

Text reports are bounded only by `--max-size`. These are measured examples, not upper bounds: the
64 MiB texts above took 79 to 379 s here, about one to six and a half minutes, the most for millions
of distinct short URLs and names, which also take the most memory (the maintainer's review measured
the equivalent of 5 to 5.7 minutes for distinct short names and for invalid UTF-8 read with
`--encoding utf-8` on its machine and inputs; without `--encoding`, invalid UTF-8 is an error before
extraction). CAPE reports of 64 MiB took 8 to 186 s, up to about three minutes: the caps bound
command lines and the behaviour lists, but not the network sections, dropped files or payloads,
whose entries are each checked, and each URL of `network.http`, `http_ex` and `https_ex` (up to
8 KiB) is searched for IOCs with no cap on their total length. Hostile CAPE reports are therefore
bounded by `--max-size` like text reports, not by the caps.

A text with a soft hyphen that refang reads as a hyphen has at most its first 8 Mi characters
(`MAX_SOFT_HYPHEN_CHECK_CHARS`, cut where no value can go on) extracted a second time, to see
whether deleting the soft hyphens would change any value. The extra cost is bounded by those 8 Mi
characters, so it is at most about twice the cost of the same text without the soft hyphen; on 64
MiB of the worst pathological text it added 37 s here. The comparison looks values up instead of
walking all of them, so it does not grow with the rest of the text. Faster IOC extraction is planned
for v0.2 (issue #2).

## Known limitations

- **Encoding guesses.** Without `--encoding`, input that is not UTF-8 (nor UTF-16 or UTF-32 with a
  byte-order mark) is an error that names the first bad byte and suggests a codec (`big5`, `cp950`,
  `gb18030`, or `utf-16-le` for input with many NUL bytes). With `--encoding`, bytes that the codec
  cannot decode are replaced with U+FFFD without a warning, which can change a value next to them.
- **Memory.** Parsed JSON can take many times the input size in memory: crafted 64 MiB CAPE reports
  of millions of tiny objects peaked at 0.9 to 2.0 GB with the default filtering, and at 2.1 GB (1.3
  million URLs) and 6.0 GB (4.2 million addresses) with those values kept by `--include-reserved`
  (see "Measured cost"). Every distinct extracted value is kept, with where it was seen, until the
  output is written, so a text report of millions of distinct short values takes far more: 8.1 GB
  for 64 MiB of distinct short names and 9.9 GB for 64 MiB of distinct short URLs in the
  measurements above. Lower `--max-size` when processing untrusted reports in bulk or on small
  machines. Bounding memory is planned for v0.2 (issue #3).
- **Time.** The 64 MiB text reports measured took one to about six and a half minutes, and the 64
  MiB CAPE reports up to about three minutes (see "Measured cost"); other inputs may take longer.
  Lower `--max-size` to bound the time per input when processing untrusted reports in bulk.
- **Python versions.** The JSON nesting guarantee relies on CPython's recursion guard, which every
  supported version (3.11+) provides. The deepest document accepted differs between versions
  (see the nesting row above), so the same deep input may be accepted on one version and rejected
  on another.

## Non-goals

- Detecting malicious content: TTPrism extracts and labels, it does not judge maliciousness.
- Protecting against a malicious analyst: anyone who can run TTPrism can already run anything.

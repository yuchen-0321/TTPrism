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
| ReDoS / super-linear regex | 1 MB of `a1.a1.a1…` makes a naive domain regex backtrack quadratically | Every pattern starts with a negative lookbehind so matches begin only at token boundaries; all repetitions are bounded; no nested ambiguous quantifiers. URL tail clean-up is a single linear pass. | `tests/test_redos.py` (56 pathological 1 MB inputs), `tests/test_fuzz.py` |
| Resource exhaustion: size | A multi-GB "report" | Input is read in 1 MiB chunks up to `--max-size` (default 64 MiB, at most 16 GiB); larger input is rejected before parsing. Rule and allowlist files are capped at 2 MiB. | `test_cli.py::test_max_size`, `test_cli.py::test_max_size_ceiling`, `test_allowlist.py::test_oversized_allowlist_rejected` |
| Resource exhaustion: nesting | `[[[[…` 1 million levels deep | CPython's JSON decoder raises `RecursionError` before exhausting the C stack. The deepest accepted document is about 1,000 levels on Python 3.11, about 10,000 on 3.12–3.13 (C recursion limit), and set by stack-space checks on 3.14+ (about 40,000 with an 8 MiB stack). TTPrism turns it into a clean error. Nesting below that limit is harmless because TTPrism never walks parsed data recursively; an explicit depth check would add a full extra pass over large reports for no added protection. | `test_redos.py::test_malformed_json_fails_fast`, `test_cli.py::test_bad_inputs` |
| Resource exhaustion: huge fields and lists | A 50 MB command line; a million fake API names or commands so that every rule rescans them | CAPE string fields are truncated to 8 KiB. At most 10,000 commands, registry keys, signatures, distinct API names and reported (technique, signature) pairs per report go into rule matching, and the overflow is counted under `suppressed` (`truncated_*`). Signature names in reported TTPs are cut to 200 characters. Rule phrases are precompiled regexes over literal text, so near-miss command lines are scanned in C. Case-folded views are computed once per report, not per rule. Evidence strings are capped at 200 characters and 20 items per technique; unknown-ID warnings list at most 20 IDs. | `test_cape.py::test_huge_field_values_are_truncated`, `test_cape.py::test_oversized_behaviour_lists_are_capped_and_fast`, `test_cape.py::test_reported_ttps_are_capped`, `test_attack.py::test_phrase_matching_is_fast_on_near_misses` |
| Malformed structure | `"hosts": "1.2.3.4"`, `"calls": 5` | The CAPE parser reads only known fields and type-checks each one; anything unexpected is skipped. | `test_cape.py::test_malformed_reports_do_not_crash`, `test_fuzz.py::test_parse_cape_never_crashes` |
| Unsafe deserialization | `!!python/object/apply:os.system` in a rule file | YAML is loaded with a `SafeLoader` subclass (plain scalars, lists and dicts only). Schemas are strict: unknown keys and non-string values are rejected, and `attack_version` must look like `19.2`. | `test_allowlist.py::test_invalid_allowlists`, `test_attack.py::test_attack_version_formats` |
| YAML alias expansion and nesting | Nested anchors expanding to 10⁹ items, or to millions of rule phrases; `- - - …` 1,000 levels deep | YAML aliases are rejected outright, so a small file cannot expand. Deep nesting becomes a clean "YAML nesting too deep" error instead of a traceback. | `test_allowlist.py::test_alias_expansion_is_rejected_quickly`, `test_allowlist.py::test_deep_nesting_is_a_clean_error`, `test_cli.py::test_rule_file_aliases_and_deep_nesting` |
| Allowlist lookup cost | 20,000 IPs against an 8,000-range allowlist | IP allowlists are indexed by IP version and prefix length, so a lookup is at most 33 (IPv4) or 129 (IPv6) set probes. | `test_allowlist.py::test_ip_lookups_use_an_index` |
| Path traversal / clobbering | Output name derived from report content; a crash half-way through writing `-o` | The output path comes only from `-o`; nothing is derived from input. Writing over the input file is refused. Output is encoded first and written to a temporary file that replaces the target only on success, so an existing file is never left truncated. Lone surrogates (from non-UTF-8 file names or JSON escapes) are replaced instead of crashing the encoder. Short writes and closed pipes are handled without tracebacks. | `test_cli.py::test_refuses_to_overwrite_input`, `test_cli.py::test_failed_write_keeps_the_existing_output_file`, `test_cli.py::test_unencodable_output_is_replaced`, `test_cli.py::test_closed_pipe_fails_quietly` |
| CSV formula injection | A value starting with `=`, `+`, `-`, `@` opens as a formula in Excel | Cells starting with those characters (or tab/CR/LF) are prefixed with `'`. | `test_export.py`, `test_fuzz.py::test_csv_cells_never_start_a_formula` |
| Terminal escape injection | A command line containing `ESC]0;…BEL`, an IPv6 zone ID or a YAML key carrying escapes, printed to a terminal | Control, bidi and surrogate characters in evidence and in every message TTPrism prints are replaced with U+FFFD; unknown config keys are shown with `repr()`; scoped IPv6 addresses (`%zone`) are rejected. JSON output escapes control characters anyway. | `test_export.py::test_output_never_contains_raw_control_characters`, `test_cli.py::test_messages_are_safe_for_terminals`, `test_extract.py::test_scoped_addresses_are_rejected` |
| Misleading IOCs from Unicode tricks | `microsоft.com` with a Cyrillic о read as `ft.com`; a superscript footnote `45.77.123.9²` read as `45.77.123.92`; zero-width or bidi marks splitting a name | Only width variants, ligatures, hyphens and a few dot forms are folded to ASCII (not full NFKC), so footnote and list digits stay separate and text never grows more than 3x. All format (Cf) characters are removed. A name glued to a non-ASCII letter of a space-separated script is dropped instead of truncated. | `test_refang.py::test_refang_keeps_other_compatibility_characters`, `test_refang.py::test_refang_does_not_expand_text`, `test_extract.py::test_domain_glued_to_other_letters_is_not_truncated` |
| STIX pattern injection | A URL containing `'` breaking out of the pattern literal | Values are escaped per the STIX patterning grammar and validated by the `stix2` library in tests. | `test_stix.py::test_pattern_escaping` |
| Hidden characters in our own source | Zero-width or bidi characters that hide code from review (Trojan Source) | Test data spells such characters as escapes; a test fails if any text file contains them. | `tests/test_repo_hygiene.py` |
| Supply chain | Compromised maintainer token or CI action | No long-lived PyPI token (Trusted Publishing); GitHub Actions pinned by commit SHA and updated by Dependabot; least-privilege workflow permissions; one runtime dependency (PyYAML). | `.github/workflows/`, `docs/maintainer-setup.md` |

## Known limitations

- **Encoding guesses.** Non-UTF-8 input is decoded with replacement characters unless the analyst
  passes `--encoding` (for example `big5` or `gb18030`). A warning is printed.
- **Memory.** Parsed JSON can take up to about 25 times the input size in memory: a crafted
  64 MiB report (millions of tiny objects) peaks around 1.6 GB. Lower `--max-size` when processing
  untrusted reports in bulk or on small machines.
- **Python versions.** The JSON nesting guarantee relies on CPython's recursion guard, which every
  supported version (3.11+) provides. The deepest document accepted differs between versions
  (see the nesting row above), so the same deep input may be accepted on one version and rejected
  on another.

## Non-goals

- Detecting malicious content: TTPrism extracts and labels, it does not judge maliciousness.
- Protecting against a malicious analyst: anyone who can run TTPrism can already run anything.

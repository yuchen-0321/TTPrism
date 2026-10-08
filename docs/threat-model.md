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
| ReDoS / super-linear regex | 1 MB of `a1.a1.a1…` makes a naive domain regex backtrack quadratically | Every pattern starts with a negative lookbehind so matches begin only at token boundaries; all repetitions are bounded; no nested ambiguous quantifiers. URL tail clean-up is a single linear pass. | `tests/test_redos.py` (22 pathological 1 MB inputs), `tests/test_fuzz.py` |
| Resource exhaustion: size | A multi-GB "report" | Input read is capped (`--max-size`, default 64 MiB); larger input is rejected before parsing. Rule and allowlist files are capped at 2 MiB. | `test_cli.py::test_max_size`, `test_allowlist.py::test_oversized_allowlist_rejected` |
| Resource exhaustion: nesting | `[[[[…` 1 million levels deep | CPython's JSON decoder raises `RecursionError` at the interpreter recursion limit (about 1000 levels) before exhausting the C stack; TTPrism turns it into a clean error. TTPrism never recurses over parsed data itself. | `test_redos.py::test_malformed_json_fails_fast`, `test_cli.py::test_bad_inputs` |
| Resource exhaustion: huge fields and lists | A 50 MB command line; a million fake API names or commands so that every rule rescans them | CAPE string fields are truncated to 8 KiB. At most 10,000 commands, registry keys, signatures and distinct API names per report go into rule matching, and the overflow is counted under `suppressed`. Case-folded views are computed once per report, not per rule. Evidence strings are capped at 200 characters and 20 items per technique; unknown-ID warnings list at most 20 IDs. | `test_cape.py::test_huge_field_values_are_truncated`, `test_cape.py::test_oversized_behaviour_lists_are_capped_and_fast` |
| Malformed structure | `"hosts": "1.2.3.4"`, `"calls": 5` | The CAPE parser reads only known fields and type-checks each one; anything unexpected is skipped. | `test_cape.py::test_malformed_reports_do_not_crash`, `test_fuzz.py::test_parse_cape_never_crashes` |
| Unsafe deserialization | `!!python/object/apply:os.system` in a rule file | YAML is loaded with `yaml.safe_load` only. Schemas are strict: unknown keys and non-string values are rejected. | `test_allowlist.py::test_invalid_allowlists` |
| YAML alias expansion ("billion laughs") | Nested anchors expanding to 10⁹ items | Strict schema validation rejects the first non-string list item, so expanded structures are never walked. | `test_allowlist.py::test_alias_expansion_is_rejected_quickly` |
| Path traversal / clobbering | Output name derived from report content | The output path comes only from `-o`; nothing is derived from input. Writing over the input file is refused. | `test_cli.py::test_refuses_to_overwrite_input` |
| CSV formula injection | A value starting with `=`, `+`, `-`, `@` opens as a formula in Excel | Cells starting with those characters (or tab/CR/LF) are prefixed with `'`. | `test_export.py`, `test_fuzz.py::test_csv_cells_never_start_a_formula` |
| Terminal escape injection | A command line containing `ESC]0;…BEL` printed to a terminal | Control characters in evidence are replaced with U+FFFD; JSON output escapes them anyway. | `test_export.py::test_output_never_contains_raw_control_characters` |
| STIX pattern injection | A URL containing `'` breaking out of the pattern literal | Values are escaped per the STIX patterning grammar and validated by the `stix2` library in tests. | `test_stix.py::test_pattern_escaping` |
| Hidden characters in our own source | Zero-width or bidi characters that hide code from review (Trojan Source) | Test data spells such characters as escapes; a test fails if any text file contains them. | `tests/test_repo_hygiene.py` |
| Supply chain | Compromised maintainer token or CI action | No long-lived PyPI token (Trusted Publishing); GitHub Actions pinned by commit SHA and updated by Dependabot; least-privilege workflow permissions; one runtime dependency (PyYAML). | `.github/workflows/`, `docs/maintainer-setup.md` |

## Known limitations

- **Encoding guesses.** Non-UTF-8 input is decoded with replacement characters unless the analyst
  passes `--encoding` (for example `big5` or `gb18030`). A warning is printed.
- **Memory.** A 64 MiB CAPE report can use several hundred MiB of memory once parsed. Lower
  `--max-size` when processing untrusted reports in bulk.
- **Python versions.** The JSON nesting guarantee relies on CPython's recursion guard, which every
  supported version (3.11+) provides.

## Non-goals

- Detecting malicious content: TTPrism extracts and labels, it does not judge maliciousness.
- Protecting against a malicious analyst: anyone who can run TTPrism can already run anything.

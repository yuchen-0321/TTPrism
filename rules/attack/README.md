# ATT&CK mapping rules

These YAML files map sandbox observations to MITRE ATT&CK techniques. They are kept separate from
the code so analysts can contribute without writing Python.

| File | Matches against |
| --- | --- |
| `cape_signatures.yaml` | CAPE signature names |
| `windows_commands.yaml` | Executed command lines |
| `windows_api.yaml` | Windows API calls recorded by CAPE's monitor |
| `windows_registry.yaml` | Registry keys written during the run |

Rules apply to sandbox reports. For text reports TTPrism records the technique IDs the author
wrote (and resolves outdated ones); it does not guess techniques from prose.

## Rule format

```yaml
attack_version: "19.2"   # ATT&CK release the file was written against (quoted)

rules:
  - id: cmd.inhibit-recovery          # unique; letters, digits, . _ -
    technique: T1490                  # technique or sub-technique ID
    confidence: high                  # low | medium | high (default: medium)
    description: Shadow copies, backups or boot recovery deleted or disabled.
    references:                       # at least one public source
      - https://attack.mitre.org/techniques/T1490/
    match:                            # the rule fires if ANY matcher matches
      commands:
        - [vssadmin, delete shadows]  # every phrase in the inner list must appear
        - [wmic, shadowcopy, delete]
```

### Matchers

| Matcher | Syntax | Matching |
| --- | --- | --- |
| `signatures` | list of names, `*` and `?` allowed | Whole signature name, case-insensitive |
| `apis` | list; `"A\|B"` means either | Any listed API was called |
| `apis_all` | list of lists | Every entry of one inner list was called (in any order) |
| `commands` | list of phrases or lists of phrases | Phrase appears in one command line on word boundaries, case-insensitive, after quotes and `^` escapes are removed and spaces collapsed |
| `registry` | list of substrings or lists of substrings | Substring of a written key path, case-insensitive. Use single quotes so backslashes stay literal |

### Choosing a confidence

- **high**: the observation is close to unambiguous (`vssadmin delete shadows` → T1490).
- **medium**: usually malicious in a sandbox run, but benign software does it too.
- **low**: a weak signal that is only useful alongside others.

When unsure, choose the lower level. Analysts can filter on confidence; they cannot un-see noise.

## Checking your changes

```sh
ttprism validate-rules                # all bundled rules
ttprism validate-rules my_rules.yaml  # your own file
```

Validation fails on structural errors and on techniques that are unknown, revoked or deprecated in
the bundled ATT&CK catalog. Run `ttprism extract --rules my_rules.yaml report.json` to try rules
without adding them to the project.

## When ATT&CK releases a new version

1. `python scripts/update_attack_catalog.py`
2. `ttprism validate-rules` and fix every warning (revoked techniques name their replacement).
3. Update `attack_version` in each file and note the change in `CHANGELOG.md`.

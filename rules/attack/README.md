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
      exclude_commands: ["/?"]        # command lines matching this are ignored by `commands`
```

### Matchers

| Matcher | Syntax | Matching |
| --- | --- | --- |
| `signatures` | list of names, `*` and `?` allowed | Whole signature name, case-insensitive |
| `apis` | list; `"A\|B"` means either | Any listed API was called |
| `apis_all` | list of lists | Every entry of one inner list was called (in any order) |
| `commands` | list of phrases or lists of phrases | Phrase appears in one command, not as part of a longer word (see below) |
| `chained_commands` | same as `commands` | Like `commands`, but the phrases of one inner list may come from different commands chained on one line (`ping 127.0.0.1 -n 3 & del x`) |
| `exclude_commands` | same as `commands` | Not a matcher of its own: commands that match it are ignored by this rule's `commands`; a line with such a command is ignored by `chained_commands` |
| `registry` | list of substrings or lists of substrings | Substring of a written key path, case-insensitive. Use single quotes so backslashes stay literal |

### How command phrases match

Command lines and phrases are normalised the same way:

1. Lower-cased.
2. cmd.exe `^` escapes removed (`s^c^h^t^a^s^k^s` becomes `schtasks`).
3. The dashes U+2013, U+2014 and U+2015, which PowerShell accepts for `-`, become `-`.
4. Quotes (`"` and `'`) handled in two ways, giving two views: turned into spaces, and deleted.
   cmd.exe runs `s"c"htasks` as `schtasks`, which only the second view shows; the first keeps
   `"a" "b"` as two words.
5. Runs of whitespace collapsed to one space, and leading and trailing spaces removed.

A command line can chain several commands with cmd.exe's `&`, `&&` and `||`, or line breaks
(`^&` is a literal `&`, and a single `|` pipe stays within one command, so PowerShell pipelines
are not split). Each command is matched on its own: an inner list of `commands` matches when all
of its phrases occur in the same view of one command, in any order and anywhere in it, and
`exclude_commands` drops only the commands it matches. So in
`net user /domain & net user x P@ss /add`, the `/add` of the second command neither excludes the
first one from discovery nor turns it into a domain account. A line is split into at most 64
commands; the rest stays in the last one.

A phrase matches only where it is not part of a longer word: if it starts with a letter, digit or
`_`, the character before it must not be one, and likewise at the end. So `net view` does not
match `Net.WebClient` or `example.net/view`, and `user` does not match `HKEY_CURRENT_USER`. A
phrase that starts with `-` or `/` is a switch and must start a word, after whitespace or at the
start of the command: `/en` does not match the URL path `/en-us/`, nor `-encoded` the word
`url-encoded`. Phrases are literal text, not patterns. Write words that must be adjacent as one
phrase (`net user`), not as separate list items, and spell out the variants a tool accepts
(`net.exe user`, `net1 user`; `certutil -urlcache` and `/urlcache`; `cmd /c` and `cmd/c`).

A phrase ending in ` <arg>` matches only when an argument follows it: `net start <arg>` matches
`net start updsvc` but not a bare `net start`, `net start > out.txt` or `net start /?`.

A phrase that is empty after normalisation (for example `'""'`) is rejected when the rules load,
and so is `<arg>` anywhere but at the end of a phrase.

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

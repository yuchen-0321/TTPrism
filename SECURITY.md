# Security Policy

TTPrism is maintained by [@yuchen-0321](https://github.com/yuchen-0321) on a volunteer basis.

TTPrism parses threat reports and sandbox output, so its input is attacker-controlled by design.
We treat bugs that let crafted input harm the analyst's machine or workflow as security
vulnerabilities. The design assumptions and mitigations are in
[docs/threat-model.md](docs/threat-model.md).

## Supported Versions

TTPrism is pre-1.0. Security fixes go into the latest release only.

| Version                            | Supported |
| ---------------------------------- | --------- |
| Latest release and the `main` branch | Yes       |
| Older releases                     | No        |

## Scope

In scope: vulnerabilities in the TTPrism code itself, for example:

- crafted input that causes excessive CPU or memory use (e.g. ReDoS)
- crashes or hangs triggered by malformed reports or sandbox output
- reading or writing files outside the intended paths
- unsafe deserialization or code execution (including through rule or allowlist files)
- injection in exported files (e.g. CSV formula injection) or terminal escape sequences in output
- weaknesses in how TTPrism is built and released (CI workflows, PyPI publishing)

Out of scope (please open a public issue with the *Detection quality* template instead):

- false positives or false negatives in IOC extraction
- incorrect or outdated MITRE ATT&CK mappings
- known issues in third-party dependencies, unless TTPrism uses them in an exploitable way

## Reporting a Vulnerability

Please do not report security vulnerabilities through public issues.

- Preferred: the **Report a vulnerability** button under this repository's
  [Security tab](https://github.com/yuchen-0321/TTPrism/security/advisories/new)
  (GitHub private vulnerability reporting).
- If you cannot use GitHub: open a public issue titled "Security contact request" that contains
  **no details**, and the maintainer will arrange a private channel.

Please include the affected version, steps to reproduce or a proof of concept, the impact, and any
suggested fix. Do not attach live malware samples; share hashes or a sanitized test case instead.

## What to Expect

- Acknowledgement within 3 business days
- Initial assessment and severity rating (CVSS) within 7 business days
- Fix target: 30 days for critical/high, 90 days for medium/low
- We will keep you updated and agree on a disclosure date with you, normally no later than
  90 days after your report

## Disclosure

Fixes are developed in a private fork attached to the GitHub Security Advisory, then released as a
new version together with the published advisory and a CHANGELOG entry. We request a CVE through
GitHub where appropriate. Reporters are credited in the advisory unless they prefer to remain
anonymous.

## Safe Harbor

We will not take legal action against researchers who act in good faith, avoid privacy violations
and service disruption, and give us reasonable time to fix the issue before public disclosure.

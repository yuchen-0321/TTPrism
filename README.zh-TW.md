[English](https://github.com/yuchen-0321/TTPrism/blob/main/README.md) | **繁體中文**

# TTPrism

[![PyPI](https://img.shields.io/pypi/v/ttprism)](https://pypi.org/project/ttprism/)
[![Python](https://img.shields.io/pypi/pyversions/ttprism)](https://pypi.org/project/ttprism/)
[![License](https://img.shields.io/github/license/yuchen-0321/TTPrism)](https://github.com/yuchen-0321/TTPrism/blob/main/LICENSE)
[![CI](https://github.com/yuchen-0321/TTPrism/actions/workflows/ci.yml/badge.svg)](https://github.com/yuchen-0321/TTPrism/actions/workflows/ci.yml)

> 本文件對應英文版 [README.md](https://github.com/yuchen-0321/TTPrism/blob/main/README.md)；兩者不一致時以英文版為準。

**TTPrism 把一份威脅報告或一次沙箱執行結果，拆成其中的 IOC（入侵指標）和 MITRE ATT&CK（MITRE 整理的攻擊手法知識庫）技術**，就像稜鏡把光拆成光譜。它也讀得懂全形與中日韓括號的 defang（把指標改寫成無法直接點擊的形式）寫法，例如 `evil【.】com`、`１９８．５１．１００．２３`。

到目前為止評估過的 12 份真實中文 IOC 清單，沒有一份用全形或中日韓括號的 defang 寫法，所以 TTPrism 對這些寫法的處理只有合成測試支持；實測到的優勢是錯誤值較少，以及能修復被 PDF 斷行切開的值，recall（抓到的比例）和 ioc-finder 相同。詳見[評估](https://github.com/yuchen-0321/TTPrism/blob/main/README.zh-TW.md#評估)。

> **狀態：** 0.1.0，第一個正式版。非常歡迎回饋意見和偵測品質的回報。

## 快速開始

需要 Python 3.11 以上：

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install ttprism
```

Windows 上改用 `py -m venv .venv` 和 `.venv\Scripts\activate`；Debian 或 Ubuntu 若缺少 `venv`，先執行 `apt install python3-venv`。

只要用指令的話，可以用 `pipx install ttprism`，它會裝在獨立的環境裡。

把下面這段混用多種 defang 寫法的中文報告節錄存成 `report.txt`：

```text
C2 為 update-check【.】example 與 198.51.100[.]23，下載 hxxps://cdn.update-check［.］example/stage2.bin
攻擊者利用 ＣＶＥ－２０２３－２３３９７，並執行 PowerShell（T1086）。
```

```sh
$ ttprism extract report.txt -f csv --include-reserved
type,value,sources,detail
url,https://cdn.update-check.example/stage2.bin,text,
domain,cdn.update-check.example,text,
domain,update-check.example,text,
ipv4,198.51.100.23,text,
cve,CVE-2023-23397,text,
attack-technique,T1059.001,reported,PowerShell (reported as T1086)
```

會需要 `--include-reserved`，只是因為範例用的是文件用 IP 和保留的 `.example` 頂級網域。不加的話，它們會和其他保留值一樣被過濾掉，只剩下 CVE 和技術：

```sh
$ ttprism extract report.txt -f csv
type,value,sources,detail
cve,CVE-2023-23397,text,
attack-technique,T1059.001,reported,PowerShell (reported as T1086)
```

過時的 `T1086` 會以現行的 `T1059.001` 回報。拿掉 `-f csv` 就是 JSON 輸出，裡面的 `suppressed` 也會記下被過濾掉多少值。

## 它做什麼、不做什麼

- **抽取 IOC**（URL、網域、IPv4／IPv6、電子郵件、MD5／SHA-1／SHA-256、CVE 編號），來源可以是報告文字，也可以是 CAPE（開源的惡意程式沙箱）報告；並且**還原 defang 寫法**：ASCII 寫法（`evil[.]com`、`hxxp://`），以及全形和中日韓括號寫法（`evil【.】com`、`evil．com`、`attacker［＠］mail．com`、`１９８．５１．１００．２３`）。在[合成測試](https://github.com/yuchen-0321/TTPrism/blob/main/docs/research/2026-10-existing-tools.md)中，以英文為主的抽取工具漏掉了後面這些寫法。緊接中文字、中間沒有空白的網域它也抓得到，這點 ioc-finder 同樣做得到。
- **把沙箱行為對應到 ATT&CK**，規則以 YAML 撰寫，比對 CAPE 簽章、指令列、API 呼叫和登錄機碼寫入。它也會**把過時的技術編號換成現行編號**：CAPE 簽章裡的 TTP 標籤，大約四分之一指向 ATT&CK 後來已撤銷或棄用的技術。
- **匯出** JSON、CSV 或 STIX 2.1（交換威脅情資的標準格式）bundle。
- **把輸入當成惡意資料處理。** 正規表示式都在線性時間內跑完、輸入大小有上限、不執行也不下載任何東西，CSV 輸出用 Excel 開也安全。詳見[威脅模型](https://github.com/yuchen-0321/TTPrism/blob/main/docs/threat-model.md)。

它不做的事：

- **只做靜態分析。** 不執行、不解壓、不下載樣本，也不連線或解析它找到的指標。
- **不直接讀 PDF。** 要先把 PDF 轉成文字（見 [PDF 報告轉成 IOC 的 CSV](https://github.com/yuchen-0321/TTPrism/blob/main/README.zh-TW.md#pdf-報告轉成-ioc-的-csv)）。
- **沙箱格式目前只支援 CAPE。**
- **不從內文推測技術。** 文字報告只記錄作者寫出來的技術編號。

| 輸入 | 讀取方式 |
| --- | --- |
| 純文字、Markdown | 抽取 IOC，加上文中寫出的 ATT&CK 技術編號 |
| PDF 報告 | 先轉成文字（例如 `pdftotext -raw advisory.pdf`）；TTPrism 不解析 PDF。[真實報告評估](https://github.com/yuchen-0321/TTPrism/blob/main/docs/research/2026-10-real-reports.md)用的是 pypdf（`page.extract_text()`），頁首頁尾都包含在內；不同轉換工具斷行和寫連字號的方式不一樣 |
| CAPE `report.json` | 自動偵測（看起來像 JSON 但無法解析的輸入，會當成文字分析並顯示警告）；讀取網路、檔案、指令、API 呼叫、登錄機碼、簽章 |

不是 UTF-8 的文字要用 `--encoding` 指定它的編碼：Big5 用 `big5`（在 Windows 上存的檔案用 `cp950`），GB18030 用 `gb18030`。沒指定時，TTPrism 遇到這種文字會報錯停止（exit code 1），並指出第一個不是 UTF-8 的位元組，不會輸出錯的值。指定了 `--encoding` 時，無法解碼的位元組會直接被替換、不會警告，所以指定錯的編碼時，緊鄰中文的值仍可能消失或變成錯的值：Big5 的 `網域：c2.example` 用 `--encoding utf-8` 讀，會得到 `gc2.example`。有 BOM（位元組順序標記）的 UTF-16／UTF-32 會自動辨識。

## 常見用法

### PDF 報告轉成 IOC 的 CSV

假設 PDF 頁面上的內容是：

```text
攻擊者從 hxxps://cdn.update-check[.]example/KB-Auto-win-
update.exe 下載第二階段酬載，C2 為 203.0.113[.]7。
樣本 SHA-256：8ddcb559924bcba8d5497d45f66c01316bb77d5cf8618b9771e62166fdbbce05
```

先用 `pdftotext -raw`（poppler 套件提供：`brew install poppler`，Debian／Ubuntu 用 `apt install poppler-utils`）轉成文字，再抽取：

```sh
$ pdftotext -raw advisory.pdf advisory.txt
$ ttprism extract advisory.txt -f csv -o iocs.csv --include-reserved
$ cat iocs.csv
type,value,sources,detail
url,https://cdn.update-check.example/KB-Auto-win-update.exe,text,
domain,cdn.update-check.example,text,
ipv4,203.0.113.7,text,
sha256,8ddcb559924bcba8d5497d45f66c01316bb77d5cf8618b9771e62166fdbbce05,text,
```

在 URL 自己的連字號後面斷開的那一行，會被接回去。請用 `-raw`：pdftotext 的預設模式會把行尾是連字號的那一行接到下一行並刪掉連字號，在這裡會得到 `/KB-Auto-winupdate.exe`。評估用的 pypdf（`page.extract_text()`）也可以。斷行怎麼接、哪些情況會接錯，列在[限制](https://github.com/yuchen-0321/TTPrism/blob/main/README.zh-TW.md#限制)。

### 輸出 defang 後貼到聊天室

```sh
$ ttprism extract report.txt -f csv --defang --include-reserved
type,value,sources,detail
url,hxxps[://]cdn[.]update-check[.]example/stage2.bin,text,
domain,cdn[.]update-check[.]example,text,
domain,update-check[.]example,text,
ipv4,198[.]51[.]100[.]23,text,
cve,CVE-2023-23397,text,
attack-technique,T1059.001,reported,PowerShell (reported as T1086)
```

`--defang` 適用於 JSON 和 CSV。它讓 IOC 值無法點擊，如上面的輸出（`hxxps[://]cdn[.]update-check[.]example/stage2.bin`、`198[.]51[.]100[.]23`），電子郵件位址則變成 `ops[@]corp[.]example`；IPv6 位址裡 IPv4 部分的點也會改掉（`[:][:]ffff[:]198[.]51[.]100[.]7`）。URL 的路徑和查詢字串保持原樣，所以在 IOC 清單裡，出現在另一個 URL 路徑或查詢字串裡的 URL 仍然可以點擊。JSON 裡的技術證據（例如 CAPE 的指令列）也會 defang，連路徑和查詢字串也包括在內：其中每個 URL 改到路徑之前（任何後面接 `://` 的 scheme，也包括另一個 URL 裡的 URL，或一串 URL 清單裡的每一個），以及每個 IP 位址、電子郵件位址和最後一段是 TLD 的名稱，接在 `\`、`@` 或 `_` 後面的也算（`...\Domains\evil[.]example`、`dig @ns1[.]evil[.]example`；`cmd.exe` 和 `T1059.001` 保持原樣）。

### CAPE 報告轉成 ATT&CK 技術與 STIX

CAPE 的 `report.json` 會自動偵測。下面的範例用的是 repo 裡的合成報告 [`tests/data/cape_report.json`](https://github.com/yuchen-0321/TTPrism/blob/main/tests/data/cape_report.json)，存成 `report.json`：

```sh
$ ttprism extract report.json -f csv --include-reserved
type,value,sources,detail
url,http://update-check.example/gate.php?id=1,cape:network.http,
url,http://update-check.example/p.ps1,cape:commands,
url,https://cdn.update-check.example/stage2.bin,cape:network.http,
domain,cdn.update-check.example,cape:network.dns;cape:network.http,
domain,update-check.example,cape:commands;cape:network.domains;cape:network.http,
ipv4,192.0.2.80,cape:network.domains,
ipv4,198.51.100.23,cape:network.domains;cape:network.hosts,
ipv4,203.0.113.5,cape:network.hosts,
ipv4,203.0.113.7,cape:network.dns,
md5,1b2062450bd3d9b1f41aadadae4f44f1,cape:dropped,
md5,5f89cef4c9ed3f109bc7c400d822e60e,cape:target,
sha1,a2eebf3d37a530f407d8907e869f880fa5346b29,cape:target,
sha1,fe077a501a66e0b4be2672b15928a38ae34068af,cape:dropped,
sha256,334486bd1343a3dd88c93f57d0b16f08d906bccb7cf084f1e545547defabb6dc,cape:dropped,
sha256,8ddcb559924bcba8d5497d45f66c01316bb77d5cf8618b9771e62166fdbbce05,cape:target,
attack-technique,T1027.002,reported;rule:cape.packer-known,Software Packing (reported as T1045)
attack-technique,T1053.005,rule:cmd.scheduled-task,Scheduled Task
attack-technique,T1055,reported,Process Injection
attack-technique,T1055.012,rule:cape.injection-runpe;rule:api.process-hollowing,Process Hollowing
attack-technique,T1059.001,rule:cmd.powershell,PowerShell
attack-technique,T1105,rule:api.download-to-file;rule:cmd.download,Ingress Tool Transfer
attack-technique,T1490,rule:cmd.inhibit-recovery,Inhibit System Recovery
attack-technique,T1497,reported,Virtualization/Sandbox Evasion
attack-technique,T1497.001,rule:cape.antivm,System Checks
attack-technique,T1547.001,rule:reg.run-keys,Registry Run Keys / Startup Folder
```

在 JSON 輸出（`ttprism extract report.json --include-reserved`）裡，每個技術都會寫明為什麼被列出。下面這個例子，CAPE 簽章帶著已撤銷的 `T1045`，同時 TTPrism 的規則也比對到同一個簽章：

```json
{
  "id": "T1027.002",
  "name": "Software Packing",
  "tactics": [
    "stealth"
  ],
  "status": "active",
  "reported": true,
  "rules": [
    "cape.packer-known"
  ],
  "confidence": "high",
  "evidence": [
    "CAPE signature packer_upx: T1045",
    "signature: packer_upx"
  ],
  "original_ids": [
    "T1045"
  ],
  "url": "https://attack.mitre.org/techniques/T1027/002/"
}
```

要輸出 STIX 2.1 bundle 的話，每個 IOC 是一個 `indicator`、每個 CVE 是一個 `vulnerability`、每個技術是一個 `attack-pattern`，再由一個 `grouping` 把它們串在一起：

```sh
$ ttprism extract report.json -f stix -o bundle.json --include-reserved
```

### 當成 Python 套件使用

```python
import ttprism

# include_reserved keeps documentation names such as *.example.com, filtered by default.
options = ttprism.AnalysisOptions(include_reserved=True)
result = ttprism.analyze_text("C2: c2【.】example.com, see T1071.001", options)
for ioc in result.iocs:
    print(ioc.type, ioc.value)          # domain c2.example.com
print(result.techniques[0].name)        # Web Protocols

result = ttprism.analyze_file("report.json")
bundle = ttprism.to_stix_bundle(result)
```

### 自訂 allowlist 和規則

allowlist（排除清單）用來拿掉你永遠不想看到的值，例如自己組織的名稱。格式是 YAML，鍵有 `domains`、`url_hosts`、`ips`（位址或 CIDR 範圍）、`hashes` 和 `emails`；`"name"` 只比對完全相同的名稱，`"*.name"` 比對該名稱和它底下所有子網域。放在 `domains` 的項目只會拿掉網域本身：除非主機也列在 `url_hosts`，這台主機上的 URL 還是會回報。內建清單是 [`allowlist.yaml`](https://github.com/yuchen-0321/TTPrism/blob/main/src/ttprism/data/allowlist.yaml)。

`my-allowlist.yaml`：

```yaml
domains:
  - "*.corp.example"
```

`incident.txt`：

```text
受害主機 hr.corp.example 連線至 update-check【.】example
```

```sh
$ ttprism extract incident.txt -f csv --include-reserved --allowlist my-allowlist.yaml
type,value,sources,detail
domain,update-check.example,text,
```

在 JSON 輸出裡，被拿掉的名稱會記成 `"suppressed": {"allowlisted": 1}`。

ATT&CK 規則也是 YAML，格式說明在 [`rules/attack/README.md`](https://github.com/yuchen-0321/TTPrism/blob/main/rules/attack/README.md)。`my-rules.yaml`：

```yaml
attack_version: "19.2"

rules:
  - id: local.powershell-hidden-window
    technique: T1564.003
    confidence: medium
    description: PowerShell started with a hidden window.
    references:
      - https://attack.mitre.org/techniques/T1564/003/
    match:
      commands:
        - [powershell, -w hidden]
        - [powershell, -windowstyle hidden]
```

先用內建的 ATT&CK 目錄檢查，再和內建規則一起使用：

```sh
$ ttprism validate-rules my-rules.yaml
1 rules checked against ATT&CK 19.2: OK
$ ttprism extract report.json -f csv --include-reserved --rules my-rules.yaml
```

對上面那份 CAPE 報告，輸出會多出一行：

```text
attack-technique,T1564.003,rule:local.powershell-hidden-window,Hidden Window
```

## 選項

`ttprism extract [options] INPUT`，`INPUT` 是檔案，或用 `-` 代表標準輸入（`cat report.txt | ttprism extract -`）。

| 選項 | 作用 |
| --- | --- |
| `-f json\|csv\|stix` | 輸出格式（預設 `json`） |
| `-o FILE` | 寫到檔案，不輸出到標準輸出 |
| `--defang` | 在 JSON／CSV 輸出中 defang IOC 值 |
| `--include-reserved` | 不過濾私有／文件用 IP，以及 `example`／`test` 網域 |
| `--allowlist FILE` | 加入 allowlist（可重複指定）；`--no-default-allowlist` 停用內建清單 |
| `--rules PATH` | 加入 ATT&CK 規則檔或目錄（可重複指定）；`--no-default-rules` 停用內建規則 |
| `--input-format auto\|text\|cape` | 輸入格式（預設 `auto`：依內容自動偵測） |
| `--encoding NAME` | 輸入文字的編碼（預設 UTF-8，有 BOM 時自動辨識 UTF-16／UTF-32；不指定時其他編碼的文字會報錯；例如 `big5`、`gb18030`） |
| `--max-size SIZE` | 拒絕超過這個大小的輸入（預設 `64m`） |
| `-q`、`--quiet` | 不顯示警告 |

`ttprism validate-rules [PATH ...]` 用內建的 ATT&CK 目錄檢查規則檔（沒給路徑時檢查內建規則）。`ttprism --version` 顯示版本。

## ATT&CK 對應的運作方式

- **`reported`**：輸入本身寫出了這個技術。例如報告引用 `T1059.001`，或 CAPE 簽章自帶 TTP 標籤。
- **`rules`**：TTPrism 的規則比對到觀察到的行為。規則以 YAML 放在 [`rules/attack/`](https://github.com/yuchen-0321/TTPrism/blob/main/rules/attack/README.md)，分析師不用寫 Python 也能新增和審查。每條規則都有 `confidence` 和一個公開的參考來源。
- **`original_ids`**：輸入裡過時的編號，透過 ATT&CK 的撤銷紀錄換成現行編號（`T1086` → `T1059.001`、`T1562.001` → `T1685`）。

TTPrism 不從報告內文推測技術。內建的目錄是 Enterprise ATT&CK **19.2**。

## 過濾

TTPrism 預設會拿掉下列的值（括號裡是 `suppressed` 底下的鍵名）：

- **保留值**（`reserved`）：IP 位址，例如私有、loopback、link-local、多播和文件用的範圍，全球單播區塊 `2000::/3` 以外的 IPv6 位址，以及 6to4 和 Teredo（IPv4-mapped 和 NAT64 `64:ff9b::/96` 位址依它帶的 IPv4 位址判斷；完整規則見 [`extract.py`](https://github.com/yuchen-0321/TTPrism/blob/main/src/ttprism/extract.py) 的 `is_reserved_ip`）；URL 主機 `localhost`；以及 `example.com`、`example.net`、`example.org`、`.test`、`.example`、`.invalid`、`.local`、`.localhost`、`.internal` 名稱。
- **allowlist 上的值**（`allowlisted`）：大型平台的根網域（`google.com`，但不含 `drive.google.com` 或其上的 URL）、沙箱的背景流量、憑證撤銷查詢主機、`attack.mitre.org` 這類參考網站，以及空檔案的雜湊值。見 [`allowlist.yaml`](https://github.com/yuchen-0321/TTPrism/blob/main/src/ttprism/data/allowlist.yaml)。
- **看起來像網域的檔名**（`filename_like_domain`）：沒有寫在 URL 裡的 `payload.zip` 或 `setup.py`。
- **公共後綴**（`public_suffix`）：沒有寫在 URL 裡的 `co.uk`、`com.tw` 或 `gov.tw`（底下的名稱，例如 `evil.co.uk`，會保留）。
- **程式識別名稱**（`code_identifier`）：`WScript.Shell`、`System.Net.Security` 這類 COM 和 .NET 名稱。
- **瀏覽器版本**（`version_like`）：User-Agent 字串裡的 `Chrome/120.0.0.0` 不是 IPv4 位址。
- **憑證序號**（`certificate_serial`）：緊接在序號標籤（`SerialNumber:`、`Serial Number`、`序列号`、`序號`、`憑證序號`，有沒有冒號都算）後面的十六進位值，長度和雜湊值一樣，但不是雜湊值。
- **遮蔽過的名稱**（`masked_name`）：有一段是三個以上 `x` 的名稱、電子郵件位址和 URL 主機（`wiki.xxxx.com`），報告用這種寫法隱藏真正的值。CAPE 報告 `network` 區段裡的值（`hosts`、`domains`、`dns` 和 HTTP 請求，包括 URL）不做這項檢查，因為那是沙箱實際看到的連線。
- **防毒軟體偵測名稱**（`detection_name`）：`Backdoor.Win32.Ht` 或 `Trojan.MSIL.Bot`，它們的家族名稱剛好是頂級網域。
- **跨行斷開的名稱片段**（`line_wrap_fragment`）：上一行以字母或數字加連字號結尾時（`dynamic-` / `dns.net`），下一行開頭的名稱或電子郵件位址片段，因為那個連字號可能屬於名稱，也可能不屬於。見「限制」。

CAPE 報告也只讀到固定的上限，這些上限記在 `suppressed` 底下：API 名稱、指令列、登錄機碼寫入、簽章和 TTP 標籤，各自最多讀 10,000 個（`truncated_apis`、`truncated_commands`、`truncated_registry_writes`、`truncated_signatures`、`truncated_ttps`）；指令列在規則比對和 IOC 搜尋時，各自最多讀總共 8 Mi 個字元（`truncated_rule_commands`、`truncated_ioc_commands`，並會在警告中列出）。重複的 API 名稱、指令列和登錄機碼寫入只算一次；簽章照列出的次數算，TTP 標籤則是每個技術和簽章的組合算一次。超過 8,192 個字元的文字欄位會被略過（`truncated_fields`，每次遇到都算，重複的指令列只算一次）；只有指令列例外，會在這個位置或之前最後一個 refang 不會把值接過去的空白或換行處切斷（不切在括號旁邊，例如 `evil [.] com`，也不切在連字號後面的換行；跨過這個位置的連續空白看到它真正的結尾），沒有這種位置才略過。超過 100 個字元的 API 名稱（`long_api_names`，每個名稱算一次），以及名稱超過 200 個字元的簽章（`long_signature_names`，照列出的次數算）會被略過；在 TTP 標籤裡，這種名稱會被截到 200 個字元，而截斷後和另一個簽章的標籤變成相同的，會被計數（`merged_ttps`）。

## 限制

- 中文句號 `。` 只有在括號裡（`[。]`、`【。】`）才當成點，因為它也是中文句子的結尾。
- 國際化網域名稱只認 punycode（`xn--`）形式。用其他非 ASCII 字母寫的名稱不會照原樣回報：依字母和它們的位置，可能整個略過（`münchen.example`，或用西里爾字母 `о` 仿冒的同形字），或被截短（`c2.example.рф` 會得到 `c2.example`）。中文、日文、韓文、泰文，以及阿拉伯文這類由右往左寫的文字，通常會被當成 IOC 周圍的文字，所以 `例子.c2.example` 會得到 `c2.example`。
- `.bit`、`.i2p` 這類替代根的頂級網域不認得；`.onion` 認得。
- URL 後面直接接 `;command`（例如 `wget http://x/a.sh;chmod`）時會保留這段後綴，因為 `;` 在 URL 裡是合法字元。
- 只有一側有空白的 defang 記號（`update [.]example[.]com`）會被讀成一個單字加上一個以點開頭的名稱，得到 `example.com`；請寫成兩側都有空白的 ` [.] `，或兩側都沒有。
- 兩個名稱字元之間的單一 bidi 記號會被當成名稱的一部分移除，所以只靠這種記號分隔的兩個 IOC（`198.51.100.7\u200f203.0.113.9`）不會被拆開。
- 全形冒號 `：` 會讀成 `:`，所以 URL 後面直接接 `：` 和 ASCII 文字時（`.../a.exe：C2`），會連那段文字一起保留；全形的 `（），；！` 則會結束 URL。
- ATT&CK 指令規則只在 cmd.exe 的 `&`、`&&` 和 `||` 切分一行：用 `;` 串起來的 PowerShell 敘述會被當成一個指令比對。
- `--defang` 不改 IOC 清單裡 URL 的路徑和查詢字串（在技術證據裡，路徑和查詢字串中認得出來的值也會改）。在技術證據裡，它只改認得出來的值：沒寫 scheme、最後一段又不是 TLD 的主機，會保留它的點。
- 跨行斷開的名稱和 URL（PDF 轉換工具常留下這種結果）只在兩種情況會接回去：斷點的連字號不可能屬於它們（`evil.-` / `com`、`evil-` / `.com`），或 URL 在它自己的某個連字號後面斷開（`/KB-Auto-win-` / `update.exe`，跨幾行都會接；URL 還在主機部分時，只有一整行都是字母、數字、點和連字號，或接著進到連接埠或路徑的那一行，才會把它帶到再下一行，所以在使用者名稱或密碼後面又斷行的 URL 會在那裡被切斷）。以下情況會判斷錯誤：
  - 真的以 `-` 結尾、剛好位於行尾的 URL，會和下一行開頭接在一起；
  - 轉換工具在斷開 URL 時自己加上的連字號會被保留（即使 URL 其實是 `/downloadfile.exe`，`/download-` / `file.exe` 也會得到 `/download-file.exe`），跨幾行都一樣；
  - 上一行以字母或數字加 `-` 結尾時（`2019-` / `evil.com`），下一行開頭的名稱會被當成片段拿掉；
  - 在密碼的連字號處斷開的 URL（`http://user:pa-` / `ss@evil.com/x`）會整個遺失：第一行結尾不構成 URL，第二行開頭則是片段。

  沒有連字號的斷行（`mp.weixi` / `n.qq.com`）看不出這一行還沒結束，所以這類名稱和 URL 不會被接起來，每一行上的部分可能各自被回報。
- 每個軟連字號（U+00AD）都讀成一個連字號，一對一（兩個就是 `--`）：從 PDF 抽出的文字裡，它出現在頁面上顯示連字號的位置（字型使用 WinAnsi 編碼、以代碼 0xAD 畫出的連字號，pypdf 會給 U+00AD，`pdftotext -raw` 則給 `-`；除了下面說的軟連字號被刪除的情況，兩份文字抽出的 IOC 相同）。在行尾，它和換行之間最多隔 1,024 個空白或格式字元時，作用和 `-` 完全一樣。以下情況則會刪除它：緊接在行尾連字號之後（這時 `pdftotext -raw` 會給 `--`；在它前面的軟連字號仍算連字號）、在含有 U+2063 或 bidi embedding／isolate 結束字元的一串格式字元裡，以及在超過 64 個的一串格式字元裡。從網頁複製的文字則把軟連字號當成看不見的斷行提示（`&shy;`）：這時 `KB-Auto` 應該讀成 `KBAuto`，中間夾著軟連字號的雜湊值會遺失，而它的片段可能被回報成較短的雜湊值（從中間切開的 SHA-256 變成兩個 MD5）。刪掉所有軟連字號會改變任何回報的值時，TTPrism 會發出警告；為了判斷這一點，它會把這類文字最前面最多 8 Mi 個字元再抽取一次，並在沒有值能延續的地方切開（8 Mi 處或之前最後 64 Ki 個字元內的行尾或空白，沒有的話就在 8 Mi 處）。在更長的文字裡，它只找得到刪掉軟連字號後會多出來的值，找不到會消失的值。pdftotext 的預設模式和 `-raw` 不同，還會把行尾是連字號的那一行接到下一行並刪掉連字號，這是逐行讀取無論如何都重現不了的。
- 沙箱格式目前只支援 CAPE。

## 評估

我們用公開的 TLP:CLEAR 中文報告，以每份報告自己的 IOC 清單為標準答案，比較 TTPrism、iocextract 和 ioc-finder。方法、所有數字和每一個判斷都在[研究報告](https://github.com/yuchen-0321/TTPrism/blob/main/docs/research/2026-10-real-reports.md)裡。

- **報告。** 8 份附 IOC 附錄的簡體中文報告（2018–2020 年），以及 4 份附真正 IOC 清單的繁體中文報告（研究報告裡的第二組）。更早的一組 4 份繁體中文報告，是依照字面解讀「指標」挑出來的，其中只有 1 份是真正的 IOC 清單：2 份是參考連結清單，1 份的內文是英文。
- **中日韓 defang 寫法還沒有在真實報告上驗證過。** 這 12 份附真正 IOC 清單的報告，沒有一份用全形或中日韓括號的 defang 寫法；裡面僅有的 defang 都是 ASCII（`[.]`，以及一次 `hxxp`）。TTPrism 對這些寫法的處理只有合成測試支持。
- **實測對 TTPrism 有利的結果：** 錯誤值較少，以及能修復被 PDF 斷行切開的名稱和 URL。
  - 在簡體中文報告上，TTPrism 找到了被斷行切開、其他工具都漏掉的 9 個網域名稱中的 7 個，錯誤值是 7 個，ioc-finder 41 個、iocextract 48 個。這些數字是在根據同一批 8 份報告做出修正之後量的，所以偏樂觀。
  - 在繁體中文第二組上（TTPrism 的程式碼在這批報告加入之前就已凍結），錯誤值 TTPrism 是 0 個、ioc-finder 1 個、iocextract 36 個。第二組是在前一組量完之後，從已經看過的候選報告中挑出來的。
- **除此之外，recall 和 ioc-finder 相同。** 在第二組上兩者都找到 75 個值中的 73 個（iocextract 71 個）；三個工具都漏掉的 2 個，是被表格儲存格斷成兩行的 SHA-256 雜湊值。在簡體中文報告上，修正之前 TTPrism 和 ioc-finder 找到的網域相同（171 個中的 162 個；ioc-finder 另外漏了 2 個緊貼括號的 MD5）；修正之後 TTPrism 多找到的 7 個，就是上面那些被切開的名稱。
- **注意事項。** 樣本少，結果只是描述性的。標準答案和標準答案以外每一個值的判斷，都由同一位評估者（Claude，替維護者工作的 AI 助理）完成，沒有測量評分者間的一致性。

## 安全性

TTPrism 只對輸入做靜態解析。它從不執行、解壓或下載樣本，這個 repository 也不含任何惡意程式。測試資料只用保留名稱、文件用 IP 範圍和無害字串的雜湊值。`docs/research/` 底下的評估結果則不同：裡面有從公開 TLP:CLEAR 報告引用的真實 IOC（惡意網域、URL、IP 位址和雜湊值），請當成資料看待，不要開啟或解析它們。

發現漏洞？請私下回報，見 [SECURITY.md](https://github.com/yuchen-0321/TTPrism/blob/main/SECURITY.md)。誤報和漏抓 IOC 不算漏洞，請改開 *Detection quality* issue。

## 參與貢獻

見 [CONTRIBUTING.md](https://github.com/yuchen-0321/TTPrism/blob/main/CONTRIBUTING.md)。請只使用 TLP:CLEAR 的資料。

- **ATT&CK 規則不需要寫 Python。** 規則是 [`rules/attack/`](https://github.com/yuchen-0321/TTPrism/blob/main/rules/attack/README.md) 裡的 YAML 檔，可以用 `ttprism validate-rules` 檢查。
- **回報偵測問題。** 漏抓的 IOC、抽錯的值、認不得的 defang 寫法或錯誤的 ATT&CK 對應，請開 [Detection quality](https://github.com/yuchen-0321/TTPrism/issues/new?template=detection_quality.yml) issue，附上能重現問題的最小節錄。
- **程式碼**：抽取、解析器、匯出、測試；開發環境設定和檢查項目見 CONTRIBUTING.md。

## 授權

MIT；見 [LICENSE](https://github.com/yuchen-0321/TTPrism/blob/main/LICENSE)。

內建的 ATT&CK 目錄衍生自 MITRE ATT&CK®：
© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The
MITRE Corporation. ATT&CK® is a registered trademark of The MITRE Corporation. 頂級網域清單來自 IANA。

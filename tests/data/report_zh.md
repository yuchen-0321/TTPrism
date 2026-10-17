<!--
Synthetic report used by the TTPrism test suite. Every domain uses the reserved
.example TLD or example.com, every IP is from a documentation range, and every
hash is the digest of a harmless string. No content comes from a real incident.
-->

# 某 APT 組織針對台灣半導體產業之攻擊活動分析（測試用虛構報告）

## 摘要

攻擊者透過釣魚郵件（T1566.001）寄送含惡意巨集之附件，寄件者為 attacker［＠］mail-update．example。
受害主機執行 PowerShell（T1086）後，連線至 C2 伺服器 update-check【.】example 與 198.51.100[.]23。

## 入侵指標（IOC）

| 類型 | 指標 |
| --- | --- |
| C2 網域 | update-check[.]example |
| 備用 C2 | ｓｙｎｃ．ｅｘａｍｐｌｅ．ｎｅｔ |
| 下載網址 | hxxps://cdn.update-check〔.〕example/payload/stage2.bin |
| C2 IP | １９８．５１．１００．２３ |
| C2 IP | 203.0.113[.]7:8443 |
| IPv6 | 2001:db8:85a3::8a2e:370:7334 |
| 附件 SHA256 | 8ddcb559924bcba8d5497d45f66c01316bb77d5cf8618b9771e62166fdbbce05 |
| 附件 MD5 | 5F89CEF4C9ED3F109BC7C400D822E60E |

攻擊者使用update-check.example作為主要中繼站（網域緊接中文字，無空白）。
第二階段酬載 payload.zip 與 setup.py 為檔案名稱，不應被視為網域。

## 漏洞利用

攻擊者利用 ＣＶＥ－２０２３－２３３９７ 與 CVE–2021–40444（en dash）取得初始存取。

## ATT&CK 對應

- T1566.001 魚叉式網路釣魚附件
- T1059.001 PowerShell
- T1071.001 網頁協定
- T1562.001 停用安全工具（已於新版 ATT&CK 撤銷）

## 參考資料

- https://attack.mitre.org/techniques/T1566/001/
- https://www.example.com/blog/apt-report（範例連結）

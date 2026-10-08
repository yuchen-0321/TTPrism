# 維護者設定清單

這份清單列出 repo 裡的檔案做不到、必須由維護者在 GitHub 與 PyPI 網頁上手動完成的設定。對應規劃書第四節「帳號與發布安全」與第六節 M1 里程碑。完成一項就勾一項，並在 commit 或 issue 留下日期，作為可查證的紀錄。

## 1. 帳號

- [ ] GitHub 帳號開啟 2FA，優先使用實體安全金鑰或 passkey（Settings → Password and authentication）
- [ ] 保存 recovery codes 到離線位置
- [ ] PyPI 帳號開啟 2FA（Account settings → Two factor authentication）

## 2. 私密漏洞回報（M1 必要項目）

- [ ] Settings → Security（Code security）→ **Private vulnerability reporting** → Enable
- [ ] 確認 repo 首頁的 Security 分頁出現 **Report a vulnerability** 按鈕
- [ ] 開啟通知：Watch → Custom → Security alerts，確保收到回報時會寄信
- [ ] （選做）申請專用的資安聯絡信箱，不要用個人主信箱；設定好後把信箱與 PGP 指紋加回 `SECURITY.md` 與 `CODE_OF_CONDUCT.md`，取代目前「開一個不含細節的 issue」的備用做法

## 3. 分支保護

Settings → Rules → Rulesets → New branch ruleset，目標 `main`：

- [ ] Restrict deletions、Block force pushes
- [ ] Require a pull request before merging（單人專案可把 required approvals 設為 0，但仍強制走 PR，留下 CI 紀錄）
- [ ] Require status checks to pass：`Lint, types, rules`、`Test (...)` 各項、`Build and smoke-test the wheel`
- [ ] （選做）Require signed commits

## 4. 程式碼掃描與相依套件

Settings → Security（Code security）：

- [ ] **Dependabot alerts** 與 **Dependabot security updates** 開啟（版本更新已由 `.github/dependabot.yml` 設定）
- [ ] **CodeQL**：Code scanning → Set up → **Default**，語言選 Python 與 GitHub Actions。repo 刻意不放 CodeQL workflow，由 GitHub 預設設定負責，版本自動更新
- [ ] **Secret scanning** 與 **Push protection** 開啟
- [ ] Settings → Actions → General → Workflow permissions 設為 **Read repository contents**（workflow 需要的權限已在檔案內個別宣告）

## 5. PyPI Trusted Publishing（第一次發布 v0.1 前）

不保存任何 PyPI API token。

1. [ ] GitHub：Settings → Environments → New environment，名稱 `pypi`；加上 **Required reviewers**（自己），讓每次發布都要手動核准
2. [ ] PyPI：Your account → Publishing → **Add a new pending publisher**
   - PyPI project name：`ttprism`
   - Owner：`yuchen-0321`，Repository：`TTPrism`
   - Workflow name：`release.yml`，Environment：`pypi`
3. [ ] 發布流程：更新 `src/ttprism/_version.py` 與 `CHANGELOG.md` → 合併到 `main` → 建立 tag `vX.Y.Z` 與 GitHub Release → `release.yml` 會檢查 tag 與版本一致、建置、等待核准後上傳 PyPI（附 PEP 740 attestation）

## 6. Release tag 簽章

- [ ] 設定 git 簽章（SSH 或 GPG 皆可）並上傳公鑰到 GitHub：`git config --global gpg.format ssh`、`git config --global user.signingkey ~/.ssh/id_ed25519.pub`
- [ ] 打 tag 時使用 `git tag -s vX.Y.Z -m "TTPrism vX.Y.Z"`

## 7. OpenSSF Scorecard

- [ ] `.github/workflows/scorecard.yml` 已就緒，合併到 `main` 後會自動執行並公開結果
- [ ] 第一次結果出來後，把分數記為基準，並在 README 加上 badge：
  `[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/yuchen-0321/TTPrism/badge)](https://scorecard.dev/viewer/?uri=github.com/yuchen-0321/TTPrism)`
- 單人專案的 Code-Review、Maintained（專案未滿 90 天）等項目先天偏低，不必追求滿分

## 8. 安全回報演練（第 4 個月）

規劃書要求一次「標明為演練」的完整流程。建議做法：

- [ ] 開一個 issue 說明即將進行演練與日期
- [ ] 從另一個帳號（或請 lab 同事）透過 Private vulnerability reporting 提交，標題以 `[DRILL]` 開頭，內容可用真實但低風險的問題（例如把 `--max-size` 預設值調高後的記憶體用量）
- [ ] 依 SECURITY.md 的時限走完：確認收到 → 評估與 CVSS → 在 advisory 的私密 fork 修補 → 發布修正版 → 發布 advisory
- [ ] advisory 與 CHANGELOG 都明確寫出這是演練，不申請 CVE
- [ ] 在 issue 記錄每一步的實際時間，作為回應時間的佐證

## 9. 開工前要確認的事（規劃書第八節）

- [ ] 向主管或 lab 確認可以用個人名義開源（必要時取得書面同意）
- [ ] 若專案掛在 lab 或單位名下，請單位確認 `SECURITY.md` 的 Safe Harbor 段落
- [ ] `pyproject.toml` 的 author 欄位與 LICENSE 的著作權人一致

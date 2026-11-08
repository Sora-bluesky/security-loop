[English](README.md) | [日本語](README.ja.md)

# security-loop

Windows PCのソフトウェアと、VPSから届いた在庫を照合するツールです。
インストール済みの版をOSVやランタイムのセキュリティ勧告と比べます。
CISAの既知悪用脆弱性カタログ（KEV）やリリース情報も確認します。
個人用のツールを、そのまま共有しています。対応を決める前に結果と根拠を確認してください。

## 何をするか

`scan.py` はPython環境、npmパッケージと対応lockfile、ランタイムの版を収集します。
Windowsのアプリ、サービス、待受ポート、コンテナやVMの名前も集めます。
VPSについては、PCに届いたパッケージと待受の在庫を読みます。
対応表を使い、各資産を勧告・リリース・更新・手動確認の経路に結び付けます。
コンテナ名やイメージのタグだけでは、その中を調べたことにはなりません。

結果は「該当あり」「該当なし」「確認できなかった」を区別します。
前回の状態を保存し、新しい検出、影響範囲の変更、新たに見つかった未監視資産を数えます。
終了コード0でも、全資産を確認できたことや安全であることは示しません。
`out/findings.json` の `unverified` も読んでください。

通常の各走査では、`impact-items.json` に書いた影響の主張も再照合します。
証拠には出典、観測日時、収集者、確認範囲を残します。
根拠が足りない場合は未確認です。取得値が前回の値、または初回の期待値と異なる場合は変化として報告します。
その後も同じ値で期待値との矛盾が続く場合は未確認です。
主張のハッシュが変わると過去の承認は無効になります。
`report_build.py` は保存済みの結果から日次JSONレポート文書を作ります。
レポートの公開やWord文書の生成は行いません。

公開用のスナップショットには、コード、合成の設定例、合成の試験データを入れます。
個人の設定、在庫、レポート、開発履歴は含めません。
公開検査はパスと内容を確認しますが、あらゆる非公開情報を自動判別するものではありません。

## 必要なもの

- WindowsとPython 3.14。Pythonの外部パッケージは不要です。
- 在庫収集用のWindows PowerShell。版の取得にはインストール済みのコマンドを実行する場合があります。
- GitHubの勧告とリリースを確認するGitHub CLI（`gh`）。接続に必要な設定は別途行います。
- npm、Node.jsなど、調べるランタイムに対応するコマンド。
- 任意で、同梱Node.jsと信頼を外した証明書を調べる `patchwait`。`PATH` に置きます。
  現在の連携は、リポジトリ直下に利用者が用意する `g3.pem` を参照します。
  この証明書ファイルは公開物に含みません。用意するまでは連携を無効にしてください。
- 任意で、依存関係を調べるScanMux、Node.js、Git、ローカルのOSVデータベース。
- VPSの在庫収集はLinuxで動かします。[vps/README.md](vps/README.md)を参照してください。

通常の走査は勧告やリリースの取得で通信します。自己テストは固定応答を使い、通信を必要としません。
このリポジトリはWindows側の定期実行を登録しません。

## 設定する

取得したリポジトリでPowerShellを開き、設定例をコピーして合成値を自分の値に置き換えます。

```powershell
Copy-Item scan-config.example.json scan-config.json
Copy-Item coverage-map.example.json coverage-map.json
Copy-Item assets-manual.example.json assets-manual.json
Copy-Item local-config.example.json local-config.json
Copy-Item impact-items.example.json impact-items.json
Copy-Item watch-prompt.example.md x-watch-prompt.md
```

コピー先に必要な設定がある場合は上書きしないでください。
`local-config.json` は省略できます。使わない合成の上書き設定は取り除きます。
追跡する主張がなければ、`impact-items.json` は `{"items": []}` にします。
設定例の主張は書式を示すものです。利用者の端末についての検出結果ではありません。

`scan-config.json`・`coverage-map.json`・`assets-manual.json`・`x-watch-prompt.md` がなければ、それぞれに対応する同じフォルダの設定例を使います。
それ以外の独自の `--config` パスでは設定例へ切り替えません。
使った設定例ごとに標準エラー出力へ1行通知します。実ファイルが不正な場合は設定例へ切り替えません。
`--config PATH` で走査設定を選べます。その隣の `local-config.json` の `scan` 節を重ねます。
objectは再帰的に統合し、配列と単独値は置き換えます。
`python_roots` と `npm_lock_roots` の相対パスは作業フォルダを基準にします。
`coverage_map` と `vps_inventory_glob` の相対パスはスクリプトのフォルダを基準にします。
ScanMuxの `node`・`entry`・`config` とリポジトリには、ローカルの絶対パスを指定します。

設定例のリポジトリ、コマンド、`example.test` のURLは架空です。
書式の見本なので、そのままでは実際の監視に使えません。

### 走査設定

| キー | 意味 |
|---|---|
| `python_roots` | Python環境を探すフォルダ。 |
| `npm_lock_roots` | 対応するnpm lockfileを探すフォルダ。 |
| `exclude_path_parts` | 上記の探索でフォルダのパス全体と照合する、大文字小文字を区別しない部分文字列。`venv` は `myvenv` も除外します。 |
| `watch_releases` | 最新リリースを調べるGitHubの `owner/repo`。 |
| `tag_repos` | リリースの代わりにタグを調べるリポジトリ。 |
| `kev_keywords` | 明示的に指定するKEVキーワード。資産の製品名からも、一般語を除いて追加します。 |
| `patchtheplanet_url` | 告知を抽出するページ。空にするとこの検査を無効にします。 |
| `patchwait.enabled` | 任意のpatchwait連携を動かすか。 |
| `patchwait.node_roots`, `patchwait.node_excludes` | patchwaitへ渡す同梱Node.jsの探索先と除外先。 |
| `patchwait.roots_keystore` | 任意のJavaキーストアのパス。空なら指定を省きます。 |
| `patchwait.timeout_sec` | patchwaitの各コマンドの制限時間。 |
| `scanmux.enabled` | 任意のScanMux連携を動かすか。 |
| `scanmux.node`, `scanmux.entry`, `scanmux.config` | Node.js、ScanMuxの起動スクリプト、設定ファイルの絶対パス。 |
| `scanmux.repos`, `scanmux.timeout_sec` | 調べるリポジトリの絶対パスと、各コマンドの制限時間。 |
| `osv_batch_size` | OSVへまとめて問い合わせるパッケージ・版の組の数。 |
| `osv_detail_ttl_hours` | PyPI/npmのOSV詳細と、更新情報がない場合のディストリビューションのOSV詳細のキャッシュ有効時間。 |
| `coverage_map` | 対応表JSONのパス。 |
| `vps_hosts` | 在庫を受け付けるホスト名。収集側と合わせます。 |
| `vps_inventory_glob` | 受信したVPS在庫を探すパターン。 |
| `vps_inventory_filename` | 保存する在庫名と受信ファイルの整理に使う名前。 |
| `http_timeout_sec`, `user_agent` | HTTPの制限時間とUser-Agent。 |
| `runtime_advisories[].repo` | ランタイムの勧告を取得するGitHubリポジトリ。 |
| `runtime_advisories[].version_cmd` | インストール済みの版を取得するコマンドの引数配列。 |
| `advisory_fixed_overrides` | GHSAをキーにした修正版の `fixed` 配列。範囲を解析できない場合の補完です。`note` と `source` に根拠を書きます。 |

任意の走査キーとして、VPSの待受でプライベートとみなすネットワークの `vps_private_networks`、
対応表の追加規則の `coverage_extra_rules`、影響の照合でリリースとコード名を結ぶ `impact_release_codenames` もあります。
PCからVPSへログインしません。生成から13時間を超えたVPSのパッケージと待受の在庫は未確認にします。
影響の照合では、それより古い保存済みスナップショットを使う場合があり、収集日時を表示します。

### 対応表と手動資産

`coverage-map.json` は、次の規則を並べた配列です。

| キー | 意味 |
|---|---|
| `match` | 資産名に対する大文字小文字を区別しない正規表現。Dockerはイメージのリポジトリ名と比べます。 |
| `product` | 見張りリストに使う製品の表示名。 |
| `kinds` | 資産種別。`apps`、`services`、`listening`、`containers_vms`、`manual`、`python_envs`、`npm_global`、`npm_locks`、`runtimes`、`vps_packages`、`vps_listening`。 |
| `routes` | `type` と `ref` を持つ配列。種別は `osv`、`runtime_advisory`、`github_advisories`、`winget`、`release`、`kev`、`x_watch`、`manual`。 |
| `routes[].ref` | OSVはパッケージ名、GitHub系は `owner/repo`、ほかは製品名や確認手順の参照。 |
| `path_match` | 任意。サービスと待受の実行ファイルパスに対する正規表現。 |
| `publisher_match` | 任意。Appxの発行者CNに対する完全一致の正規表現。名前と発行者の両方を照合します。 |
| `advisory_sources` | 任意。勧告に使える版の収集元。`registry` と `appx` を指定でき、GitHubのアプリ勧告では既定がregistryです。 |
| `advisory_package` | 任意。GitHubのアプリ勧告と比較するパッケージ名の上書き。 |
| `note` | 規則の説明。 |

経路の登録だけでは、検査が成功したことを示しません。
サービスや待受をアプリの経路で確認するには、一致するアプリと今回の検査成功が必要です。
`winget` は更新があるかを返すだけで、その版に脆弱性があるかは判定しません。
`manual` と `x_watch` は、走査の外で確認を進めるための経路です。

`assets-manual.json` は `product`・`where`（場所）・`note` を持つobjectの配列です。
自動収集できない資産を追加します。
プロンプトには `{{PRODUCTS}}` を入れます。
走査は製品名を埋めた `out/x-watch-prompt.md` を作ります。AIエージェントの実行は行いません。
`xseen.py` は別に収集したX-watchのJSONLを既読一覧と照合し、既読にもできます。
`source_health.py` は保存済みの収集失敗を診断します。この2つは走査の設定例を読みません。

### 任意の連携設定

`local-config.json` の任意の節は `scan`・`scanmux`・`vps` です。
`scan` は上記の走査設定、`scanmux` はScanMuxへ渡す設定を上書きします。
`scanmux.config` で指定したJSONに、その隣の `local-config.json` の `scanmux` 節を統合し、導入済みのScanMuxへ渡します。
各キーの意味と設定要件は、その版のScanMuxの文書を参照してください。
`vps` 節の `inventory_filename` は在庫のファイル名、`taildrop_target` はPCのTaildrop送信先です。
収集側には、この節だけをコピーします。詳細はVPSの手順を参照してください。

## 実行する

```powershell
py -3.14 -I -B scan.py --scan-id example-scan
py -3.14 -I -B scan.py --cve CVE-2099-10001
py -3.14 -I -B report_build.py --scan-id example-scan --items impact-items.json --findings out/findings.json --base none --output out/daily-report.json
```

レポートには、結果を生成した走査と同じIDを指定します。
走査の `--scan-id` を省略するとIDを自動生成します。
`--base none` の代わりに前回の日次JSONを指定すると、ほかの節を引き継げます。
出力先のフォルダは事前に必要です。走査が完了すれば `out/` が作られます。
`scan.py --baseline` は通常の検出を既知として記録します。影響の変化は引き続き報告します。

| 終了コード | 通常の走査 | `--cve` |
|---|---|---|
| 0 | 完了した検査の範囲で新しい検出なし。 | 該当するローカルの版なし。未確認が残る場合があります。 |
| 10 | 新しい検出または影響の変化あり。 | 該当するローカルの版あり。 |
| 2 | 新しい検出がない場合の実行失敗または必須検査の失敗。新しい検出があれば10を優先します。 | 識別子の取得やコマンドの実行に失敗。 |

結果、キャッシュ、状態のファイルは手元に保管し、公開しないでください。
`report_build.py` はファイル・JSONのエラー、レポート構造の不正、走査IDの不一致で2を返します。
項目単位の検証問題は診断付きでレポートに表示し、0を返す場合があります。
VPS収集の設置と解除は[vps/](vps/README.md)にまとめています。

## 自己テスト

リポジトリ直下で実行します。実設定、実機の在庫、実際の投稿は使いません。
公開検査の自己テストは使い捨てのローカルGitリポジトリと、gitleaksの試験用代用品を作ります。
公開を止める仕組みの検査であり、本物の秘密検出器の性能試験ではありません。

```powershell
py -3.14 -I -B scan.py --selftest
py -3.14 -I -B scan.py --selftest-runtime
py -3.14 -I -B scan.py --selftest-ptp
py -3.14 -I -B scan.py --selftest-patchwait
py -3.14 -I -B scan.py --selftest-scanmux
py -3.14 -I -B scan.py --selftest-coverage
py -3.14 -I -B scan.py --selftest-xwatch
py -3.14 -I -B scan.py --selftest-vps
py -3.14 -I -B scan.py --selftest-impact
py -3.14 -I -B source_health.py --selftest
py -3.14 -I -B report_build.py --selftest
py -3.14 -I -B tools/publish_check.py selftest
```

## 公開前の検査

メンテナ向けの公開手順は [tools/README.md](tools/README.md) にあります。
`tools/publish-allowlist.txt` でスナップショットの対象を選びます。
内部パスの規則に該当するファイルは、一覧にあっても公開しません。
指定した非公開文字列、端末の利用者名、利用者フォルダのパス、IPアドレス、コミットの識別情報を検査します。
公開時はgitleaksも必要です。非公開文字列の一覧とguardは手元に置き、Git管理のファイルへ実値を書かないでください。

```powershell
py -3.14 -I -B tools/publish_check.py --markers markers.txt --guard guard.json all
```

`all` は既存のGit履歴を検査します。未ステージの編集や公開スナップショットの合格判定にはなりません。
`publish SOURCE` は選んだコミットの公開対象を検査し、pushせずに別の公開用refを作ります。
公開前にファイル一覧と内容を確認してください。自己テストを動かすだけなら、この公開用設定は不要です。

## ライセンス

[MIT](LICENSE)

## agent_secrets.py

Claudeの権限ルール、設定の `env` 値、MCPサーバー設定の文字列に保存された認証情報を、オフラインで検査します。
表示するのはパス、設定内の位置、種類、値の長さ、Gitの追跡・無視状態です。認証情報の値やハッシュは出力しません。
サーバー名・環境変数名・ヘッダー名は `mcpServers[0].headers[1]` のように索引で示し、辞書のキーから値が漏れることを防ぎます。
Python標準ライブラリとローカルのGitコマンドだけを使います。

```powershell
py -3.14 -I -B agent_secrets.py --root .
py -3.14 -I -B agent_secrets.py --file .claude/settings.local.json --json
py -3.14 -I -B agent_secrets.py --root . --history
py -3.14 -I -B agent_secrets.py --root . --exclude "archive*" --exclude "group/old-*" --history
py -3.14 -I -B agent_secrets.py --selftest
```

`--root` と `--file` は複数指定できます。探索先の既定値はありません。
各rootを深さ0として、深さ5までのディレクトリにある `.mcp.json` と
`.claude/settings.local.json`・`.claude/settings.json` を探します。
`node_modules`・`.git`・`.venv`・`venv`・`__pycache__` とディレクトリへのリンクは探索しません。
`--exclude GLOB` は複数指定でき、ディレクトリ名またはrootからの相対パスを `fnmatch` で照合します。
Windowsでは大文字・小文字を区別しません。パス指定の例では `/` を使います。
一致したディレクトリは読取り前に除外します。root自身やリポジトリも対象とし、一致するディレクトリ配下の履歴の検出結果も除外します。
探索中に除外したディレクトリの件数をパターン別に通知します。0件の場合も通知します。
`--file` は探索条件に関係なく指定ファイルを検査します。
JSONが不正なら行単位で検査し、検出結果に `unparsed` を付けます。読み取れない対象はエラーです。
読取り拒否や消失したディレクトリは、パス・失敗した処理・OSエラーの種類とerrnoを記録し、他のディレクトリの探索を続けます。
Gitエラーには失敗したコマンドと終了コードを含めます。Git状態が不明ならJSONでは `null`、テキストでは `unknown` と表示します。
使用できない `.git` をGitが `not a git repository` と判定した場合は、`skipped invalid git dir` の通知を出してスキップします。
所有者不一致（`dubious ownership`）など他のGit失敗はエラーのままです。Gitの所有者確認設定は変更しません。

`--history` は各リポジトリで対象パスに関わる最大200コミットについて、対象ファイル全体を現在ファイルと同じ構造化処理で調べます。
パス・位置・種類・長さが同じ検出はまとめ、検査した範囲の最古・最新コミットを `oldest_commit`・`newest_commit` に保持します。
それぞれのリモートブランチ包含判定は `oldest_remote`・`newest_remote` で示します。既存の `commit`・`remote` は最新の検出を示します。
各rootから深さ5までのリポジトリ（`.git` がファイルの場合も含む）を探索するため、複数リポジトリをまとめた通常フォルダも指定できます。
各リポジトリの履歴は深さを問わず対象名を検索し、削除済み・現在は無視対象のファイルも含めます。上限超過はリポジトリごとに通知します。
`--file` の履歴は、そのリポジトリが `--root` からも発見された場合を除き、指定ファイルだけを対象にします。
コミット識別子とリモートブランチへの包含判定は、ローカルにあるGit情報を使います。fetchは行いません。
JSON出力には `files_scanned`・`findings`・`errors`・`notices` が入ります。
終了コードは **0**＝検出なし、**10**＝検出あり、**2**＝引数・読取り・Gitエラーです。エラーを優先します。
変数参照とプレースホルダーは除外し、一般的な代入値は6文字以上を対象にします。
プロバイダー固有の形式も検出しますが、山括弧のプレースホルダー内と `op://` 参照内は除外します。
固定長のGitHubトークン形式は接頭辞の後に英数字36文字を必要とします。数字を含む大文字の値はプレースホルダー扱いしません。
空白なしの `curl -uuser:pass`、`Authorization: token`、`api-key` ヘッダーにも対応します。パターンによる検査のため、検出なしでも認証情報の不在を保証しません。
検査対象ファイルは変更しません。

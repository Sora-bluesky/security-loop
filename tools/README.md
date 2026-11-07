# 公開前の検査

開発履歴は非公開の `dev` に送ります。公開先の `origin` には別系列の
snapshot だけを送ります。URL は `.local/publish-guard.json` で区別します。
remote 名だけでは許可しません。登録のない URL への push は拒否します。
開発先と公開先の URL は、ローカルの `.local/publish-guard.json` に設定します。
remote の作成や変更は運用者が行います。

運用者が `git config core.hooksPath .githooks` を実行して導入します。
`--no-verify` や `core.hooksPath` の未設定で、クライアント側のフックは回避できます。
各フックは global の `core.hooksPath` にある同名フックを先に実行します。
その失敗時は止めます。`post-checkout`・`post-commit`・`post-merge` も引き継ぎます。
`pre-commit` は index と次の作者・コミッターを、`commit-msg` はメッセージを検査します。
`pre-push` は送信先 URL、送信先 ref 名、コミット全体、blob、作者・コミッターを検査します。
公開先は `refs/heads/main` と `refs/tags/v*` だけを許可し、ref の削除は拒否します。
タグは snapshot コミットを直接指す lightweight tag だけを許可します。
開発先でも送信先 ref 名の markers・ユーザー名・ユーザーパスを検査します。
開発先ではパスの allowlist を適用しません。公開先では全祖先の全 tree に適用します。
公開先の全祖先は、tree・任意の親1個・author・committer のヘッダーだけを持つ必要があります。
メッセージは `publish` が書く `Publish snapshot` と末尾改行だけに限ります。
開発 ref から到達できるコミットを含む公開 push は `dev-history rule` で拒否します。
開発 ref は `refs/heads/public` 以外の全ローカルブランチ、`refs/remotes/dev/*`、
設定した `local_only_refs` です。公開系列を別のローカルブランチに置くと拒否されます。
annotated tag、shallow 履歴、grafts による判定は対応せず拒否します。
replace ref は無視して元の履歴を検査します。

`.local/` は Git 管理外です。運用者が必須の `publish-markers.txt` と `publish-guard.json` を作ります。
欠落・不正なら検査は失敗します。実機値を文書やログへ写さないでください。

`publish-markers.txt` は1行に一つの非公開文字列を書きます。
大文字小文字は区別せず、空行と先頭が `#` のコメントは無視します。
`re:` から始めると Python 正規表現です。空ファイルは組込み検査だけを使う明示指定です。
合成例:

```text
# 公開しない値の合成例
private-host.example.test
re:internal-account-[0-9]+
```

公開時だけ禁止する文字列は、任意の `.local/publish-markers-public.txt` に同じ書式で指定します。
例えば、非公開の開発履歴では使える開発リポジトリ名を指定できます。以下は合成例です。

```text
# 公開時だけ禁止する値の合成例
example-private-development-repo
re:private-project-[0-9]+
```

`--public-markers PATH` で別のファイルを選べます。ファイルがなければ追加マーカーなしで続けます。
存在するファイルの読取失敗や不正な正規表現は公開検査を失敗させます。
共通の markers に加えて、`publish` と公開先への push の検査にだけ適用します。
公開側のパス・内容・コミット全体・送信先 ref 名が対象です。
開発側の `staged`・`message`・push・`all` には適用せず、公開専用ファイルも読みません。
非公開値はこれらのローカルファイルだけに置き、Git 管理に追加しないでください。

`publish-guard.json` は次の形式です。以下は合成例です。
`allowed_identities` は表示名とメールを含む完全一致で作者・コミッターの両方に適用します。
`local_only_refs` は完全な ref 名か glob、`internal_paths` は相対パスの glob です。
末尾 `/` はディレクトリ全体を表します。パスの `*` は1階層、`**` は任意の深さに一致します。
URL は表記も含む完全一致です。SSH や別表記を使う場合は運用者が明記します。

```json
{
  "dev_urls": ["https://example.test/team/loop-dev.git"],
  "public_urls": ["https://example.test/team/loop.git"],
  "internal_paths": ["private/**"],
  "allowed_identities": ["Example Publisher <publisher@example.test>"],
  "local_only_refs": ["refs/archive/*"]
}
```

検査対象は環境のユーザー名、Windows のユーザーフォルダー絶対パス、markers、
許可範囲外の IPv4 です。UTF-8・UTF-16LE・UTF-16BE の内容を検査します。
IPv4 は loopback・文書用・CGNAT・全アドレス待受を許可します。
IPv4 の形でも、`==`・`@` の直後か `version` キーの値は版番号として除外します。
`v` が直前に付いた4つの数値は、開発側では版番号、公開スナップショットではアドレスとして扱います。
`v1.2.3` は IPv4 の形ではありません。裸の `v` に続く4要素の IPv4 は検出します。
秘密情報は別に gitleaks が検査します。commit・push・snapshot 作成で必要で、
未導入なら拒否します。gitleaks のフック出力は `--redact` を指定します。
markers と allowlist も確認してください。全種類の個人情報を自動識別する検査ではありません。

公開する開発コミットを確定した後、運用者が次を実行します。

```sh
git fetch origin main
py -3.14 -I -B tools/publish_check.py publish HEAD
git diff --stat refs/remotes/origin/main refs/heads/public
git ls-tree -r --name-only refs/heads/public
git show --root --format=fuller refs/heads/public
git push origin refs/heads/public:refs/heads/main
```

初回の公開 push 前に `py -3.14 -I -B tools/publish_check.py all` を実行します。
初回は公開先をまだ作成していないため fetch と既存公開 tip との diff を省きます。
`publish` 自体は通信しません。対象 tree の allowlist 外・内部パスを除き、
一時 index と `git commit-tree` で snapshot を作ります。実 index は変えません。
親は `refs/remotes/origin/main` だけで、初回は親なしです。
作成前に公開 tip を最新にしてください。未送信の `public` は自動で上書きしません。
失敗時は ref を更新しません。成功しても push は運用者が別途行います。
取り消しは公開前に `public` の差分と ref を確認して行います。開発履歴は変更しません。
フックはこの作業ツリーのファイルを使います。公開ブランチの checkout は不要です。

`tools/publish-allowlist.txt` は保守的な完全パス一覧です。`.gitignore` も公開対象です。
allowlist はパスで判定します。内部文書の文章を許可済みファイルへ移すと、名前では検出できません。
その文章の検出は内容の markers に依存します。
公開 push 前に snapshot のファイル一覧と差分を確認してください。`publish` はファイル数を表示します。
`AGENTS.md`・運用記録・`docs/`・`.local/`・`state/`・`out/`・`local-config.json`・
`*.bak-*` は glob に一致しても公開しません。`fixtures-health/` と `x-watch-*` も除外します。
symlink と submodule の公開は拒否します。
実設定の `assets-manual.json`・`coverage-map.json`・`scan-config.json` は公開しません。
公開する `*.example.json` は合成値です。通常走査は実設定を優先し、欠落時だけ example を使います。
`scanmux-config.json` は相対パスと汎用設定だけなので公開対象です。
`fixtures/app.js`・`fixtures/index.html`・`fixtures-health/`・`fixtures-new/` は公開しません。
自己テストは `fixtures/public/` と既存の合成 `fixtures/patchwait/` を使います。
X-watch の公開テンプレートは `watch-prompt.example.md` です。
実際の `x-watch-prompt.md` が無いときだけ使用し、生成先は `out/x-watch-prompt.md` です。
使い方と自己テストの全コマンドは [README](../README.md) を参照してください。

検証コマンド:

```sh
py -3.14 -I -B tools/publish_check.py selftest
py -3.14 -I -B tools/publish_check.py --markers <検証用ファイル> --guard <検証用JSON> all
```

`all` は全 ref から到達できる開発履歴の内容・識別情報を検査します。
公開可能という判定ではありません。`staged` は全 index、`message FILE` はメッセージを検査します。
`range --url URL --remote-ref REF OLD NEW` は push 検査、`revs` は同じ対象の gitleaks 用引数を返します。
終了コードは0が合格、1が違反、2が設定・実行エラーです。検出した実値は表示しません。
Python はフックで3.14を優先し、なければ `python3`・`python` の順で探します。
自己テストは一時リポジトリとファイル URL の bare リポジトリだけを使います。
gitleaks はテスト用の代用品を使うため、実際の秘密検出性能の試験ではありません。

`local-config.example.json` の `scan`・`scanmux`・`vps` は利用者の設定用です。
配列と単独値は上書き、object は再帰的に重ねます。実機設定を Git に追加しません。

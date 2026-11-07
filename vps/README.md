# VPS の在庫を PC に送る

このフォルダーは Ubuntu 26.04 の `vps.example.test` に管理者がコピーして設置するためのものです。
PC から VPS へ接続せず、VPS が `sec-inventory.timer` で指定した時刻に
在庫を作り、`tailscale file cp` で設定した PC に送ります。PC 側の走査時刻は利用者が設定します。
ここにあるファイルを PC で実行する必要はありません。

## 前提

- VPS に Python 3、dpkg-query、ss、Docker、Tailscale があること。追加の Python パッケージは不要です。
- VPS と PC が同じ Tailscale ユーザーに属し、タグ付きノードでないこと。
- Tailscale 管理画面の **Send Files** が有効になっていること。
- PC の Tailscale が受信できる状態であること。受信先は `%USERPROFILE%/Downloads` です。
  同名時の動作には依存せず、`vps-inventory (1).json` のような名前も PC 側が拾います。

## 設置

`local-config.example.json` を参考に、PC の `local-config.json` に実際の
`scan.vps_hosts`・`scan.vps_inventory_glob`・`scan.vps_inventory_filename` と
`scan.vps_private_networks` を設定します。既存の受信名を使い続ける場合もここで指定します。
VPS 用には `vps` 節だけを含む次の形の JSON を作り、VPS 上の
`/var/lib/sec-inventory/local-config.json` に管理者だけが読める権限で保存します。
PC 用のパスや公開検査用の `.local/` は VPS にコピーしません。

```json
{"vps": {"inventory_filename": "vps-inventory.json", "taildrop_target": "pc.example.test:"}}
```

ファイル名は PC 側の `scan.vps_inventory_filename`・受信 glob と合わせ、
送信先は実際の Tailscale 名へ変更します。未設定の送信先では収集を開始しません。
VPS の設定パスは `SEC_INVENTORY_CONFIG` でも指定できます。

この `vps/` を VPS にコピーし、そのフォルダーに移動して次を実行します。

```bash
sudo install -d -m 0755 /usr/local/lib/sec-inventory
sudo install -m 0755 sec-inventory.py /usr/local/lib/sec-inventory/sec-inventory.py
sudo install -m 0644 sec-inventory.service /etc/systemd/system/sec-inventory.service
sudo install -m 0644 sec-inventory.timer /etc/systemd/system/sec-inventory.timer
sudo systemctl daemon-reload
sudo systemctl enable --now sec-inventory.timer
sudo systemctl start sec-inventory.service
sudo journalctl -u sec-inventory --no-pager -n 50
sudo systemctl list-timers sec-inventory.timer
sudo cat /var/lib/sec-inventory/send-status.json
```

`send-status.json` の `exit_code` が0なら送信成功です。送信失敗時はサービスも失敗します。
収集の一部が失敗しても在庫の `errors`（コンテナの場合は各コンテナの `errors`）に記録して送ります。
Docker の環境変数や認証情報は収集しません。コンテナ内は `docker exec <id> cat <path>` だけで読みます。

`security_facts` には `/proc/stat` の `btime` から得た UTC 起動日時 `boot.booted_at`（末尾 `Z`）、
取得できた場合の `boot.boot_id`、`nft list tables` の表一覧 `nft_tables`（各要素は `family`・`name`）を保存します。
収集失敗は `security_facts.errors` の `boot`・`nft_tables` に記録し、失敗した項目は省略します。
boot_id だけ取得できない場合は起動日時を残し、空の表一覧 `[]` は nft の実行に成功して表が無かった場合だけ保存します。
更新時は管理者が新しい `sec-inventory.py` を VPS の `/usr/local/lib/sec-inventory/sec-inventory.py` へコピーしてください。

`sec-inventory.service` は `TimeoutStartSec=300` で、収集と送信が 300 秒を超えたら systemd が止めます。
その回の在庫は届かず、照合が VPS を「確認できなかった」に数えます。
`.service` を更新したら、VPS へコピーして `systemctl daemon-reload` を実行してください。

在庫は `/var/lib/sec-inventory/vps-inventory.json` に一時ファイルから置き換えて保存します。
root で動作し、Docker/Tailscale の既存ソケットを使います。サービスの保護設定はローカルの書込先を
在庫ディレクトリに限定しますが、Docker ソケットへのアクセスは root 相当です。

PC の `scan.py` は `scan-config.json` に `local-config.json` の `scan` 節を重ねた `vps_inventory_glob` で最新の受信ファイルを探し、
検証後 `state/vps/vps-inventory.json` に保存します。最新の受信ファイルが不正なら移動せず、
既存の保存分を使います。保存分が無い・不正・生成から13時間超の場合は確認不能とし、OSV に流しません。
古い同一ホストの有効な受信在庫だけを削除し、他のホストや不正な JSON は残します。
OS パッケージの source/origin を照合し、Linux カーネルの版・コンテナイメージの情報は在庫として残します。
これはイメージ全体の SBOM 走査ではありません。

## 解除

VPS で以下を実行すると定時送信を止め、設置したファイルを削除できます。

```bash
sudo systemctl disable --now sec-inventory.timer
sudo systemctl stop sec-inventory.service
sudo systemctl reset-failed sec-inventory.service
sudo rm -f /etc/systemd/system/sec-inventory.timer /etc/systemd/system/sec-inventory.service
sudo rm -f /usr/local/lib/sec-inventory/sec-inventory.py
sudo rmdir /usr/local/lib/sec-inventory
sudo systemctl daemon-reload
```

VPS の `/var/lib/sec-inventory/` と PC の保存分・受信分は残します。
在庫も消したい場合は中身を確認してから別途削除してください。PC 側の機能を戻す場合は、この変更の
`scan.py` と `scan-config.json` を戻します（送信停止後は13時間を超えると確認不能として表示されます）。

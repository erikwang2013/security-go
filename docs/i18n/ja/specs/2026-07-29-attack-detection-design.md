# Attack Detection Package — Design Spec

## 概要

純粋な Go 攻撃検出ライブラリ。統一インターフェース + レジストリパターンを提供し、6 大カテゴリ 36 個の検出器をカバーします。**実装完了 (2026-07-29)。`session` パッケージは 2026-09-15 に追加。**

## パッケージ構造

```
security-go/
├── go.mod
├── security.go              # Result, Severity, Detector interface, Engine
├── all/all.go               # RegisterAll — 注册所有内置 detector
├── injection/               # 注入类攻击 (10)
├── protocol/                # 协议与请求攻击 (9)
├── httpval/                 # HTTP 协议层校验 (7)
├── data/                    # 数据与序列化攻击 (5)
├── file/                    # 文件与敏感数据 (3)
├── session/                 # 会话安全 (2) — 不经过 Engine
│   ├── store.go             # Store interface + MemoryStore
│   ├── tracker.go           # Tracker — 客户端被劫持 / 异地登录
│   ├── lockout.go           # 失败计数、锁定查找与键
│   ├── bruteforce.go        # 渐进退避 / 撞库检测 / GuardLogin
│   └── tamper.go            # Signer — 篡改数据
└── storage/                 # 可插拔存储后端
    ├── storage.go           # Backend interface
    ├── memory.go            # 内存实现 (带 TTL 清理)
    ├── file.go              # JSON 文件持久化
    └── redis/               # Redis 子模块 (可选依赖)
```

## コア API

完全な API インターフェース（`Result`、`Detector`、`Engine`、ストレージバックエンド `Backend`、HTTP バリデータ）については独立ドキュメントを参照してください：**[API インターフェースドキュメント](../api.md)**

- すべての検出器はプリコンパイル済みの正規表現パターンを使用します

## 検出器

| カテゴリ | 名前 | 主要パターン |
|----------|------|-------------|
| injection | xss | `<script>`, `on[a-z]+=`, `javascript:`, SVG/CSS vectors |
| injection | sql | UNION SELECT, `/**/`, sleep/benchmark, boolean blind, schema enum |
| injection | command | backtick, `$()`, pipe, `/dev/tcp`, PHP exec functions |
| injection | nosql | MongoDB `$ne`/`$gt`/`$regex`/`$where`, auth bypass |
| injection | ldap | filter operators `(`, `)`, `&`, `|`, `*` |
| injection | xpath | boolean bypass `1=1`, `' or '1'='1` |
| injection | jndi | `${jndi:ldap://`, `${lower:j}`, `${env:}` |
| injection | ssi | `<!--#exec`, `<!--#include`, `<!--#echo` |
| injection | graphql | `__schema`, `__type`, deep nested query, mutation detect |
| injection | ssti | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO |
| protocol | ssrf | internal IP, 169.254.169.254, IPv6 loopback, gopher/dict |
| protocol | xxe | `<!ENTITY`, parameter entities, DOCTYPE |
| protocol | header_injection | CRLF `%0d%0a`, Set-Cookie/Location injection |
| protocol | host_header | CRLF Host injection, X-Forwarded-Host poisoning |
| protocol | request_smuggling | TE/CL mismatch, dual TE, folded header |
| protocol | open_redirect | `//evil.com`, `javascript:`, `data:` |
| protocol | cors | Origin: null, ACA* header injection |
| protocol | websocket | Upgrade injection, null Origin, ws:// |
| protocol | dns_rebinding | Host header internal IP, localhost, hostname without TLD |
| httpval | method | Whitelist GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH → 405 |
| httpval | body_size | Max size check → 413 (default 10MB) |
| httpval | content_type | MIME whitelist → 415 |
| httpval | csrf_origin | Cross-origin Origin vs Host match |
| httpval | ip_blacklist | Window-based rate limit → auto ban (5/60s → 15min) |
| httpval | nested_depth | JSON body bomb: nesting depth / element count exceeded (streamed; non-JSON never matches) |
| httpval | cookie_attrs | Set-Cookie missing Secure/HttpOnly/SameSite, overlong or empty value |
| data | deserialization | PHP `O:数字:`, `C:数字:`, unserialize() |
| data | csv_injection | `=`, `@`, `+`, `-` formula prefix |
| data | mail_header | Bcc/Cc/From/To injection, MIME |
| data | jwt_attack | alg:none, kid path traversal, empty signature |
| data | prototype_pollution | `__proto__`, `constructor`, `__defineGetter__` |
| file | path_traversal | `../`, `..\\`, php://filter, null byte |
| file | upload | Extension whitelist + PHP tag content scan |
| file | data_leak | Credit card, AWS key, private key, connection string, JWT secret |
| session | session_guard | token↔client binding: UA/fingerprint change (client hijack), IP subnet/country change (remote login), login-network history; brute-force lockout with progressive backoff and per-IP credential-stuffing detection |
| session | data_tamper | HMAC-SHA256 over canonical params, ±5m timestamp window, nonce replay counter |

## 対象外 (Non-Goals)

- HTTP ミドルウェアは提供しない（純粋な検出ライブラリ） — 唯一の例外は `session.Tracker.Guard` で、`Check` が検出したときに 401 を返す薄いラッパーです
- リアルタイムのリクエスト傍受はしない（検出は呼び出し側が実行）
- 攻撃のブロックはしない（検出のみ。ip_blacklist がブロック機能を提供）

## 実装状況 (2026-07-29)

- **32 個の検出器をすべて実装** — 登録エントリポイント `all.RegisterAll(engine)`
- **テストカバレッジ** — 7/8 パッケージにテストあり（`all` パッケージは未対応）、httpval には 32 個のテストを追加済み
- **コードレビュー完了** — 3 個のバグを修正（レビュー報告参照）、`go vet` 警告ゼロ
- **既知の制限** — `storage/redis/` サブモジュールには `go mod tidy` が必要。protocol パッケージの receiver スタイルは統一待ち
- **レポート** — [`../reports/2026-07-29-code-review-report.md`](../reports/2026-07-29-code-review-report.md)

## 追加事項 — session パッケージ (2026-09-15)

セッションセキュリティを第 6 カテゴリとして追加しました。設計上の制約は上記と同じです：

- **`session.Tracker`** (`session_guard`) — `Issue` が token → IP サブネット / UA / デバイスフィンガープリントをバインド；`Check` がリクエストごとに比較し、`client_hijack`（UA またはフィンガープリントの変化、Critical）または `remote_login`（クロスカントリー Critical / 別サブネット High）を検出；`Guard` は検出時に 401 を返す；`Observe` はログイン時にそのユーザーの過去のサブネットと比較；`Revoke` で即座に無効化。
- **`session.Signer`** (`data_tamper`) — パラメータに HMAC-SHA256 署名 `<タイムスタンプ>.<nonce>.<署名>` を行い、検証順序はタイムスタンプ → 署名 → nonce カウンターであるため、偽造署名が正当な nonce を消費することはできません。リプレイカウンターは `storage.Backend` を再利用。
- **ブルートフォース対策** — `RecordFailure(identity, r)` がログイン失敗を計上し、しきい値でロック、以降 1 回ごとに倍増して `MaxLockout`（既定 24 時間）まで。`CheckLogin` はさらにクライアント IP ごとに失敗した異なる識別子を数え、`StuffingLimit`（既定 10）で `credential_stuffing` を報告。`GuardLogin` は認証エンドポイント用ミドルウェアで、429 と `Retry-After` を返します。漸進的バックオフは、任意のアカウントをロックすること自体が DoS 手段にならないようにするためです。
- **ストレージ** — セッション構造はカウント/ブロックのみをサポートする `storage.Backend` では表現できないため、`session.Store`（`Save` / `Load` / `Delete`）+ `MemoryStore` を追加；`storage.Backend` とその 3 つの実装は変更なし。
- **`Engine` には登録しない** — `Detector.Detect(input string)` では token / クライアント IP / UA を取得できないため、`Tracker` は `*http.Request` を直接受け取ります；`all.RegisterAll` はゼロ設定検出器のみを登録する動作を維持。
- **テスト** — `session` パッケージには 5 つのテストファイル（store / tracker / tamper / lockout / bruteforce）、`go test ./... -race` 通過。

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

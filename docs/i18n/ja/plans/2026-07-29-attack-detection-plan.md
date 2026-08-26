# Attack Detection Package — Implementation Plan

> **エージェントワーカー向け:** 必須サブスキル: この計画をタスク単位で実装するには、superpowers:subagent-driven-development（推奨）または superpowers:executing-plans を使用してください。

**目標:** 5 カテゴリ 32 個の検出器、3 種類のプラグ可能なストレージバックエンド、統一 Engine レジストリを備えた純粋な Go 攻撃検出ライブラリを構築する。**状態: 完了 (2026-07-29)。**

**アーキテクチャ:** フラットなインターフェース設計 — すべての検出器が `Detector`（Name + Detect）を実装します。プリコンパイル済みの正規表現パターン。Engine はレジストリ、名前による検索、および完全な HTTP リクエストスキャンのための `DetectRequest` を提供します。RegisterAll は `all/all.go`（独立パッケージ）にあります。

**技術スタック:** Go 1.21+、標準ライブラリ `regexp` + `net/http`、Redis バックエンド用 `go-redis`（`storage/redis/` のオプションサブモジュール）。

---

### タスク 1: Go モジュールとコア型の初期化

**ファイル:**
- 作成: `go.mod`
- 作成: `security.go`

- [x] **ステップ 1: Go モジュールの初期化**

```bash
cd /home/wwwroot/bag/security-go && go mod init github.com/erikwang2013/security-go
```

- [x] **ステップ 2: security.go の作成 — Result、Severity、Detector インターフェース、Engine**

```go
package security

import "net/http"

type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

type Result struct {
	Name     string
	Detected bool
	Message  string
	Severity Severity
	Details  map[string]interface{}
}

type Detector interface {
	Name() string
	Detect(input string) *Result
}

type Engine struct {
	detectors map[string]Detector
}

func NewEngine() *Engine {
	return &Engine{detectors: make(map[string]Detector)}
}

func (e *Engine) Register(d Detector) {
	e.detectors[d.Name()] = d
}

func (e *Engine) Detect(name, input string) *Result {
	if d, ok := e.detectors[name]; ok {
		return d.Detect(input)
	}
	return nil
}

func (e *Engine) DetectAll(input string) []*Result {
	var results []*Result
	for _, d := range e.detectors {
		if r := d.Detect(input); r != nil && r.Detected {
			results = append(results, r)
		}
	}
	return results
}

func (e *Engine) DetectRequest(r *http.Request) []*Result {
	var results []*Result
	inputs := collectRequestInputs(r)
	for _, input := range inputs {
		results = append(results, e.DetectAll(input)...)
	}
	return results
}

func collectRequestInputs(r *http.Request) []string {
	var inputs []string
	inputs = append(inputs, r.URL.String())
	inputs = append(inputs, r.URL.Query().Encode())
	for key, vals := range r.Header {
		for _, v := range vals {
			inputs = append(inputs, key+": "+v)
		}
	}
	for _, c := range r.Cookies() {
		inputs = append(inputs, c.Name+"="+c.Value)
	}
	return inputs
}
```

- [x] **ステップ 3: ビルド** — `go build ./...`
- [x] **ステップ 4: コミット** — `feat: initialize Go module with core types and Engine`

---

### タスク 2: ストレージバックエンドインターフェースと Memory

**ファイル:**
- 作成: `storage/storage.go`
- 作成: `storage/memory.go`

- [x] **ステップ 1: storage/storage.go** — Backend インターフェース（Incr、Get、Block、IsBlocked、Close）
- [x] **ステップ 2: storage/memory.go** — TTL reap goroutine を備えた sync.Map ベースの実装
- [x] **ステップ 3: ビルド** — `go build ./storage/...`
- [x] **ステップ 4: コミット** — `feat: add storage interface and memory backend`

---

### タスク 3: File と Redis ストレージ

**ファイル:**
- 作成: `storage/file.go`
- 作成: `storage/redis.go`
- 変更: `go.mod`（go-redis 依存を追加）

- [x] **ステップ 1: storage/file.go** — 遅延 flush 付き JSON ファイル永続化
- [x] **ステップ 2: storage/redis.go** — go-redis/v9 を使用した Redis バックエンド
- [x] **ステップ 3: ビルド** — `go build ./storage/...`
- [x] **ステップ 4: コミット** — `feat: add file and redis storage backends`

---

### タスク 4: インジェクション検出器 — XSS、SQL

**ファイル:**
- 作成: `injection/xss.go`
- 作成: `injection/sql.go`

- [x] **ステップ 1: injection/xss.go** — `<script>`、`on[a-z]+=`、`javascript:`、SVG/CSS パターン
- [x] **ステップ 2: injection/sql.go** — UNION SELECT（`/**/` バイパス付き）、sleep/benchmark、ブール盲注、schema 列挙、ストアドプロシージャ
- [x] **ステップ 3: ビルド** — `go build ./injection/...`
- [x] **ステップ 4: コミット** — `feat: add XSS and SQL injection detectors`

---

### タスク 5: インジェクション検出器 — Command、NoSQL、LDAP、XPATH

**ファイル:**
- 作成: `injection/command.go`
- 作成: `injection/nosql.go`
- 作成: `injection/ldap.go`
- 作成: `injection/xpath.go`

- [x] **ステップ 1: injection/command.go** — バッククォート、`$()`、パイプ、`/dev/tcp`、PHP exec 関数
- [x] **ステップ 2: injection/nosql.go** — MongoDB `$ne`/`$gt`/`$regex`/`$where`、認証バイパス
- [x] **ステップ 3: injection/ldap.go** — フィルタ演算子 `(`, `)`, `&`, `|`, `*`
- [x] **ステップ 4: injection/xpath.go** — ブールバイパス、string-length、count
- [x] **ステップ 5: ビルド & コミット**

---

### タスク 6: インジェクション検出器 — JNDI、SSI、GraphQL、SSTI

**ファイル:**
- 作成: `injection/jndi.go`
- 作成: `injection/ssi.go`
- 作成: `injection/graphql.go`
- 作成: `injection/ssti.go`

- [x] **ステップ 1: injection/jndi.go** — `${jndi:ldap://`、`${lower:j}`、`${env:}`、rmi/dns プロトコル
- [x] **ステップ 2: injection/ssi.go** — `<!--#exec`、`<!--#include`、`<!--#echo`
- [x] **ステップ 3: injection/graphql.go** — `__schema`、`__type`、深いネストクエリ、mutation
- [x] **ステップ 4: injection/ssti.go** — Jinja2 `{{}}`、FreeMarker `${}`、ERB `<% %>`、Python MRO
- [x] **ステップ 5: ビルド & コミット**

---

### タスク 7: プロトコル検出器 — SSRF、XXE、ヘッダーインジェクション

**ファイル:**
- 作成: `protocol/ssrf.go`
- 作成: `protocol/xxe.go`
- 作成: `protocol/header_injection.go`

- [x] **ステップ 1: protocol/ssrf.go** — 内部 IP、169.254.169.254、IPv6 loopback、gopher/dict
- [x] **ステップ 2: protocol/xxe.go** — `<!ENTITY SYSTEM/PUBLIC`、パラメータエンティティ、DOCTYPE
- [x] **ステップ 3: protocol/header_injection.go** — CRLF、Set-Cookie/Location インジェクション
- [x] **ステップ 4: ビルド & コミット**

---

### タスク 8: プロトコル検出器 — Host Header、Request Smuggling、Open Redirect、CORS、WebSocket、DNS Rebinding

**ファイル:**
- 作成: `protocol/host_header.go`
- 作成: `protocol/request_smuggling.go`
- 作成: `protocol/open_redirect.go`
- 作成: `protocol/cors.go`
- 作成: `protocol/websocket.go`
- 作成: `protocol/dns_rebinding.go`

- [x] **ステップ 1: プロトコル検出器 6 つすべて** — 各ファイル 1 個、プリコンパイル済みの正規表現パターン
- [x] **ステップ 2: ビルド & コミット**

---

### タスク 9: HTTP バリデーション検出器

**ファイル:**
- 作成: `httpval/method.go`
- 作成: `httpval/body_size.go`
- 作成: `httpval/content_type.go`
- 作成: `httpval/csrf_origin.go`
- 作成: `httpval/ip_blacklist.go`

- [x] **ステップ 1: httpval/method.go** — GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH のホワイトリスト
- [x] **ステップ 2: httpval/body_size.go** — 最大サイズチェック、デフォルト 10MB
- [x] **ステップ 3: httpval/content_type.go** — MIME ホワイトリスト
- [x] **ステップ 4: httpval/csrf_origin.go** — クロスオリジンの Origin と Host の一致チェック
- [x] **ステップ 5: httpval/ip_blacklist.go** — ウィンドウレート制限（5/60s → 15 分ブロック）、storage.Backend を使用
- [x] **ステップ 6: ビルド & コミット**

---

### タスク 10: データ/シリアライズ検出器

**ファイル:**
- 作成: `data/deserialization.go`
- 作成: `data/csv_injection.go`
- 作成: `data/mail_header.go`
- 作成: `data/jwt_attack.go`
- 作成: `data/prototype_pollution.go`

- [x] **ステップ 1: data/deserialization.go** — PHP `O:数字:`、`C:数字:`、unserialize()、マジックメソッド
- [x] **ステップ 2: data/csv_injection.go** — `=cmd|`、`@SUM(`、`+`、`-` 数式プレフィックス
- [x] **ステップ 3: data/mail_header.go** — Bcc/Cc/From/To インジェクション、MIME multipart
- [x] **ステップ 4: data/jwt_attack.go** — alg:none、kid パストラバーサル、空シグネチャ（構造デコード）
- [x] **ステップ 5: data/prototype_pollution.go** — `__proto__`、`constructor`、`__defineGetter__/Setter__`
- [x] **ステップ 6: ビルド & コミット**

---

### タスク 11: ファイル・機密データ検出器

**ファイル:**
- 作成: `file/path_traversal.go`
- 作成: `file/upload.go`
- 作成: `file/data_leak.go`

- [x] **ステップ 1: file/path_traversal.go** — `../`、`..\\`、php://filter、null バイト、URL エンコードバイパス
- [x] **ステップ 2: file/upload.go** — 拡張子ホワイトリスト + PHP タグ内容スキャン
- [x] **ステップ 3: file/data_leak.go** — クレジットカード、AWS キー、秘密鍵、DB 接続文字列、API トークン、JWT シークレット
- [x] **ステップ 4: ビルド & コミット**

---

### タスク 12: Engine 統合 — RegisterAll

**ファイル:**
- 変更: `security.go`

- [x] **ステップ 1: RegisterAll() を追加** — 組み込み検出器 32 個すべてを登録
- [x] **ステップ 2: ビルド** — `go build ./...`
- [x] **ステップ 3: コミット** — `feat: add RegisterAll for built-in detectors`

---

### タスク 13: テスト

**ファイル:**
- 作成: `security_test.go`
- 作成: `injection/xss_test.go`, `sql_test.go`, `jndi_test.go`, `ssti_test.go`
- 作成: `protocol/ssrf_test.go`
- 作成: `file/path_traversal_test.go`, `data_leak_test.go`
- 作成: `data/jwt_attack_test.go`
- 作成: `storage/memory_test.go`

- [x] **ステップ 1: テストを作成** — それぞれ正例と負例のテストケースを含む
- [x] **ステップ 2: 実行** — `go test ./... -v`
- [x] **ステップ 3: コミット** — `test: add core engine and detector tests`

---

### タスク 14: 実装後のコードレビューと修正 (2026-07-29)

- [x] **全面的なコードレビュー** — Go ソースファイル 42 個、8 パッケージ
- [x] **バグ修正 #1** — `storage/file.go`: JSON シリアライズエラーが黙って無視されていた → エラーを検査して返すよう修正
- [x] **バグ修正 #2** — `httpval/content_type.go`: 空の AllowList がすべての Content-Type を許可していた → deny-all をデフォルトに変更
- [x] **バグ修正 #3** — `protocol/xxe.go`: `&[a-z]+;` が正当な HTML エンティティを誤検出 → 既知の悪意あるプロトコルリストに絞り込み
- [x] **httpval テストを追加** — 32 個のテストケース、5 個の検出器をカバー（BodySize、ContentType、CSRFOrigin、IPBlacklist、Method）
- [x] **全量テスト** — `go test -count=1 ./...` 7/7 パッケージ通過、`go vet` 警告ゼロ

---

## 実際の実装と計画の乖離

| 計画 | 実際 | 理由 |
|------|------|------|
| RegisterAll を `security.go` に配置 | `all/all.go` の独立パッケージ | 循環参照の回避。httpval は storage に依存するが、他の検出器は依存しない |
| Redis をルート go.mod に配置 | `storage/redis/` サブモジュール | オプション依存の分離 |
| Receiver を統一してポインタに | protocol パッケージは値レシーバを使用 | ✅ v2 レビューで全件ポインタレシーバに変更済み |
| タスク 4-12 をビルド & コミットで段階的に | 段階的なコミットなし | すべてのコードを一括で実装 |

## テストカバレッジサマリー

| パッケージ | テストファイル | テスト数 |
|----|---------|--------|
| security | security_test.go | 5 |
| data | deserialization_test.go, csv_injection_test.go, mail_header_test.go, jwt_attack_test.go, prototype_pollution_test.go | 8 |
| file | path_traversal_test.go, data_leak_test.go, upload_test.go | 5 |
| httpval | httpval_test.go | 32 |
| injection | xss_test.go, sql_test.go, command_test.go, nosql_test.go, ldap_test.go, xpath_test.go, jndi_test.go, ssi_test.go, graphql_test.go, ssti_test.go | 10 |
| protocol | ssrf_test.go, xxe_test.go, header_injection_test.go, host_header_test.go, request_smuggling_test.go, open_redirect_test.go, cors_test.go, websocket_test.go, dns_rebinding_test.go | 9 |
| storage | memory_test.go | 4 |
| all | (なし) | 0 |

> 完全なレポートは [`../reports/2026-07-29-code-review-report-v2.md`](../reports/2026-07-29-code-review-report-v2.md) を参照

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

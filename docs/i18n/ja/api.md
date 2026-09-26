# Security Go — API インターフェースドキュメント

このドキュメントは `security-go` の公開 API をすべてまとめたものです：コア型、`Detector` インターフェース、`Engine` レジストリ、ストレージバックエンドインターフェース、HTTP バリデータのコンストラクタ。

## コア型

### Result

各検出器が返す検出結果の構造体：

```go
type Result struct {
    Name     string                 // 検出器の名前
    Detected bool                   // 攻撃を検出したかどうか
    Message  string                 // 結果の説明
    Severity Severity               // 深刻度
    Details  map[string]interface{} // 追加の詳細
}
```

### Severity

深刻度レベル：

```go
type Severity int

const (
    SeverityLow      Severity = iota // 低リスク
    SeverityMedium                   // 中リスク
    SeverityHigh                     // 高リスク
    SeverityCritical                 // 重大
)
```

## Detector インターフェース

すべての検出器はこのインターフェースを実装する必要があります：

```go
type Detector interface {
    Name() string                // 検出器の一意な名前
    Detect(input string) *Result // 入力に対して検出を実行し結果を返す
}
```

## Engine レジストリ

`Engine` は統合エントリポイントであり、名前によって検出器を登録・管理します：

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // 空の Engine を作成
func (e *Engine) Register(d Detector)             // 検出器を登録
func (e *Engine) Detect(name, input string) *Result // 名前で単一の入力を検出
func (e *Engine) DetectAll(input string) []*Result  // 全件検出（Detected=true のみ返す）
func (e *Engine) DetectRequest(r *http.Request) []*Result // HTTP リクエスト全体を検出
```

`DetectRequest` はリクエストの URL、Query、Headers、Cookies を自動的に収集して入力とします。 各入力は URL デコード後にも再スキャンされるため、`%3Cscript%3E` のようなエンコード済みペイロードで検出を回避できません。

## 登録エントリポイント

```go
// all パッケージは設定不要の検出器を一括登録します（27 個）
all.RegisterAll(engine)
```

## 補助関数

```go
// FirstMatch は input に最初に一致したパターン文字列を返す。すべて不一致なら ("", false) を返す
func FirstMatch(input string, patterns []*regexp.Regexp) (string, bool)
```

カスタム検出器が組み込みのプリコンパイル済みパターンを再利用でき、正規表現の再コンパイルを避けられます。

## ストレージバックエンドインターフェース

`httpval.IPBlacklist` はこのインターフェースを通じてプラグ可能なストレージを使用します：

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // ウィンドウ内のカウントを +1
    Get(key string) (int, error)                          // カウントを読み取る
    Block(key string, duration time.Duration) error       // 指定した期間ブロック
    IsBlocked(key string) (bool, error)                   // すでにブロック済みかどうか
    Close() error                                         // 閉じてリソースを解放
}
```

実装：

| バックエンド | 説明 |
|------|------|
| `storage.NewMemory() *Memory` | メモリ実装、`sync.Mutex` + map、30 秒ごとに期限切れエントリを自動クリーンアップ |
| `storage.NewFile(path) (*File, error)` | JSON ファイル永続化、30 秒ごとに自動保存 + Close 時に flush |
| `redis.New(addr, password string, db int) *Backend` | Redis サブモジュール、Pipeline Incr + TTL、`go-redis/v9` が必要 |

## HTTP バリデータ

```go
// HTTP メソッドのホワイトリスト検証
e.Register(&httpval.Method{})

// リクエストボディサイズ制限（既定 10MB）
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type ホワイトリスト（空リスト = すべて拒否）
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF Origin 検証（クロスオリジン要求は Origin と Host の一致を確認）
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP ブラックリスト（ウィンドウ内 N 回の攻撃で自動ブロック、既定 5 回/60 秒 → 15 分ブロック）
bl := httpval.NewIPBlacklist(mem) // mem は任意の storage.Backend 実装
e.Register(bl)
blocked, _ := bl.RecordAttack(clientIP)
```

### JSON ネスト深度と Cookie 属性

| コンストラクタ | 説明 |
|--------|------|
| `NewNestedDepth(maxDepth, maxKeys) *NestedDepth` | JSON ボディをストリーム走査し、ネスト深度（既定 32）または要素数が上限を超えると `nested_depth` を報告。不正・切り詰められた JSON は決して一致しません |
| `NewCookieAttrs(requireSecure, requireHttpOnly, requireSameSite) *CookieAttrs` | 1 つの `Set-Cookie` を検証: 属性の欠落、値の超過長（`MaxValueLen`）、空値（`RequireNonEmpty`） |

## セッションセキュリティ

`session` パッケージは**クライアントハイジャック**、**データ改ざん**、**遠隔地ログイン**を検出します。完全な `*http.Request`（token、クライアント IP、User-Agent）と、アプリ側で用意するストレージおよび鍵が必要なため、`Engine` には登録せず、ミドルウェア／関数として直接呼び出します。

### Store インターフェース

セッションのバインドは `storage.Backend`（カウントとブロックのみ）では表現できないため、`session` は独自の小さなインターフェースを持ちます：

```go
type Store interface {
    Save(key string, value []byte, ttl time.Duration) error
    Load(key string) ([]byte, error)   // 存在しないか期限切れなら (nil, nil) を返す
    Delete(key string) error
}

session.NewMemoryStore() *MemoryStore // メモリ実装、30 秒ごとに期限切れエントリを削除、Close で削除停止
```

### Session

```go
type Session struct {
    IP          string    `json:"ip"`           // セッション確立時のクライアント IP
    UserAgent   string    `json:"ua,omitempty"`
    Fingerprint string    `json:"fp,omitempty"` // デバイスフィンガープリント（X-Device-Fingerprint ヘッダー）
    Country     string    `json:"country,omitempty"`
    IssuedAt    time.Time `json:"issued_at"`
    LastSeen    time.Time `json:"last_seen"`    // 各 Check でスライディング更新
}
```

### Tracker

検出器名は `session_guard`（`Tracker.Name()` を参照）。

```go
type Tracker struct {
    Store             Store
    TTL               time.Duration              // セッションのライフサイクル、既定 30m、各 Check でスライディング更新
    SubnetBits        int                        // 同一拠点判定プレフィックス、既定 24（IPv6 は自動で +24）
    CountryOf         func(ip string) string     // 省略可能な GeoIP フック。nil の場合は国判定をスキップ
    KnownNets         int                        // Observe がユーザーごとに保持するログインサブネット数、既定 8
    KnownNetTTL       time.Duration              // ログインサブネットの保持期間、既定 90 日
    TokenSource       func(*http.Request) string // 既定 DefaultTokenSource
    TrustProxyHeaders bool                       // 既定 false
    FailClosed        bool                       // 既定 false
    Failures          int                        // ウィンドウ内で token をロックする失敗回数のしきい値、既定 5
    FailureWindow     time.Duration              // 失敗カウントの保持期間、超過分は数えない、既定 5m
    Lockout           time.Duration              // しきい値に初めて達したときのロック期間、毎回倍増、既定 15m
    MaxLockout        time.Duration              // ロックごとの倍増の上限、既定 24h
    BackoffWindow     time.Duration              // エスカレーションカウントの保持期間、既定 24h
    StuffingLimit     int                        // 同一 IP で失敗を許す異なる識別子数の上限、既定 10
}
```

| メソッド | 説明 |
|------|------|
| `NewTracker(store) *Tracker` | 作成しデフォルト値を設定 |
| `Issue(token, r) error` | ログイン成功後に token → IP サブネット / UA / フィンガープリントをバインド；空の token はエラーを返す |
| `Check(r) *Result` | リクエストごとに検証し、検出時は `Detected: true` を返す；通過時はスライディングで延長 |
| `Observe(user, r) *Result` | ログイン時にそのユーザーの過去のサブネットと比較し、新しいサブネットで警告；初回ログインはベースラインがなく警告しない |
| `Guard(http.Handler) http.Handler` | ミドルウェアラッパー、`Check` が検出すると 401 を返す |
| `Revoke(token) error` | ログアウト、セッションを即座に無効化 |
| `DefaultTokenSource(r) string` | `Authorization: Bearer <token>` を取得、次に `session` Cookie |
| `RecordFailure(identity, r) error` | ログイン失敗を 1 回計上（identity はユーザー名などの認証キー、r はクライアント IP を提供）。ウィンドウ内で `Failures`（既定 5 回 / 5 分）に達するとロックし、以降 1 回ごとに倍増、上限は `MaxLockout`（既定 24 時間） |
| `CheckLogin(identity, r) *Result` | ログイン試行の事前チェック: 識別子がロック中なら `token_locked`、クライアント IP が既に `StuffingLimit`（既定 10）個の異なる識別子で失敗していれば `credential_stuffing` — いずれも Critical |
| `GuardLogin(next, identity) http.Handler` | 認証エンドポイント用ミドルウェア: 該当時は `Retry-After` 付き 429。ハンドラ後は 401 を失敗として計上し、2xx でカウントを戻します |
| `IsLocked(token) (bool, time.Time)` | トークンがロック中かどうかと解除時刻。ストア障害時は未ロック扱い |
| `ClearFailures(token) error` | ログイン成功時に失敗カウントを戻します（ロックは独自のタイマーで動き、解除されません） |

`Details["reason"]` の値：

| reason | トリガー条件 | 深刻度 |
|--------|---------|---------|
| `missing_token` | リクエストに token が含まれない | High |
| `unknown_token` | token が未発行、`Revoke` 済み、または期限切れ | High |
| `token_locked` | ウィンドウ内で失敗回数がしきい値に到達、トークンをロック | Critical |
| `credential_stuffing` | 1 つの IP がウィンドウ内で `StuffingLimit` 個の異なる識別子に失敗 | Critical |
| `client_hijack` | UA の変化、またはデバイスフィンガープリントの変化 | Critical |
| `remote_login` | `CountryOf` がクロスカントリーと判定（Critical）/ IP が別サブネット（High）。`Check` と `Observe` で共通 | Critical / High |
| `store_error` | ストレージ読み取り失敗かつ `FailClosed = true` | High |

> `TrustProxyHeaders` はデフォルトで無効：`X-Forwarded-For` / `X-Real-IP` はクライアントが制御できるため、有効にするとハイジャック者がバインドされた IP を偽装できます。自前のリバースプロキシ配下でのみ有効にしてください。
> `FailClosed` はデフォルトで無効（ストレージ障害時は通過）、`httpval.IPBlacklist` と同様です。ストレージのキーは token の SHA-256 であり、ストレージが漏洩しても直接利用可能な token は得られません。

### Signer

検出器名は `data_tamper`（`Signer.Name()` を参照）。

```go
type Signer struct {
    Secret  []byte           // 共有 HMAC 鍵、crypto/rand で生成
    MaxSkew time.Duration    // タイムスタンプの許容ずれ、既定 5m
    Nonces  storage.Backend  // 省略可能: nil でない場合、ウィンドウカウントで署名リプレイを遮断（クロスインスタンス可、Redis を再利用）
}

signer := session.NewSigner(secret, mem)
sig, err := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // "<unix-ts>.<nonce>.<mac>"
res := signer.Verify(params, sig)                                        // パラメータ改変／鍵不一致／タイムアウト／リプレイ
```

パラメータは `url.Values.Encode()` で正規化され（ソート + エスケープ）、map の順序は結果に影響しません。検証順序はタイムスタンプ → 署名 → nonce カウンターであるため、偽造署名が正当な nonce を消費することはできません。`Nonces` が nil の場合、リプレイの制限はタイムスタンプウィンドウのみになります。

`Details["reason"]` の値：`signer_not_configured`（Critical）、`signature_mismatch`（Critical）、`replay`（Critical）、`signature_malformed`、`timestamp_invalid`、`signature_expired`、`timestamp_in_future`（High）。

## ファイルアップロード補助関数

アップロード検出は検出器としての登録に加え、直接呼び出せる 2 つの補助関数もエクスポートします:

```go
// HasMaliciousExt はファイル名の拡張子がホワイトリスト（15 種）にないか判定。拡張子なしは true を返す
func HasMaliciousExt(filename string) bool

// CheckExtension は上記と同源だが、完全な *Result を返す（深刻度と説明を含む）
func (d *MaliciousFileUpload) CheckExtension(filename string) *security.Result
```

ファイルがディスクに書き込まれる前の迅速な事前検証用で、`Engine` を構築する必要はありません。

## プロジェクトのマスコット

`pet` パッケージはコンパイル時に `go:embed` でプロジェクトのマスコット Sentinel Gopher の SVG を埋め込みます — サードパーティ依存も、実行時のファイル読み込みもありません:

```go
func SVG() []byte         // 生の SVG バイト。スライスは共有されるため、呼び出し側は変更しないこと
func Handler() http.Handler // image/svg+xml として配信、Cache-Control は 1 日
func Banner() string      // ターミナル向けのプレーンテキストバナー、末尾に改行を含む
```

```go
log.Println(pet.Banner())              // 起動時に出力
http.Handle("/pet.svg", pet.Handler()) // デバッグループにマウント
```

`Handler` は内部的に `http.ServeContent` を通すため `Content-Length` を備え、`Range` と `HEAD` に対応します。直接 `w.Write` すると `net/http` の 2 KiB スニッフバッファを超え、chunked レスポンスに退化します。

## カスタム検出器の例

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "悪意のあるコンテンツを検出",
    }
}

e.Register(&MyDetector{})
```

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

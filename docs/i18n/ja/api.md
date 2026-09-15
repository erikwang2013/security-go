# Security Go — API インターフェースドキュメント

このドキュメントは `security-go` の公開 API をすべてまとめたものです：コア型、`Detector` インターフェース、`Engine` レジストリ、ストレージバックエンドインターフェース、HTTP バリデータのコンストラクタ。

## コア型

### Result

各検出器が返す検出結果の構造体：

```go
type Result struct {
    Name     string                 // 检测器名称
    Detected bool                   // 是否检测到攻击
    Message  string                 // 结果说明
    Severity Severity               // 严重程度
    Details  map[string]interface{} // 附加细节
}
```

### Severity

深刻度レベル：

```go
type Severity int

const (
    SeverityLow      Severity = iota // 低风险
    SeverityMedium                   // 中风险
    SeverityHigh                     // 高风险
    SeverityCritical                 // 严重
)
```

## Detector インターフェース

すべての検出器はこのインターフェースを実装する必要があります：

```go
type Detector interface {
    Name() string                // 检测器唯一名称
    Detect(input string) *Result // 对输入执行检测，返回结果
}
```

## Engine レジストリ

`Engine` は統合エントリポイントであり、名前によって検出器を登録・管理します：

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // 创建空 Engine
func (e *Engine) Register(d Detector)             // 注册检测器
func (e *Engine) Detect(name, input string) *Result // 按名称检测单个输入
func (e *Engine) DetectAll(input string) []*Result  // 全量检测（仅返回 Detected=true）
func (e *Engine) DetectRequest(r *http.Request) []*Result // 检测完整 HTTP 请求
```

`DetectRequest` はリクエストの URL、Query、Headers、Cookies を自動的に収集して入力とします。 各入力は URL デコード後にも再スキャンされるため、`%3Cscript%3E` のようなエンコード済みペイロードで検出を回避できません。

## 登録エントリポイント

```go
// all 包提供一键注册全部零配置检测器（27 个）
all.RegisterAll(engine)
```

## ストレージバックエンドインターフェース

`httpval.IPBlacklist` はこのインターフェースを通じてプラグ可能なストレージを使用します：

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // 窗口内计数 +1
    Get(key string) (int, error)                          // 读取计数
    Block(key string, duration time.Duration) error       // 封禁指定时长
    IsBlocked(key string) (bool, error)                   // 是否已封禁
    Close() error                                         // 关闭并释放资源
}
```

実装：

| バックエンド | 説明 |
|------|------|
| `storage.NewMemory()` | メモリ実装、`sync.Mutex` + map、30 秒ごとに期限切れエントリを自動クリーンアップ |
| `storage.NewFile(path)` | JSON ファイル永続化、30 秒ごとに自動保存 + Close 時に flush |
| `storage/redis` | Redis サブモジュール、Pipeline Incr + TTL、`go-redis/v9` が必要 |

## HTTP バリデータ

```go
// HTTP 方法白名单校验
e.Register(&httpval.Method{})

// 请求体大小限制（默认 10MB）
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type 白名单（空白名单 = 拒绝所有）
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF Origin 校验（跨域请求检查 Origin 与 Host 匹配）
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP 黑名单（窗口内 N 次攻击自动封禁，默认 5次/60s → 封禁15分钟）
bl := httpval.NewIPBlacklist(mem) // mem 为任意 storage.Backend 实现
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
    Load(key string) ([]byte, error)   // 不存在或已过期返回 (nil, nil)
    Delete(key string) error
}

session.NewMemoryStore() *MemoryStore // 内存实现，30s 清理过期条目，Close 停止清理
```

### Session

```go
type Session struct {
    IP          string    `json:"ip"`           // 建立会话时的客户端 IP
    UserAgent   string    `json:"ua,omitempty"`
    Fingerprint string    `json:"fp,omitempty"` // 设备指纹（X-Device-Fingerprint 头）
    Country     string    `json:"country,omitempty"`
    IssuedAt    time.Time `json:"issued_at"`
    LastSeen    time.Time `json:"last_seen"`    // 每次 Check 滑动续期
}
```

### Tracker

```go
type Tracker struct {
    Store             Store
    TTL               time.Duration              // 会话生命周期，默认 30m，每次 Check 滑动续期
    SubnetBits        int                        // 同地判定前缀，默认 24（IPv6 自动 +24）
    CountryOf         func(ip string) string     // 可选 GeoIP 钩子；为 nil 时跳过国家判定
    KnownNets         int                        // Observe 每用户保留的登录网段数，默认 8
    KnownNetTTL       time.Duration              // 登录网段保留时长，默认 90 天
    TokenSource       func(*http.Request) string // 默认 DefaultTokenSource
    TrustProxyHeaders bool                       // 默认 false
    FailClosed        bool                       // 默认 false
    MaxLockout        time.Duration              // 每次锁定翻倍的上限，默认 24h
    BackoffWindow     time.Duration              // 升级计数的保留时长，默认 24h
    StuffingLimit     int                        // 同一 IP 允许失败的不同身份数上限，默认 10
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

```go
type Signer struct {
    Secret  []byte           // 共享 HMAC 密钥，用 crypto/rand 生成
    MaxSkew time.Duration    // 时间戳允许偏差，默认 5m
    Nonces  storage.Backend  // 可选：非空时用窗口计数拦截签名重放（可跨实例，复用 Redis）
}

signer := session.NewSigner(secret, mem)
sig, err := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // "<unix-ts>.<nonce>.<mac>"
res := signer.Verify(params, sig)                                        // 参数被改动/密钥不符/超时/重放
```

パラメータは `url.Values.Encode()` で正規化され（ソート + エスケープ）、map の順序は結果に影響しません。検証順序はタイムスタンプ → 署名 → nonce カウンターであるため、偽造署名が正当な nonce を消費することはできません。`Nonces` が nil の場合、リプレイの制限はタイムスタンプウィンドウのみになります。

`Details["reason"]` の値：`signer_not_configured`（Critical）、`signature_mismatch`（Critical）、`replay`（Critical）、`signature_malformed`、`timestamp_invalid`、`signature_expired`、`timestamp_in_future`（High）。

## カスタム検出器の例

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "检测到恶意内容",
    }
}

e.Register(&MyDetector{})
```

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

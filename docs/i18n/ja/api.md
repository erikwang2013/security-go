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

`DetectRequest` はリクエストの URL、Query、Headers、Cookies を自動的に収集して入力とします。

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

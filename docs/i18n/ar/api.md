# Security Go — وثيقة واجهة API

تلخّص هذه الوثيقة جميع واجهات API العامة لحزمة `security-go`: الأنواع الأساسية، واجهة `Detector`، سجل `Engine`، واجهة التخزين الخلفي، ومُنشئات مُدقّقات HTTP.

## الأنواع الأساسية

### Result

هيكل نتيجة الكشف، يُرجَع من كل كاشف:

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

مستويات الخطورة:

```go
type Severity int

const (
    SeverityLow      Severity = iota // 低风险
    SeverityMedium                   // 中风险
    SeverityHigh                     // 高风险
    SeverityCritical                 // 严重
)
```

## واجهة Detector

يجب أن تنفّذ جميع الكاشفات هذه الواجهة:

```go
type Detector interface {
    Name() string                // 检测器唯一名称
    Detect(input string) *Result // 对输入执行检测，返回结果
}
```

## سجل Engine

`Engine` هو نقطة الدخول الموحّدة، يسجّل الكاشفات ويديرها حسب الاسم:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // 创建空 Engine
func (e *Engine) Register(d Detector)             // 注册检测器
func (e *Engine) Detect(name, input string) *Result // 按名称检测单个输入
func (e *Engine) DetectAll(input string) []*Result  // 全量检测（仅返回 Detected=true）
func (e *Engine) DetectRequest(r *http.Request) []*Result // 检测完整 HTTP 请求
```

يجمع `DetectRequest` تلقائيًا URL وQuery وHeaders وCookies الخاصة بالطلب كمدخلات.

## نقطة التسجيل

```go
// all 包提供一键注册全部零配置检测器（27 个）
all.RegisterAll(engine)
```

## واجهة التخزين الخلفي

يستخدم `httpval.IPBlacklist` تخزينًا قابلًا للتوصيل عبر هذه الواجهة:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // 窗口内计数 +1
    Get(key string) (int, error)                          // 读取计数
    Block(key string, duration time.Duration) error       // 封禁指定时长
    IsBlocked(key string) (bool, error)                   // 是否已封禁
    Close() error                                         // 关闭并释放资源
}
```

التنفيذات:

| الواجهة الخلفية | الوصف |
|------|------|
| `storage.NewMemory()` | تنفيذ بالذاكرة، `sync.Mutex` + map، تنظيف تلقائي للعناصر المنتهية كل 30 ثانية |
| `storage.NewFile(path)` | استمرارية عبر ملفات JSON، حفظ تلقائي كل 30 ثانية + flush عند Close |
| `storage/redis` | وحدة Redis الفرعية، Pipeline Incr + TTL، يتطلب `go-redis/v9` |

## مُدقّقات HTTP

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

## مثال على كاشف مخصص

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

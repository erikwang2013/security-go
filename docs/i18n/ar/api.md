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

يجمع `DetectRequest` تلقائيًا URL وQuery وHeaders وCookies الخاصة بالطلب كمدخلات. ويُعاد فحص كل مدخل بعد فك ترميز URL، فلا تستطيع حِزم مُرمَّزة مثل `%3Cscript%3E` تجاوز الكشف.

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

### عمق تداخل JSON وسمات Cookie

| المُنشئ | الوصف |
|--------|------|
| `NewNestedDepth(maxDepth, maxKeys) *NestedDepth` | مسح تدفقي لجسم JSON: يُبلّغ `nested_depth` عند تجاوز عمق التداخل (الافتراضي 32) أو عدد العناصر؛ لا يطابق JSON غير الصالح أو المقطوع أبدًا |
| `NewCookieAttrs(requireSecure, requireHttpOnly, requireSameSite) *CookieAttrs` | يتحقق من `Set-Cookie` واحد: سمات غائبة، قيمة طويلة جدًا (`MaxValueLen`)، قيمة فارغة (`RequireNonEmpty`) |

## أمان الجلسات

تكشف حزمة `session` **اختطاف العميل** و**التلاعب بالبيانات** و**تسجيل الدخول من موقع بعيد**. وتحتاج إلى `*http.Request` كاملًا (token، عنوان IP للعميل، User-Agent) وإلى تخزين ومفاتيح يوفّرها التطبيق، لذلك لا تُسجَّل في `Engine`، بل تُستدعى مباشرة كوسيط/دالة.

### واجهة Store

لا يمكن التعبير عن ربط الجلسة عبر `storage.Backend` (فهو لا يوفّر سوى العدّ والحظر)، لذلك تأتي `session` بواجهة صغيرة خاصة بها:

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
}
```

| الطريقة | الوصف |
|------|------|
| `NewTracker(store) *Tracker` | ينشئ ويملأ القيم الافتراضية |
| `Issue(token, r) error` | بعد نجاح تسجيل الدخول يربط الـ token بـ نطاق IP / UA / بصمة الجهاز؛ الـ token الفارغ يُرجع خطأ |
| `Check(r) *Result` | يتحقق مع كل طلب، وعند الإصابة يُرجع `Detected: true`؛ وعند النجاح يجدّد الجلسة انزلاقيًا |
| `Observe(user, r) *Result` | عند تسجيل الدخول يقارن النطاقات السابقة لهذا المستخدم، ويُنبّه عند ظهور نطاق جديد؛ أول تسجيل دخول بلا خط أساس لا يُنبّه |
| `Guard(http.Handler) http.Handler` | تغليف كوسيط، وعند إصابة `Check` يُرجع 401 |
| `Revoke(token) error` | تسجيل الخروج، فتُبطل الجلسة فورًا |
| `DefaultTokenSource(r) string` | يأخذ `Authorization: Bearer <token>`، ثم كوكي `session` |
| `RecordFailure(token) error` | يحصي محاولة مصادقة فاشلة؛ وعند بلوغ `Failures` (افتراضيًا 5 خلال 5 دقائق) يُكتب القفل، و`Lockout` افتراضيًا 15 دقيقة |
| `IsLocked(token) (bool, time.Time)` | هل الرمز مقفل ومتى ينتهي القفل؛ خطأ المخزن يُقرأ كغير مقفل |
| `ClearFailures(token) error` | يصفّر عدّاد الفشل بعد نجاح تسجيل الدخول (القفل يعمل بمؤقته ولا يُلغى) |

قيم `Details["reason"]`:

| reason | شرط الإطلاق | مستوى الخطورة |
|--------|---------|---------|
| `missing_token` | الطلب لا يحمل token | High |
| `unknown_token` | الـ token لم يُصدر، أو تم `Revoke`، أو انتهت صلاحيته | High |
| `token_locked` | بلوغ حد الفشل داخل النافذة، الرمز مقفل | Critical |
| `client_hijack` | تغيّر UA، أو تغيّر بصمة الجهاز | Critical |
| `remote_login` | يحكم `CountryOf` باختلاف البلد (Critical) / اختلاف نطاق IP (High)، ويشترك فيه `Check` و`Observe` | Critical / High |
| `store_error` | فشل قراءة التخزين مع `FailClosed = true` | High |

> `TrustProxyHeaders` معطّل افتراضيًا: `X-Forwarded-For` / `X-Real-IP` يتحكم بهما العميل، وبعد تفعيله يمكن للمختطف تزوير عنوان IP المربوط. لا تفعّله إلا خلف وكيل عكسي تملكه.
> `FailClosed` معطّل افتراضيًا (السماح عند فشل التخزين)، متوافق مع `httpval.IPBlacklist`. مفتاح التخزين هو SHA-256 للـ token، لذا فإن تسريب التخزين لا يمنح token صالحًا مباشرة.

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

تُنظَّم المعاملات عبر `url.Values.Encode()` (ترتيب + تهريب)، فترتيب الـ map لا يؤثر على النتيجة. ترتيب التحقق هو الطابع الزمني ← التوقيع ← عدّاد nonce، لذلك لا يمكن لتوقيع مزوّر أن يستهلك nonce صالحًا؛ وعندما يكون `Nonces` مساويًا لـ nil لا يبقى سوى نافذة الطابع الزمني للحد من إعادة الإرسال.

قيم `Details["reason"]`: `signer_not_configured` (Critical)، `signature_mismatch` (Critical)، `replay` (Critical)، `signature_malformed`، `timestamp_invalid`، `signature_expired`، `timestamp_in_future` (High).

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

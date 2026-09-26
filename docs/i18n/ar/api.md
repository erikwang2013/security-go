# Security Go — وثيقة واجهة API

تلخّص هذه الوثيقة جميع واجهات API العامة لحزمة `security-go`: الأنواع الأساسية، واجهة `Detector`، سجل `Engine`، واجهة التخزين الخلفي، ومُنشئات مُدقّقات HTTP.

## الأنواع الأساسية

### Result

هيكل نتيجة الكشف، يُرجَع من كل كاشف:

```go
type Result struct {
    Name     string                 // اسم الكاشف
    Detected bool                   // هل تم اكتشاف هجوم
    Message  string                 // وصف النتيجة
    Severity Severity               // درجة الخطورة
    Details  map[string]interface{} // تفاصيل إضافية
}
```

### Severity

مستويات الخطورة:

```go
type Severity int

const (
    SeverityLow      Severity = iota // خطر منخفض
    SeverityMedium                   // خطر متوسط
    SeverityHigh                     // خطر مرتفع
    SeverityCritical                 // حرج
)
```

## واجهة Detector

يجب أن تنفّذ جميع الكاشفات هذه الواجهة:

```go
type Detector interface {
    Name() string                // الاسم الفريد للكاشف
    Detect(input string) *Result // ينفّذ الفحص على المدخل ويعيد النتيجة
}
```

## سجل Engine

`Engine` هو نقطة الدخول الموحّدة، يسجّل الكاشفات ويديرها حسب الاسم:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // ينشئ Engine فارغة
func (e *Engine) Register(d Detector)             // يسجّل كاشفًا
func (e *Engine) Detect(name, input string) *Result // يفحص مدخلًا واحدًا بالاسم
func (e *Engine) DetectAll(input string) []*Result  // يفحص الكل (يعيد Detected=true فقط)
func (e *Engine) DetectRequest(r *http.Request) []*Result // يفحص طلب HTTP كاملًا
```

يجمع `DetectRequest` تلقائيًا URL وQuery وHeaders وCookies الخاصة بالطلب كمدخلات. ويُعاد فحص كل مدخل بعد فك ترميز URL، فلا تستطيع حِزم مُرمَّزة مثل `%3Cscript%3E` تجاوز الكشف.

## نقطة التسجيل

```go
// حزمة all تسجّل بنداء واحد كل الكاشفات التي لا تحتاج إعدادًا (27 كاشفًا)
all.RegisterAll(engine)
```

## الدوال المساعدة

```go
// FirstMatch يعيد أول نمط يطابق input؛ وإن لم يتطابق أي منها يعيد ("", false)
func FirstMatch(input string, patterns []*regexp.Regexp) (string, bool)
```

تتيح للكاشفات المخصصة إعادة استخدام الأنماط المُجمَّعة مسبقًا بدل إعادة تجميع التعبيرات النمطية.

## واجهة التخزين الخلفي

يستخدم `httpval.IPBlacklist` تخزينًا قابلًا للتوصيل عبر هذه الواجهة:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // عدّاد ضمن النافذة +1
    Get(key string) (int, error)                          // يقرأ العدّاد
    Block(key string, duration time.Duration) error       // يحجب للمدة المحددة
    IsBlocked(key string) (bool, error)                   // هل هو محجوب بالفعل
    Close() error                                         // يغلق ويحرّر الموارد
}
```

التنفيذات:

| الواجهة الخلفية | الوصف |
|------|------|
| `storage.NewMemory() *Memory` | تنفيذ بالذاكرة، `sync.Mutex` + map، تنظيف تلقائي للعناصر المنتهية كل 30 ثانية |
| `storage.NewFile(path) (*File, error)` | استمرارية عبر ملفات JSON، حفظ تلقائي كل 30 ثانية + flush عند Close |
| `redis.New(addr, password string, db int) *Backend` | وحدة Redis الفرعية، Pipeline Incr + TTL، يتطلب `go-redis/v9` |

## مُدقّقات HTTP

```go
// تحقق من القائمة البيضاء لطرق HTTP
e.Register(&httpval.Method{})

// تحديد حجم جسم الطلب (10MB افتراضيًا)
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// قائمة Content-Type البيضاء (قائمة فارغة = رفض الكل)
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// تحقق CSRF من Origin (في الطلبات عبر النطاقات يُقارن Origin مع Host)
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// قائمة IP السوداء (حجب تلقائي بعد N هجومًا في النافذة؛ افتراضيًا 5/60 ث → حجب 15 دقيقة)
bl := httpval.NewIPBlacklist(mem) // mem هو أي تطبيق لـ storage.Backend
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
    Load(key string) ([]byte, error)   // يعيد (nil, nil) إن لم يوجد أو انتهت صلاحيته
    Delete(key string) error
}

session.NewMemoryStore() *MemoryStore // تطبيق في الذاكرة، ينظّف الإدخالات المنتهية كل 30 ث، وClose يوقف التنظيف
```

### Session

```go
type Session struct {
    IP          string    `json:"ip"`           // عنوان IP للعميل عند إنشاء الجلسة
    UserAgent   string    `json:"ua,omitempty"`
    Fingerprint string    `json:"fp,omitempty"` // بصمة الجهاز (ترويسة X-Device-Fingerprint)
    Country     string    `json:"country,omitempty"`
    IssuedAt    time.Time `json:"issued_at"`
    LastSeen    time.Time `json:"last_seen"`    // تجديد متحرّك مع كل Check
}
```

### Tracker

اسم الكاشف `session_guard` (انظر `Tracker.Name()`).

```go
type Tracker struct {
    Store             Store
    TTL               time.Duration              // عمر الجلسة، افتراضيًا 30m، مع تجديد متحرّك عند كل Check
    SubnetBits        int                        // بادئة تحديد الموقع نفسه، افتراضيًا 24 (IPv6 تلقائيًا +24)
    CountryOf         func(ip string) string     // خطاف GeoIP اختياري؛ وعندما يكون nil يُتخطّى فحص الدولة
    KnownNets         int                        // عدد شبكات تسجيل الدخول التي يحتفظ بها Observe لكل مستخدم، افتراضيًا 8
    KnownNetTTL       time.Duration              // مدة الاحتفاظ بشبكات تسجيل الدخول، افتراضيًا 90 يومًا
    TokenSource       func(*http.Request) string // افتراضيًا DefaultTokenSource
    TrustProxyHeaders bool                       // افتراضيًا false
    FailClosed        bool                       // افتراضيًا false
    Failures          int                        // عتبة مرات الفشل في النافذة لقفل الـ token، افتراضيًا 5
    FailureWindow     time.Duration              // مدة الاحتفاظ بعدّاد الفشل، وما تجاوزها لا يُحتسب، افتراضيًا 5m
    Lockout           time.Duration              // مدة الحجب عند بلوغ العتبة أول مرة، وتتضاعف في كل مرة، افتراضيًا 15m
    MaxLockout        time.Duration              // الحد الأقصى لمضاعفة كل حجب، افتراضيًا 24h
    BackoffWindow     time.Duration              // مدة الاحتفاظ بعدّاد التصعيد، افتراضيًا 24h
    StuffingLimit     int                        // الحد الأقصى لعدد الهويات المختلفة التي يمكن أن تفشل معها نفس الـ IP، افتراضيًا 10
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
| `RecordFailure(identity, r) error` | يحصي فشل تسجيل دخول واحد (identity هو مفتاح المصادقة كاسم المستخدم، وr يوفّر عنوان IP للعميل)؛ عند بلوغ `Failures` (افتراضيًا 5 خلال 5 دقائق) يُقفل الهوية، ويتضاعف كل قفل حتى `MaxLockout` (افتراضيًا 24 ساعة) |
| `CheckLogin(identity, r) *Result` | فحص مسبق لمحاولة الدخول: `token_locked` عند قفل الهوية، و`credential_stuffing` عند فشل الـ IP نفسه أمام `StuffingLimit` (افتراضيًا 10) هويات مختلفة — كلاهما Critical |
| `GuardLogin(next, identity) http.Handler` | وسيط لنقطة تسجيل الدخول: 429 مع `Retry-After` عند الانطباق؛ وبعد المعالج تُحتسب 401 فشلًا و2xx تصفّر العدّاد |
| `IsLocked(token) (bool, time.Time)` | هل الرمز مقفل ومتى ينتهي القفل؛ خطأ المخزن يُقرأ كغير مقفل |
| `ClearFailures(token) error` | يصفّر عدّاد الفشل بعد نجاح تسجيل الدخول (القفل يعمل بمؤقته ولا يُلغى) |

قيم `Details["reason"]`:

| reason | شرط الإطلاق | مستوى الخطورة |
|--------|---------|---------|
| `missing_token` | الطلب لا يحمل token | High |
| `unknown_token` | الـ token لم يُصدر، أو تم `Revoke`، أو انتهت صلاحيته | High |
| `token_locked` | بلوغ حد الفشل داخل النافذة، الرمز مقفل | Critical |
| `credential_stuffing` | فشل عنوان IP واحد أمام `StuffingLimit` من الهويات المختلفة داخل النافذة | Critical |
| `client_hijack` | تغيّر UA، أو تغيّر بصمة الجهاز | Critical |
| `remote_login` | يحكم `CountryOf` باختلاف البلد (Critical) / اختلاف نطاق IP (High)، ويشترك فيه `Check` و`Observe` | Critical / High |
| `store_error` | فشل قراءة التخزين مع `FailClosed = true` | High |

> `TrustProxyHeaders` معطّل افتراضيًا: `X-Forwarded-For` / `X-Real-IP` يتحكم بهما العميل، وبعد تفعيله يمكن للمختطف تزوير عنوان IP المربوط. لا تفعّله إلا خلف وكيل عكسي تملكه.
> `FailClosed` معطّل افتراضيًا (السماح عند فشل التخزين)، متوافق مع `httpval.IPBlacklist`. مفتاح التخزين هو SHA-256 للـ token، لذا فإن تسريب التخزين لا يمنح token صالحًا مباشرة.

### Signer

اسم الكاشف `data_tamper` (انظر `Signer.Name()`).

```go
type Signer struct {
    Secret  []byte           // مفتاح HMAC مشترك، يُولَّد بـ crypto/rand
    MaxSkew time.Duration    // الانحراف المسموح به للطابع الزمني، افتراضيًا 5m
    Nonces  storage.Backend  // اختياري: عند عدم الفراغ يمنع عدّاد النافذة إعادة استخدام التوقيع (عبر النسخ، بإعادة استخدام Redis)
}

signer := session.NewSigner(secret, mem)
sig, err := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // "<unix-ts>.<nonce>.<mac>"
res := signer.Verify(params, sig)                                        // تغيّرت المعاملات/المفتاح غير مطابق/انتهت المدة/إعادة استخدام
```

تُنظَّم المعاملات عبر `url.Values.Encode()` (ترتيب + تهريب)، فترتيب الـ map لا يؤثر على النتيجة. ترتيب التحقق هو الطابع الزمني ← التوقيع ← عدّاد nonce، لذلك لا يمكن لتوقيع مزوّر أن يستهلك nonce صالحًا؛ وعندما يكون `Nonces` مساويًا لـ nil لا يبقى سوى نافذة الطابع الزمني للحد من إعادة الإرسال.

قيم `Details["reason"]`: `signer_not_configured` (Critical)، `signature_mismatch` (Critical)، `replay` (Critical)، `signature_malformed`، `timestamp_invalid`، `signature_expired`، `timestamp_in_future` (High).

## دوال مساعدة لرفع الملفات

إلى جانب تسجيله ككاشف، يُصدِّر فحص الرفع دالتين مساعدتين يمكن استدعاؤهما مباشرة:

```go
// HasMaliciousExt يتحقق مما إذا كان امتداد اسم الملف خارج القائمة البيضاء (15 امتدادًا)؛ وبدون امتداد يعيد true
func HasMaliciousExt(filename string) bool

// CheckExtension من المصدر نفسه، لكنه يعيد *Result كاملًا (مع درجة الخطورة والوصف)
func (d *MaliciousFileUpload) CheckExtension(filename string) *security.Result
```

تُستخدم للتحقق السريع قبل كتابة الملف على القرص، دون إنشاء `Engine`.

## تميمة المشروع

تُضمِّن حزمة `pet` ملف SVG الخاص بتميمة المشروع Sentinel Gopher (哨兵鼠) في وقت الترجمة عبر `go:embed` — دون أي اعتماد خارجي ودون قراءة ملفات في وقت التشغيل:

```go
func SVG() []byte         // بايتات SVG الخام؛ الشريحة مشتركة وعلى المستدعي عدم تعديلها
func Handler() http.Handler // يُقدَّم بوصفه image/svg+xml مع Cache-Control ليوم واحد
func Banner() string      // لافتة نصية عادية مناسبة للطرفية مع سطر جديد في النهاية
```

```go
log.Println(pet.Banner())              // يُطبع عند بدء التشغيل
http.Handle("/pet.svg", pet.Handler()) // يُربط بمسار تنقيح
```

يستخدم `Handler` داخليًا `http.ServeContent`، لذا يحمل `Content-Length` ويدعم `Range` و`HEAD`؛ أما `w.Write` المباشر فيتجاوز مخزن الاستشعار 2 KiB في `net/http` ويتحوّل إلى استجابة chunked.

## مثال على كاشف مخصص

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "تم اكتشاف محتوى خبيث",
    }
}

e.Register(&MyDetector{})
```

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

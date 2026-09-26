# Security Go — مكتبة كشف الهجمات

[简体中文](../../../README.md) · [English](../../../README-EN.md) · [وثيقة واجهة API](api.md)

حزمة كشف الهجمات المكتوبة بلغة Go، تغطي **36 كاشفًا** و**6 فئات هجمات رئيسية** و**3 واجهات خلفية للتخزين قابلة للتوصيل**. واجهة موحّدة + نمط سجلّات (Registry)، مكتبة كشف خالصة، متوافقة مع أي إطار عمل HTTP بلغة Go.

<p align="center">
  <img src="../../../pet/pet.svg" width="190" alt="Sentinel Gopher">
  <br>
  <sub>تميمة المشروع <b>Sentinel Gopher</b> (哨兵鼠) — غوفر بلغة Go يقف حارسًا حاملًا درعًا.<br>الرقم <b>36</b> على الدرع هو عدد الكاشفات؛ والعدسة المكبِّرة هي الفحص مع كل طلب.</sub>
</p>

[بنية التصميم](#بنية-التصميم) · [الوظائف](#الوظائف-المنفّذة) · [دورة الحياة](#دورة-الحياة) · [هيكل المشروع](#هيكل-المشروع) · [التميمة](#التميمة)

## فلسفة التصميم

### المبادئ الأساسية

- **كشف بدون اعتماديات** — تستخدم جميع الكاشفات مكتبة Go القياسية `regexp` فقط، بدون أي اعتماديات خارجية
- **واجهة موحّدة** — ينفّذ كل كاشف واجهة `Detector` (`Name()` + `Detect()`)، وتُدار بشكل موحّد عبر سجل `Engine`
- **تعبيرات نمطية مُجمّعة مسبقًا** — تُجمّع جميع الأنماط عند تهيئة `var`، بصفر تكلفة وقت تشغيل
- **تكوين حسب الحاجة** — كاشفات الحقن/البروتوكول/البيانات/الملفات جاهزة للاستخدام الفوري؛ بينما تتطلب مُدقّقات HTTP وكشف أمان الجلسات تكوينًا من التطبيق

### بنية التصميم

![بنية التصميم](../../../docs/images/architecture.svg)

> حزمة `session` لا تمر عبر تسجيل `Engine`: فحص الجلسة يجب أن يقرأ `*http.Request` كاملًا (token، عنوان IP للعميل، User-Agent)،
> ويحتاج إلى توفير التخزين والمفاتيح من التطبيق، لذلك تُستدعى مباشرة كوسيط (middleware)، انظر قسم تكوين أمان الجلسات أدناه.

### دورة الحياة

الدورة الكاملة للطلب، من الدخول مرورًا بالكشف ووصولًا إلى المعالجة المتدرّجة (بما في ذلك دورة حظر عناوين IP وإعادة الفحص بعد فك ترميز URL)، إضافة إلى رحلة الجلسة من الربط حتى الإبطال:

![دورة الحياة](../../../docs/images/lifecycle.svg)

### مستويات الخطورة

| المستوى | الوصف | سيناريو نموذجي |
|------|------|---------|
| `SeverityLow` | خطورة منخفضة | طريقة HTTP غير قانونية، عدم تطابق Content-Type |
| `SeverityMedium` | خطورة متوسطة | إشارات ضعيفة: مشكلات إعدادات CORS، إعادة التوجيه المفتوحة، استكشاف GraphQL، إضافة إلى الأنماط بلا سياق التي يفصلها كل كاشف عمدًا (`../`, `on…=`, `javascript:`, `sleep(`, `sqlite_master`, العلامات الخلفية, `{#…#}`, `__proto__:`, أسماء دوال PHP السحرية)، وهي شائعة في الدروس والمحتوى العادي |
| `SeverityHigh` | خطورة عالية | إشارات قوية: XSS، حقن SQL، SSRF، اجتياز المسار، شذوذ الجلسة |
| `SeverityCritical` | خطورة حرجة | إشارات قوية: حقن الأوامر، JNDI، SSTI، XXE، تسريب البيانات، إلغاء التسلسل (كائنات PHP المتسلسلة / pickle / Java / .NET) |

## الوظائف المنفّذة

### نظرة عامة على الوظائف

![تصميم الوظائف](../../../docs/images/features.svg)

### هجمات الحقن (10)

| الكاشف | أنماط الكشف |
|--------|---------|
| **XSS** | `<script>`، معالجات الأحداث `on[a-z]+=`، البروتوكول الزائف `javascript:`، حقن SVG/CSS، `eval()`، `document.cookie` |
| **حقن SQL** | `UNION SELECT` (بما في ذلك الالتفاف عبر `/**/`)، `sleep/benchmark/pg_sleep`، الحقن الأعمى المنطقي، تعداد `information_schema`، `xp_cmdshell` |
| **حقن الأوامر** | علامات الاقتباس الخلفية، `$()`، الأنابيب `|`، `/dev/tcp`، دوال PHP `system/exec/shell_exec`، التنفيذ المتسلسل `&&` `;` `\|\|` |
| **حقن NoSQL** | عوامل تشغيل MongoDB `$ne` `$gt` `$regex` `$where`، `$func`، حقن مفاتيح JSON |
| **حقن LDAP** | عوامل تشغيل الفلترة `(\|(&(!`، `objectClass=*`، التفاف عبر ترميز URL |
| **حقن XPATH** | التفاف منطقي `' or '1'='1`، `string-length()`، `count()` |
| **JNDI/Log4Shell** | `${jndi:ldap://`، تشويش `${lower:j}`، متغيرات البيئة `${env:}`، بروتوكولات `ldap/rmi/dns` |
| **حقن SSI** | `<!--#exec cmd=`، `<!--#include file=`، `<!--#echo var=` |
| **حقن GraphQL** | استكشاف `__schema`/`__type`، DoS عبر التداخل العميق (5 طبقات فأكثر)، كشف `mutation` |
| **SSTI** | Jinja2 `{{}}`، FreeMarker `${}`، ERB `<% %>`، اجتياز Python MRO، الوصول إلى `config/self` |

### هجمات البروتوكول والطلبات (9)

| الكاشف | أنماط الكشف |
|--------|---------|
| **SSRF** | عناوين IP الداخلية (127/10/172.16/192.168)، `169.254.169.254`، IPv6 loopback، بروتوكولات `gopher/dict/file/ftp` |
| **XXE** | `<!ENTITY SYSTEM/PUBLIC`، الكيانات المعلمية `%entity;`، إعلان DOCTYPE |
| **حقن ترويسات HTTP** | CRLF `%0d%0a` / `\r\n`، حقن Set-Cookie/Location/Content-Length |
| **هجوم ترويسة Host** | حقن CRLF في Host، تسميم `X-Forwarded-Host`، `X-Original-URL` |
| **تهريب الطلبات** | عدم تطابق Transfer-Encoding/Content-Length، ترويسات TE مزدوجة، تشويش الترويسات المطوية `\x0b` |
| **إعادة التوجيه المفتوحة** | عناوين URL نسبية للبروتوكول `//evil.com`، بروتوكولات زائفة `javascript:/data:` |
| **تجاوز CORS** | `Origin: null`، حقن ترويسات `Access-Control-Allow-*` |
| **اختطاف WebSocket** | حقن ترويسة Upgrade، تجاوز Origin فارغ، عناوين `ws://` |
| **إعادة ربط DNS** | عناوين IP داخلية في ترويسة Host، localhost، أسماء مضيفين قصيرة بلا TLD |

### التحقق من طبقة بروتوكول HTTP (7)
| **عمق تداخل JSON** | مسح تدفقي عبر `json.Decoder`: يُعتبر قنبلة JSON عند تجاوز عمق التداخل أو عدد العناصر الحدّ (العمق الافتراضي 32)؛ لا يُنبّه على JSON غير الصالح أو المقطوع |
| **سمات ملف تعريف الارتباط** | يرصد `Set-Cookie` عند غياب `Secure`/`HttpOnly`/`SameSite` أو تجاوز طول القيمة أو كونها فارغة؛ وتُجمع السمات الغائبة في نتيجة واحدة |

| الكاشف | الوصف |
|--------|------|
| **طريقة HTTP** | يُسمح فقط بـ GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH، أي طريقة أخرى تُطلق إنذارًا |
| **حجم جسم الطلب** | تجاوز الحد الأقصى (افتراضيًا 10MB) يُطلق إنذارًا |
| **Content-Type** | يُسمح فقط بأنواع MIME الموجودة في القائمة البيضاء المُهيأة |
| **CSRF Origin** | يتحقق من تطابق Origin مع Host للطلبات عبر النطاقات، مع دعم قائمة بيضاء إضافية |
| **القائمة السوداء للـ IP** | حظر تلقائي بعد N من الهجمات خلال نافذة زمنية (افتراضيًا 5 مرات/60 ثانية ← حظر 15 دقيقة)، مع دعم تخزين File/Redis/Memory |

### هجمات البيانات والتحويل التسلسلي (5)

| الكاشف | أنماط الكشف |
|--------|---------|
| **إلغاء تسلسل** | كائنات متسلسلة `O:رقم:` / `C:رقم:`، `unserialize()`، الطرق السحرية (`__wakeup`/`__destruct`)؛ يغطي حِزم PHP / pickle / Java / .NET |
| **حقن CSV** | `=cmd\|`، `@SUM(`، بادئات الصيغ `+`/`-`، `HYPERLINK`/`DDE` |
| **حقن ترويسات البريد** | حقن Bcc/Cc/From/To، MIME multipart، معامل boundary |
| **هجوم JWT** | تجاوز `alg: none`، اجتياز المسار عبر `kid`، كشف التوقيع الفارغ (تحليل فك البنية) |
| **تلوث النماذج الأولية** | مفاتيح `__proto__`/`constructor`، `__defineGetter__`/`__defineSetter__` |

### الملفات والبيانات الحساسة (3)

| الكاشف | أنماط الكشف |
|--------|---------|
| **اجتياز المسار** | `../`، `..\\`، `php://filter`/`php://input`، البايت الفارغ، التفاف عبر ترميز URL، `/etc/passwd` |
| **الرفع الخبيث** | قائمة بيضاء للامتدادات (15 نوعًا) + فحص محتوى وسوم PHP `<?php`/`<?=` |
| **تسريب البيانات** | أرقام بطاقات الائتمان، AWS Access Key، المفاتيح الخاصة `-----BEGIN`، سلاسل اتصال قواعد البيانات، API Token، JWT Secret، GitHub PAT |

### أمان الجلسات (2)

| الكاشف | أنماط الكشف |
|--------|---------|
| **حارس الجلسة** (`session_guard`) | ربط الـ token بالعميل عند إنشاء الجلسة، ويُقارن مع كل طلب: تغيّر User-Agent أو بصمة الجهاز يُحكم بـ**اختطاف العميل** (Critical)؛ وقوع عنوان IP للعميل في نطاق شبكة أو بلد آخر يُحكم بـ**تسجيل الدخول من موقع بعيد** (High/Critical)؛ يقارن `Observe()` عند تسجيل الدخول النطاقات السابقة، ويُنبّه عند ظهور نطاق جديد. تجديد الجلسة المنزلق، و`Revoke()` يُبطلها فورًا؛ يحصي `RecordFailure()` المحاولات الفاشلة ويقفل الرمز عند بلوغ الحد داخل النافذة، ويُبلّغ `Check()` بالسبب `token_locked`، ويصفّر `ClearFailures()` العدّاد عند نجاح تسجيل الدخول؛ ويرصد `CheckLogin()` أيضًا حشو بيانات الاعتماد (فشل عميل واحد أمام هويات مختلفة كثيرة يُبلّغ `credential_stuffing`)، ويتضاعف القفل مع كل تكرار حتى 24 ساعة |
| **التلاعب بالبيانات** (`data_tamper`) | توقيع HMAC-SHA256 لمعاملات الطلب (`الطابع الزمني.nonce.التوقيع`)، لكشف تعديل المعاملات، وعدم تطابق المفتاح، وتجاوز الطابع الزمني، وإعادة إرسال التوقيع (عدّاد nonce) |

### واجهات التخزين الخلفية (3)

| الواجهة الخلفية | الوصف |
|------|------|
| **Memory** | `sync.Mutex` + map، تنظيف تلقائي للعناصر المنتهية كل 30 ثانية |
| **File** | استمرارية عبر ملفات JSON، مع flush عند Close |
| **Redis** | وحدة فرعية مستقلة، Pipeline Incr + TTL، يتطلب `go-redis/v9` |

## هيكل المشروع

```
security-go/
├── security.go            # النواة: Result / Severity / واجهة Detector / سجل Engine
├── injection/             # كاشفات الحقن (10): xss, sql, command, nosql, ldap,
│                          #   xpath, jndi, ssi, graphql, ssti
├── protocol/              # كاشفات البروتوكول والطلبات (9): ssrf, xxe, header, host,
│                          #   smuggling, redirect, cors, websocket, dns_rebinding
├── data/                  # كاشفات البيانات والتسلسل (5): deserialization, csv,
│                          #   mail, jwt, prototype_pollution
├── file/                  # كاشفات الملفات والبيانات الحساسة (3): path_traversal,
│                          #   upload, data_leak
├── httpval/               # مُدقّقات بروتوكول HTTP (7)، كل منها يحتاج إعدادات من التطبيق
├── session/               # أمان الجلسات (2): session_guard, data_tamper
│                          #   تتجاوز محرّك Engine وتُستخدم مباشرة كوسيط (middleware)
├── storage/               # واجهات التخزين الخلفية
│   ├── storage.go         #   واجهة الواجهة الخلفية: Incr / Get / Block / IsBlocked / Close
│   ├── memory.go          #   Memory: Mutex + map، تنظيف خلفي كل 30 ثانية
│   ├── file.go            #   File: استمرارية JSON، مع flush عند الإغلاق
│   └── redis/             #   Redis: وحدة فرعية مستقلة بملف go.mod خاص بها
├── all/                   # تسجيل الكاشفات الـ 27 بلا تكوين في نداء واحد
├── pet/                   # تميمة المشروع: SVG مُضمَّن + شعار بدء التشغيل
├── docs/
│   ├── api.md             # مرجع واجهة API
│   ├── images/            # رسومات SVG للبنية / الوظائف / دورة الحياة
│   ├── i18n/              # توثيق مترجم (12 لغة)
│   └── superpowers/       # مواصفات التصميم، خطة التنفيذ، تقارير مراجعة الكود
└── tests/                 # تقارير التغطية
```

يقترن كل كاشف بملف `xxx.go` مع `xxx_test.go`؛ وتضم حزمة `all` إضافة إلى ذلك اختبارات انحدار.

## دليل الاستخدام

### التثبيت

```bash
go get github.com/erikwang2013/security-go
```

### بدء سريع

```go
package main

import (
    "fmt"
    "github.com/erikwang2013/security-go"
    "github.com/erikwang2013/security-go/all"
)

func main() {
    e := security.NewEngine()
    all.RegisterAll(e) // يسجّل الكاشفات الـ 27 بلا تكوين دفعة واحدة

    // كشف فردي
    r := e.Detect("xss", "<script>alert(1)</script>")
    fmt.Printf("تم الكشف: %v, الخطورة: %d\n", r.Detected, r.Severity)

    // كشف شامل
    for _, r := range e.DetectAll("' OR '1'='1") {
        fmt.Printf("[%s] %s\n", r.Name, r.Message)
    }
}
```

### كشف طلبات HTTP

```go
func handler(w http.ResponseWriter, r *http.Request) {
    e := security.NewEngine()
    all.RegisterAll(e)

    for _, result := range e.DetectRequest(r) {
        if result.Detected {
            log.Printf("تم اكتشاف هجوم: [%s] %s", result.Name, result.Message)
        }
    }
}
```

### تكوين مُدقّق HTTP

```go
// التحقق من الطريقة
e.Register(&httpval.Method{})

// حد حجم جسم الطلب
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// قائمة Content-Type البيضاء
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// فحص CSRF Origin
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// القائمة السوداء للـ IP (حظر تلقائي: 5 هجمات/60 ثانية ← حظر 15 دقيقة)
mem := storage.NewMemory()
defer mem.Close()
bl := httpval.NewIPBlacklist(mem)
e.Register(bl)

// تسجيل الهجوم
blocked, _ := bl.RecordAttack(clientIP)
```

### تكوين أمان الجلسات

تُستخدم حزمة `session` مباشرة كوسيط (middleware)، دون المرور عبر `Engine`. يجب أن يوفّر التطبيق التخزين بنفسه (يُوفَّر تنفيذ بالذاكرة افتراضيًا، ويمكن استبداله بـ Redis أو غيره):

```go
import "github.com/erikwang2013/security-go/session"

st := session.NewMemoryStore()
defer st.Close()

tr := session.NewTracker(st)
tr.CountryOf = geo.Lookup // اختياري: ربط GeoIP لرصد تسجيل الدخول عبر الدول

// ربط الجلسة بعد نجاح تسجيل الدخول (token يأتي من عملية تسجيل الدخول لديك)
// كشف تسجيل الدخول من موقع بعيد: قارن مع النطاقات السابقة للمستخدم ونبّه عند ظهور نطاق جديد
if res := tr.Observe("user-1", r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
if err := tr.Issue(token, r); err != nil {      // ربط token → نطاق IP / UA / بصمة الجهاز
    http.Error(w, "session error", http.StatusInternalServerError)
    return
}

// حماية المسارات: إرجاع 401 عند الاختطاف أو تسجيل الدخول من موقع بعيد
mux.Handle("/api/", tr.Guard(apiHandler))

// أو اكتشف فقط وقرّر الإجراء بنفسك
if res := tr.Check(r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}

// تسجيل الخروج
tr.Revoke(token)
```

كشف التلاعب بالبيانات: يشارك العميل والخادم مفتاحًا واحدًا، يوقّع العميل المعاملات، ويعيد الخادم حسابها للتحقق:

```go
signer := session.NewSigner(secret, storage.NewMemory()) // المعامل الثاني يمنع إعادة إرسال التوقيع، ويمكن أن يكون nil

sig, _ := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // العميل: أرسله مع المعاملات

if res := signer.Verify(map[string]string{"amount": "100", "to": "bob"}, sig); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
```

> `TrustProxyHeaders` معطّل افتراضيًا: `X-Forwarded-For` / `X-Real-IP` يتحكم بهما العميل، لذا لا تفعّله إلا خلف وكيل عكسي تملكه.
> `FailClosed` معطّل افتراضيًا (السماح عند فشل التخزين، متوافق مع `IPBlacklist`)؛ ويُستحسن تفعيله للأنشطة الحساسة للجلسات.

### كاشف مخصص

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

### التميمة

تُضمِّن حزمة `pet` تميمة Sentinel Gopher كـ SVG في وقت الترجمة عبر `go:embed` — دون أي اعتماد على ملفات وقت التشغيل، ودون إضافة أي اعتماد خارجي:

```go
import "github.com/erikwang2013/security-go/pet"

log.Println(pet.Banner())              // شعار بدء التشغيل: نص عادي مناسب للطرفية
http.Handle("/pet.svg", pet.Handler()) // مسار تنقيح: يُقدَّم كـ image/svg+xml ويُخزَّن مؤقتًا ليوم واحد
svg := pet.SVG()                       // أو خذ بايتات SVG الخام
```

### المستندات ذات الصلة

- [وثيقة واجهة API](api.md) — الأنواع الأساسية، واجهتا Detector/Engine، واجهة التخزين الخلفي، مُدقّقات HTTP
- [مواصفات التصميم](specs/2026-07-29-attack-detection-design.md) — بنية الحزمة، فهرس الكاشفات
- [خطة التنفيذ](plans/2026-07-29-attack-detection-plan.md) — خطة المهام المرحلية ومقارنة انحرافات التنفيذ
- [تقرير مراجعة الكود](reports/2026-07-29-code-review-report.md) — إصلاحات الأخطاء، تغطية الاختبارات، تقييم البنية
- [تقرير مراجعة الكود v2](reports/2026-07-29-code-review-report-v2.md) — الجولة الثانية: إصلاح 4 مشكلات، وإضافة 18 ملف اختبار

---

## مستندات متعددة اللغات

| اللغة | المستند |
|------|------|
| 简体中文 | [README.md](../../../README.md) |
| English | [README-EN.md](../../../README-EN.md) · [docs/i18n/en/README.md](../en/README.md) |
| 한국어 | [docs/i18n/ko/README.md](../ko/README.md) |
| Русский | [docs/i18n/ru/README.md](../ru/README.md) |
| Deutsch | [docs/i18n/de/README.md](../de/README.md) |
| Français | [docs/i18n/fr/README.md](../fr/README.md) |
| Español | [docs/i18n/es/README.md](../es/README.md) |
| Português | [docs/i18n/pt/README.md](../pt/README.md) |
| हिन्दी | [docs/i18n/hi/README.md](../hi/README.md) |
| العربية | [README.md](README.md) |
| বাংলা | [docs/i18n/bn/README.md](../bn/README.md) |
| Bahasa Indonesia | [docs/i18n/id/README.md](../id/README.md) |
| 日本語 | [docs/i18n/ja/README.md](../ja/README.md) |

- [فهرس المستندات متعددة اللغات](../README.md)

---

## دعم التبرعات

إذا كان هذا المشروع مفيدًا لك، فنرحّب بتبرعك دعماً له:

| الطريقة | رمز الاستجابة السريعة |
|------|--------|
| Alipay (علي باي) | ![Alipay](images/alipay.png) |
| WeChat Pay (وي تشات باي) | ![WeChat Pay](images/weixinpay.png) |

### تبرع عبر التحويل المصرفي الدولي (حوالة بنكية)

**معلومات المستفيد**

- اسم المستفيد: WANG KEXUN
- رقم حساب المستفيد: 881015918251

**البنك المستفيد (ZA Bank)**

- رمز SWIFT: `AABLHKHHXXX`
- اسم البنك: ZA Bank Limited
- رقم البنك: 387
- عنوان البنك: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

**البنك الوسيط للتحويلات الدولية (عند الحاجة)**

> يُرجى الانتباه: هذه معلومات البنك الوسيط (بنك التحويل) للتحويلات الدولية، وليست معلومات البنك المستفيد. يُرجى الاستفسار من البنك المُرسِل عما إذا كان مطلوبًا تقديم معلومات البنك الوسيط للتحويلات الدولية.

- البنك الوسيط لتحويلات الدولار الهونغ كونغي (HKD) واليوان (CNY) والدولار الأمريكي (USD) هو Citibank:
  - اسم البنك: Citibank N.A. Hong Kong
  - رمز SWIFT: `CITIHKHXXXX`
  - رقم البنك: 006
  - اسم الفرع: Hong Kong Branch
  - رقم الفرع: 391
  - عنوان البنك: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong
- البنك الوسيط للعملات الأخرى هو BNY Mellon:
  - اسم البنك: THE BANK OF NEW YORK MELLON
  - رمز SWIFT: `IRVTUS3NXXX`
  - عنوان البنك: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## English

See [README-EN.md](../../../README-EN.md) for the full English documentation.

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

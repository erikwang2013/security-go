# Security Go — مكتبة كشف الهجمات

[简体中文](../../../README.md) · [English](../../../README-EN.md)

حزمة كشف الهجمات المكتوبة بلغة Go، تغطي **32 كاشفًا** و**5 فئات هجمات رئيسية** و**3 واجهات خلفية للتخزين قابلة للتوصيل**. واجهة موحّدة + نمط سجلّات (Registry)، مكتبة كشف خالصة، متوافقة مع أي إطار عمل HTTP بلغة Go.

## فلسفة التصميم

### المبادئ الأساسية

- **كشف بدون اعتماديات** — تستخدم جميع الكاشفات مكتبة Go القياسية `regexp` فقط، بدون أي اعتماديات خارجية
- **واجهة موحّدة** — ينفّذ كل كاشف واجهة `Detector` (`Name()` + `Detect()`)، وتُدار بشكل موحّد عبر سجل `Engine`
- **تعبيرات نمطية مُجمّعة مسبقًا** — تُجمّع جميع الأنماط عند تهيئة `var`، بصفر تكلفة وقت تشغيل
- **تكوين حسب الحاجة** — كاشفات الحقن/البروتوكول/البيانات/الملفات جاهزة للاستخدام الفوري؛ بينما تتطلب مُدقّقات HTTP تكوينًا من التطبيق

### بنية التصميم

```
                         ┌───────────────────────────────┐
                         │        security.Engine         │
                         │  ┌─────────────────────────┐  │
                         │  │    Detector Registry     │  │
                         │  │   map[string]Detector    │  │
                         │  └─────────────────────────┘  │
                         │                               │
                         │  Detect(name, input)          │
                         │  DetectAll(input)             │
                         │  DetectRequest(*http.Request) │
                         └──────────────┬────────────────┘
                                        │
          ┌─────────────────┬───────────┴───────────┬─────────────────┐
          │                 │                       │                 │
   ┌──────▼──────┐   ┌──────▼──────┐   ┌────────────▼────────┐   ┌───▼───────────┐
   │  injection  │   │  protocol   │   │        data         │   │     file      │
   │   (10 个)   │   │   (9 个)    │   │       (5 个)        │   │    (3 个)     │
   │             │   │             │   │                     │   │               │
   │  xss, sql,  │   │  ssrf, xxe, │   │  deser, csv,        │   │  traversal,   │
   │  command,   │   │  header,    │   │  mail, jwt,         │   │  upload,      │
   │  nosql,     │   │  host,      │   │  proto_poll         │   │  data_leak    │
   │  ldap,      │   │  smuggling, │   │                     │   │               │
   │  xpath,     │   │  redirect,  │   │                     │   │               │
   │  jndi, ssi, │   │  cors, ws,  │   │                     │   │               │
   │  graphql,   │   │  dns_rebind │   │                     │   │               │
   │  ssti       │   │             │   │                     │   │               │
   └─────────────┘   └─────────────┘   └─────────────────────┘   └───────────────┘
                                                                          │
          ┌───────────────────────────────────────────────────────────────┤
          │                                                               │
   ┌──────▼──────────┐                                         ┌──────────▼──────────┐
   │     httpval     │                                         │       storage       │
   │     (5 个)      │                                         │  ┌──────────────┐   │
   │                 │                                         │  │   Backend    │   │
   │  method, size,  │                                         │  │   interface  │   │
   │  type, csrf,    │                                         │  └──┬───┬───┬───┘   │
   │  ip_blacklist   │◄────── 使用 storage.Backend ──────────►│  Memory File Redis │
   │  (需配置参数)    │                                         │                    │
   └─────────────────┘                                         └────────────────────┘
```

### تدفق البيانات

```
HTTP Request
     │
     ▼
┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│ collectInputs│────▶│  DetectAll()    │────▶│  []*Result   │
│ URL, Query,  │     │  逐个检测器调用   │     │  聚合结果     │
│ Headers,     │     │  Detect(input)  │     │              │
│ Cookies      │     └─────────────────┘     └──────────────┘
└──────────────┘
```

### مستويات الخطورة

| المستوى | الوصف | سيناريو نموذجي |
|------|------|---------|
| `SeverityLow` | خطورة منخفضة | طريقة HTTP غير قانونية، عدم تطابق Content-Type |
| `SeverityMedium` | خطورة متوسطة | مشكلات إعدادات CORS، إعادة توجيه مفتوحة، استكشاف GraphQL |
| `SeverityHigh` | خطورة عالية | XSS، حقن SQL، SSRF، اجتياز المسار |
| `SeverityCritical` | خطورة حرجة | حقن الأوامر، JNDI، SSTI، XXE، تسريب البيانات |

## الوظائف المنفّذة

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

### التحقق من طبقة بروتوكول HTTP (5)

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
| **إلغاء تسلسل PHP** | كائنات متسلسلة `O:رقم:` / `C:رقم:`، `unserialize()`، الطرق السحرية (`__wakeup`/`__destruct`) |
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

### واجهات التخزين الخلفية (3)

| الواجهة الخلفية | الوصف |
|------|------|
| **Memory** | `sync.Mutex` + map، تنظيف تلقائي للعناصر المنتهية كل 30 ثانية |
| **File** | استمرارية عبر ملفات JSON، مع flush عند Close |
| **Redis** | وحدة فرعية مستقلة، Pipeline Incr + TTL، يتطلب `go-redis/v9` |

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
    all.RegisterAll(e) // 一键注册 27 个零配置检测器

    // 单个检测
    r := e.Detect("xss", "<script>alert(1)</script>")
    fmt.Printf("检测到: %v, 严重程度: %d\n", r.Detected, r.Severity)

    // 全量检测
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
            log.Printf("攻击检测: [%s] %s", result.Name, result.Message)
        }
    }
}
```

### تكوين مُدقّق HTTP

```go
// 方法校验
e.Register(&httpval.Method{})

// 请求体大小限制
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type 白名单
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF Origin 检查
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP 黑名单（自动封禁：5次/60s → 封禁15分钟）
mem := storage.NewMemory()
defer mem.Close()
bl := httpval.NewIPBlacklist(mem)
e.Register(bl)

// 攻击发生时记录
blocked, _ := bl.RecordAttack(clientIP)
```

### كاشف مخصص

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

### المستندات ذات الصلة

- [وثيقة واجهة API](api.md) — الأنواع الأساسية، واجهتا Detector/Engine، واجهة التخزين الخلفي، مُدقّقات HTTP
- [مواصفات التصميم](specs/2026-07-29-attack-detection-design.md) — بنية الحزمة، فهرس الكاشفات
- [خطة التنفيذ](plans/2026-07-29-attack-detection-plan.md) — خطة المهام المرحلية ومقارنة انحرافات التنفيذ
- [تقرير مراجعة الكود](reports/2026-07-29-code-review-report.md) — إصلاحات الأخطاء، تغطية الاختبارات، تقييم البنية

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

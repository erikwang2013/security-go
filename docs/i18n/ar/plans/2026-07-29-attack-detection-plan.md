# حزمة كشف الهجمات — خطة التنفيذ

> **للعاملين الآليين (agentic workers):** المهارة الفرعية المطلوبة: استخدم superpowers:subagent-driven-development (موصى به) أو superpowers:executing-plans لتنفيذ هذه الخطة مهمةً تلو الأخرى.

**الهدف:** بناء مكتبة كشف هجمات خالصة بلغة Go تضم 32 كاشفًا عبر 5 فئات، و3 واجهات تخزين خلفية قابلة للتوصيل، وسجل Engine موحّد. **الحالة: مكتملة (2026-07-29).**

**البنية:** تصميم واجهة مسطّح — كل كاشف ينفّذ `Detector` (Name + Detect). أنماط regex مُجمّعة مسبقًا. يوفر Engine السجلّ والبحث بالاسم و`DetectRequest` لفحص طلبات HTTP الكاملة. توجد RegisterAll في `all/all.go` (حزمة منفصلة).

**مجموعة التقنيات:** Go 1.21+، مكتبة `regexp` القياسية + `net/http`، `go-redis` للواجهة الخلفية لـ Redis (وحدة فرعية اختيارية في `storage/redis/`).

---

### المهمة 1: تهيئة وحدة Go والأنواع الأساسية

**الملفات:**
- إنشاء: `go.mod`
- إنشاء: `security.go`

- [x] **الخطوة 1: تهيئة وحدة Go**

```bash
cd /home/wwwroot/bag/security-go && go mod init github.com/erikwang2013/security-go
```

- [x] **الخطوة 2: إنشاء security.go — Result, Severity, Detector interface, Engine**

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

- [x] **الخطوة 3: البناء** — `go build ./...`
- [x] **الخطوة 4: الالتزام (Commit)** — `feat: initialize Go module with core types and Engine`

---

### المهمة 2: واجهة التخزين الخلفي والذاكرة

**الملفات:**
- إنشاء: `storage/storage.go`
- إنشاء: `storage/memory.go`

- [x] **الخطوة 1: storage/storage.go** — واجهة Backend (Incr, Get, Block, IsBlocked, Close)
- [x] **الخطوة 2: storage/memory.go** — تنفيذ مبني على sync.Map مع goroutine لحذف TTL
- [x] **الخطوة 3: البناء** — `go build ./storage/...`
- [x] **الخطوة 4: الالتزام** — `feat: add storage interface and memory backend`

---

### المهمة 3: التخزين عبر الملفات و Redis

**الملفات:**
- إنشاء: `storage/file.go`
- إنشاء: `storage/redis.go`
- تعديل: `go.mod` (إضافة اعتماد go-redis)

- [x] **الخطوة 1: storage/file.go** — استمرارية عبر ملفات JSON مع flush كسول
- [x] **الخطوة 2: storage/redis.go** — واجهة Redis الخلفية باستخدام go-redis/v9
- [x] **الخطوة 3: البناء** — `go build ./storage/...`
- [x] **الخطوة 4: الالتزام** — `feat: add file and redis storage backends`

---

### المهمة 4: كاشفات الحقن — XSS, SQL

**الملفات:**
- إنشاء: `injection/xss.go`
- إنشاء: `injection/sql.go`

- [x] **الخطوة 1: injection/xss.go** — `<script>`, `on[a-z]+=`, `javascript:`, أنماط SVG/CSS
- [x] **الخطوة 2: injection/sql.go** — UNION SELECT (مع التفاف `/**/`), sleep/benchmark, الحقن الأعمى المنطقي, تعداد المخطط, الإجراءات المخزنة
- [x] **الخطوة 3: البناء** — `go build ./injection/...`
- [x] **الخطوة 4: الالتزام** — `feat: add XSS and SQL injection detectors`

---

### المهمة 5: كاشفات الحقن — Command, NoSQL, LDAP, XPATH

**الملفات:**
- إنشاء: `injection/command.go`
- إنشاء: `injection/nosql.go`
- إنشاء: `injection/ldap.go`
- إنشاء: `injection/xpath.go`

- [x] **الخطوة 1: injection/command.go** — backtick, `$()`, أنابيب, `/dev/tcp`, دوال PHP exec
- [x] **الخطوة 2: injection/nosql.go** — MongoDB `$ne`/`$gt`/`$regex`/`$where`, تجاوز المصادقة
- [x] **الخطوة 3: injection/ldap.go** — عوامل تشغيل الفلترة `(`, `)`, `&`, `|`, `*`
- [x] **الخطوة 4: injection/xpath.go** — التفاف منطقي, string-length, count
- [x] **الخطوة 5: البناء والالتزام**

---

### المهمة 6: كاشفات الحقن — JNDI, SSI, GraphQL, SSTI

**الملفات:**
- إنشاء: `injection/jndi.go`
- إنشاء: `injection/ssi.go`
- إنشاء: `injection/graphql.go`
- إنشاء: `injection/ssti.go`

- [x] **الخطوة 1: injection/jndi.go** — `${jndi:ldap://`, `${lower:j}`, `${env:}`, بروتوكولات rmi/dns
- [x] **الخطوة 2: injection/ssi.go** — `<!--#exec`, `<!--#include`, `<!--#echo`
- [x] **الخطوة 3: injection/graphql.go** — `__schema`, `__type`, استعلامات متداخلة عميقة, mutation
- [x] **الخطوة 4: injection/ssti.go** — Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO
- [x] **الخطوة 5: البناء والالتزام**

---

### المهمة 7: كاشفات البروتوكول — SSRF, XXE, حقن الترويسات

**الملفات:**
- إنشاء: `protocol/ssrf.go`
- إنشاء: `protocol/xxe.go`
- إنشاء: `protocol/header_injection.go`

- [x] **الخطوة 1: protocol/ssrf.go** — عناوين IP الداخلية, 169.254.169.254, IPv6 loopback, gopher/dict
- [x] **الخطوة 2: protocol/xxe.go** — `<!ENTITY SYSTEM/PUBLIC`, الكيانات المعلمية, DOCTYPE
- [x] **الخطوة 3: protocol/header_injection.go** — CRLF, حقن Set-Cookie/Location
- [x] **الخطوة 4: البناء والالتزام**

---

### المهمة 8: كاشفات البروتوكول — Host Header, Request Smuggling, Open Redirect, CORS, WebSocket, DNS Rebinding

**الملفات:**
- إنشاء: `protocol/host_header.go`
- إنشاء: `protocol/request_smuggling.go`
- إنشاء: `protocol/open_redirect.go`
- إنشاء: `protocol/cors.go`
- إنشاء: `protocol/websocket.go`
- إنشاء: `protocol/dns_rebinding.go`

- [x] **الخطوة 1: كاشفات البروتوكول الستة جميعها** — ملف لكل منها، أنماط regex مُجمّعة مسبقًا
- [x] **الخطوة 2: البناء والالتزام**

---

### المهمة 9: كاشفات التحقق من HTTP

**الملفات:**
- إنشاء: `httpval/method.go`
- إنشاء: `httpval/body_size.go`
- إنشاء: `httpval/content_type.go`
- إنشاء: `httpval/csrf_origin.go`
- إنشاء: `httpval/ip_blacklist.go`

- [x] **الخطوة 1: httpval/method.go** — القائمة البيضاء GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH
- [x] **الخطوة 2: httpval/body_size.go** — فحص الحد الأقصى للحجم، الافتراضي 10MB
- [x] **الخطوة 3: httpval/content_type.go** — القائمة البيضاء لـ MIME
- [x] **الخطوة 4: httpval/csrf_origin.go** — مطابقة Origin مع Host للطلبات عبر النطاقات
- [x] **الخطوة 5: httpval/ip_blacklist.go** — حد النافذة الزمنية (5/60s ← حظر 15 دقيقة)، يستخدم storage.Backend
- [x] **الخطوة 6: البناء والالتزام**

---

### المهمة 10: كاشفات البيانات/التحويل التسلسلي

**الملفات:**
- إنشاء: `data/deserialization.go`
- إنشاء: `data/csv_injection.go`
- إنشاء: `data/mail_header.go`
- إنشاء: `data/jwt_attack.go`
- إنشاء: `data/prototype_pollution.go`

- [x] **الخطوة 1: data/deserialization.go** — PHP `O:رقم:`, `C:رقم:`, unserialize(), الطرق السحرية
- [x] **الخطوة 2: data/csv_injection.go** — بادئات الصيغ `=cmd|`, `@SUM(`, `+`, `-`
- [x] **الخطوة 3: data/mail_header.go** — حقن Bcc/Cc/From/To, MIME multipart
- [x] **الخطوة 4: data/jwt_attack.go** — alg:none, اجتياز المسار عبر kid, التوقيع الفارغ (فك البنية)
- [x] **الخطوة 5: data/prototype_pollution.go** — `__proto__`, `constructor`, `__defineGetter__/Setter__`
- [x] **الخطوة 6: البناء والالتزام**

---

### المهمة 11: كاشفات الملفات والبيانات الحساسة

**الملفات:**
- إنشاء: `file/path_traversal.go`
- إنشاء: `file/upload.go`
- إنشاء: `file/data_leak.go`

- [x] **الخطوة 1: file/path_traversal.go** — `../`, `..\\`, php://filter, البايت الفارغ, التفاف عبر ترميز URL
- [x] **الخطوة 2: file/upload.go** — القائمة البيضاء للامتدادات + فحص محتوى وسوم PHP
- [x] **الخطوة 3: file/data_leak.go** — بطاقات الائتمان, مفتاح AWS, المفاتيح الخاصة, سلسلة اتصال DB, API token, JWT secret
- [x] **الخطوة 4: البناء والالتزام**

---

### المهمة 12: تكامل Engine — RegisterAll

**الملفات:**
- تعديل: `security.go`

- [x] **الخطوة 1: إضافة RegisterAll()** — تسجيل الكاشفات المدمجة الـ 32 جميعها
- [x] **الخطوة 2: البناء** — `go build ./...`
- [x] **الخطوة 3: الالتزام** — `feat: add RegisterAll for built-in detectors`

---

### المهمة 13: الاختبارات

**الملفات:**
- إنشاء: `security_test.go`
- إنشاء: `injection/xss_test.go`, `sql_test.go`, `jndi_test.go`, `ssti_test.go`
- إنشاء: `protocol/ssrf_test.go`
- إنشاء: `file/path_traversal_test.go`, `data_leak_test.go`
- إنشاء: `data/jwt_attack_test.go`
- إنشاء: `storage/memory_test.go`

- [x] **الخطوة 1: كتابة الاختبارات** — لكل منها حالات اختبار موجبة وسالبة
- [x] **الخطوة 2: التشغيل** — `go test ./... -v`
- [x] **الخطوة 3: الالتزام** — `test: add core engine and detector tests`

---

### المهمة 14: مراجعة الكود بعد التنفيذ والإصلاحات (2026-07-29)

- [x] **مراجعة كود شاملة** — 42 ملف مصدر Go، 8 حزم
- [x] **إصلاح الخطأ #1** — `storage/file.go`: خطأ تسلسل JSON كان يُتجاهل بصمت → تغييره إلى فحص الخطأ وإرجاعه
- [x] **إصلاح الخطأ #2** — `httpval/content_type.go`: قائمة AllowList فارغة كانت تسمح بكل أنواع Content-Type → القيمة الافتراضية رفض الكل (deny-all)
- [x] **إصلاح الخطأ #3** — `protocol/xxe.go`: `&[a-z]+;` كان يطابق كيانات HTML القانونية خطأً → تقليصه إلى قائمة البروتوكولات الخبيثة المعروفة
- [x] **كتابة اختبارات httpval** — 32 حالة اختبار تغطي 5 كاشفات (BodySize, ContentType, CSRFOrigin, IPBlacklist, Method)
- [x] **الاختبارات الكاملة** — `go test -count=1 ./...` مرّت 7/7 حزم، `go vet` بصفر تحذيرات

---

## الانحرافات الفعلية عن المخطط

| المخطط | الفعلي | السبب |
|------|------|------|
| RegisterAll في `security.go` | حزمة مستقلة `all/all.go` | تجنب الاستدعاء الدائري؛ يعتمد httpval على storage بينما لا تعتمد الكاشفات الأخرى |
| Redis في go.mod الجذر | وحدة فرعية `storage/redis/` | عزل الاعتماديات الاختيارية |
| توحيد Receiver على المؤشرات | حزمة protocol تستخدم مستقبلات القيمة | ✅ جرى التحويل الكامل إلى مستقبلات المؤشر في مراجعة v2 |
| المهام 4-12 بناء والتزام | لم تُلتزم على مراحل | تنفيذ كل الكود دفعة واحدة |

## ملخص تغطية الاختبارات

| الحزمة | ملفات الاختبار | عدد الاختبارات |
|----|---------|--------|
| security | security_test.go | 5 |
| data | deserialization_test.go, csv_injection_test.go, mail_header_test.go, jwt_attack_test.go, prototype_pollution_test.go | 8 |
| file | path_traversal_test.go, data_leak_test.go, upload_test.go | 5 |
| httpval | httpval_test.go | 32 |
| injection | xss_test.go, sql_test.go, command_test.go, nosql_test.go, ldap_test.go, xpath_test.go, jndi_test.go, ssi_test.go, graphql_test.go, ssti_test.go | 10 |
| protocol | ssrf_test.go, xxe_test.go, header_injection_test.go, host_header_test.go, request_smuggling_test.go, open_redirect_test.go, cors_test.go, websocket_test.go, dns_rebinding_test.go | 9 |
| storage | memory_test.go | 4 |
| all | (لا يوجد) | 0 |

> التقرير الكامل: [تقرير مراجعة الكود v2](../reports/2026-07-29-code-review-report-v2.md)

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

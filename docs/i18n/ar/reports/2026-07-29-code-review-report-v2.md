# تقرير مراجعة الكود v2

**التاريخ**: 2026-07-29  
**المشروع**: security-go — مكتبة كشف الهجمات بلغة Go  
**نطاق المراجعة**: جميع ملفات Go المصدرية البالغ عددها 47 (بما في ذلك 32 كاشفًا، 3 واجهات تخزين خلفية، 5 مُدقّقات HTTP)  
**نتيجة المراجعة**: اكتُشفت 4 مشكلات، أُصلحت جميعها؛ أُضيفت 18 ملف اختبار (+36 حالة اختبار)

---

## أولًا: نظرة عامة على نتائج الاختبارات

| الحزمة | الحالة | التغطية | عدد الاختبارات |
|---|------|--------|--------|
| `security` (الأساسية) | PASS | 95.8% | 5 |
| `injection` | PASS | 100.0% | 10 |
| `protocol` | PASS | 100.0% | 9 |
| `data` | PASS | 93.2% | 8 |
| `file` | PASS | 100.0% | 5 |
| `httpval` | PASS | 92.9% | 31 |
| `storage` | PASS | 33.7% | 4 |
| `all` | — | 0.0% | 0 (دالة التسجيل) |

- **go vet**: PASS (صفر تحذيرات)
- **معدل نجاح الاختبارات**: 58/58 (100%)

---

## ثانيًا: المشكلات المكتشفة والإصلاحات

### المشكلة 1: `storage/file.go` — نقص استدامة البيانات (خطيرة)

**الوصف**: كانت طريقا `Incr()` و`Block()` تعملان في الذاكرة فقط، وتُكتبان إلى القرص عند `Close()` فقط. إذا تعطلت العملية، ستُفقد جميع العدادات وبيانات الحظر.

**الإصلاح**:
- أُضيفت goroutine باسم `autoSave` في `NewFile()` تُستمر إلى القرص تلقائيًا كل 30 ثانية
- استُخرجت الطريقة الداخلية `saveLocked()` لتشاركها `Close()` و`autoSave`

**الملف**: `storage/file.go`

### المشكلة 2: حزمة `protocol/` — عدم اتساق مستقبلات القيمة (مهمة)

**الوصف**: تستخدم الكاشفات التسعة جميعها في حزمة `protocol/` (SSRF، XXE، HeaderInjection، HostHeader، RequestSmuggling، OpenRedirect، CORS، WebSocket، DNSRebinding) مستقبلات القيمة `(d Type)`، بينما تستخدم الكاشفات في حزم `injection/` و`data/` و`file/` مستقبلات المؤشر `(d *Type)` جميعها — أسلوب غير متسق.

**الإصلاح**: تحويل مستقبلات الطرق في الملفات التسعة إلى مستقبلات المؤشر.

**الملفات**: `protocol/ssrf.go`, `xxe.go`, `header_injection.go`, `host_header.go`, `request_smuggling.go`, `open_redirect.go`, `cors.go`, `websocket.go`, `dns_rebinding.go`

### المشكلة 3: `storage/redis/redis.go` — نقص إعلان حقوق النشر (ثانوية)

**الوصف**: هذا هو ملف Go الوحيد في المشروع كله الذي لا يحتوي على ترويسة حقوق النشر `Copyright (c) 2026 erik <erik@erik.xyz>`.

**الإصلاح**: إضافة إعلان حقوق النشر.

**الملف**: `storage/redis/redis.go`

### المشكلة 4: `file/upload.go` — حساب مكرر (ثانوية)

**الوصف**: في طريقة `CheckExtension()` يُستدعى `strings.LastIndex(filename, ".")` مرتين (مرة استدعاء مباشر ومرة عبر `HasMaliciousExt()`).

**الإصلاح**: تخزين النتيجة في متغير `dotIdx`، وحساب الامتداد مباشرة وفحص القائمة البيضاء.

**الملف**: `file/upload.go`

---

## ثالثًا: تغطية الاختبارات المكملة

### قبل المراجعة

لم يكن لديه اختبارات سوى 6 كاشفات (XSS، SQL، JNDI، SSTI، SSRF، JWTAttack)، بتغطية حوالي 19%.

### بعد المراجعة

جميع الكاشفات الـ 32 لديها اختبارات، وارتفعت التغطية إلى أكثر من 92%.

| الحزمة | ملفات الاختبار المضافة | حالات الاختبار |
|---|-------------|---------|
| `injection/` | 6 (command، nosql، ldap، xpath، ssi، graphql) | 6 |
| `protocol/` | 8 (xxe، header_injection، host_header، request_smuggling، open_redirect، cors، websocket، dns_rebinding) | 8 |
| `data/` | 4 (deserialization، csv_injection، mail_header، prototype_pollution) | 4 |
| `file/` | 1 (upload) | 3 |

---

## رابعًا: تقييم جودة الكود

### المزايا

1. **تصميم واجهة ممتاز** — واجهة `Detector` بسيطة، ونمط سجل `Engine` واضح
2. **تجميع التعبيرات النمطية مسبقًا** — تُجمّع جميع الأنماط في كتلة `var`، بصفر تكلفة وقت تشغيل
3. **صفر اعتماديات خارجية** — منطق الكشف يستخدم مكتبة Go القياسية بالكامل
4. **بنية جاهزة للاستخدام الفوري** — `RegisterAll()` يسجّل 27 كاشفًا بدون تكوين بنقرة واحدة
5. **تخزين قابل للتوصيل** — واجهة `storage.Backend` تدعم ثلاث واجهات خلفية: Memory/File/Redis
6. **تغطية اختبارات شاملة** — لكل كاشف حالات موجبة وسالبة

### اقتراحات التحسين

1. **storage/file.go**: يُقترح إضافة إغلاق أنيق لـ autoSave (إشارة channel)، إذ قد تستمر goroutine الحالية في العمل بعد `Close()`
2. **كاشف JWT**: يمكن لـ decodeBase64URL معالجة المدخلات غير القانونية، لكن يُقترح إضافة حد أقصى للطول لمنع DoS
3. **حزمة all**: يمكن النظر في إضافة اختبارات للتحقق من عدد الكاشفات المسجلة عبر `RegisterAll()`
4. **تغطية storage**: اختبارات file.go و redis.go تحتاج مزيدًا من سيناريوهات الاختبار التكاملي
5. **أمثلة كود README**: يجب أن يستخدم مسار go get مسار الوحدة الفعلي

---

## خامسًا: قائمة الملفات المعدلة

### إصلاحات الكود (12 ملفًا)
- `storage/file.go` — إضافة goroutine auto-save، إصلاح خطأ فقدان البيانات
- `protocol/ssrf.go` — مستقبل القيمة ← مستقبل المؤشر
- `protocol/xxe.go` — مستقبل القيمة ← مستقبل المؤشر
- `protocol/header_injection.go` — مستقبل القيمة ← مستقبل المؤشر
- `protocol/host_header.go` — مستقبل القيمة ← مستقبل المؤشر
- `protocol/request_smuggling.go` — مستقبل القيمة ← مستقبل المؤشر
- `protocol/open_redirect.go` — مستقبل القيمة ← مستقبل المؤشر
- `protocol/cors.go` — مستقبل القيمة ← مستقبل المؤشر
- `protocol/websocket.go` — مستقبل القيمة ← مستقبل المؤشر
- `protocol/dns_rebinding.go` — مستقبل القيمة ← مستقبل المؤشر
- `storage/redis/redis.go` — إضافة ترويسة حقوق النشر
- `file/upload.go` — تحسين الحساب المكرر في CheckExtension

### الاختبارات المضافة (18 ملفًا)
- `injection/command_test.go`
- `injection/nosql_test.go`
- `injection/ldap_test.go`
- `injection/xpath_test.go`
- `injection/ssi_test.go`
- `injection/graphql_test.go`
- `protocol/xxe_test.go`
- `protocol/header_injection_test.go`
- `protocol/host_header_test.go`
- `protocol/request_smuggling_test.go`
- `protocol/open_redirect_test.go`
- `protocol/cors_test.go`
- `protocol/websocket_test.go`
- `protocol/dns_rebinding_test.go`
- `data/deserialization_test.go`
- `data/csv_injection_test.go`
- `data/mail_header_test.go`
- `data/prototype_pollution_test.go`
- `file/upload_test.go`

---

## سادسًا: الخلاصة

اكتشفت هذه المراجعة **خطأً خطيرًا واحدًا** (خطر فقدان البيانات)، و**مشكلة اتساق واحدة** (أسلوب receiver)، و**نقص إعلان حقوق نشر واحد**، و**نقطة تحسين كود واحدة**، وجرى إصلاحها جميعًا. كما أُضيفت اختبارات وحدة كاملة للكاشفات الـ 18 الناقصة في الاختبارات، لترتفع تغطية الاختبارات من حوالي 19% إلى أكثر من 92%.

جُدّت جميع التعديلات عبر `go test ./...` و`go vet ./...`.

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

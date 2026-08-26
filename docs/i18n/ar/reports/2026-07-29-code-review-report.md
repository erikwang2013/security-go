# تقرير مراجعة كود Security-Go

**التاريخ**: 2026-07-29  
**المشروع**: github.com/erikwang2013/security-go  
**نطاق المراجعة**: 42 ملفًا مصدريًا بلغة Go، 8 حزم (security، all، data، file، httpval، injection، protocol، storage)

---

## أولًا: نتائج الاختبارات

```
ok      github.com/erikwang2013/security-go       0.004s
?       github.com/erikwang2013/security-go/all   [no test files]
ok      github.com/erikwang2013/security-go/data  0.005s
ok      github.com/erikwang2013/security-go/file  0.006s
ok      github.com/erikwang2013/security-go/httpval 0.004s  (已补写 32 个测试)
ok      github.com/erikwang2013/security-go/injection 0.005s
ok      github.com/erikwang2013/security-go/protocol  0.005s
ok      github.com/erikwang2013/security-go/storage   0.159s
```

- `go vet ./...` نجح دون تحذيرات
- جميع الاختبارات ناجحة
- **الحزمة الناقصة في الاختبارات**: `all` (الأخيرة المتبقية)

---

## ثانيًا: الأخطاء التي تم إصلاحها

### الخطأ #1 [حرج] `storage/file.go:101` — خطأ تسلسل JSON كان يُتجاهل بصمت

**المشكلة**: في طريقة `Close()` كان `data, _ := json.Marshal(out)` يتجاهل خطأ التسلسل. إذا فشل تسلسل JSON، تكون `data` فارغة (nil)، فيكتب `os.WriteFile` بيانات فارغة، **مما يؤدي إلى فقدان كامل للبيانات المُستدامة**.

**الإصلاح**: فحص القيمة المُرجعة للخطأ من `json.Marshal`، وإرجاع الخطأ فورًا عند الفشل.

```go
// 修复前
data, _ := json.Marshal(out)
return os.WriteFile(f.path, data, 0644)

// 修复后
data, err := json.Marshal(out)
if err != nil {
    return err
}
return os.WriteFile(f.path, data, 0644)
```

### الخطأ #2 [حرج] `httpval/content_type.go:34` — قائمة AllowList فارغة تسمح بكل أنواع Content-Type

**المشكلة**: الشرط `if len(c.Allowed) == 0 || c.Allowed[mt]` يعني أنه عندما تكون AllowList فارغة، **يُسمح بجميع أنواع Content-Type**. القيمة الافتراضية الآمنة يجب أن تكون رفض الكل (deny-all).

**الإصلاح**: إزالة شرط `len(c.Allowed) == 0`، فتذهب القائمة البيضاء الفارغة إلى فرع الرفض.

```go
// 修复前
if len(c.Allowed) == 0 || c.Allowed[mt] {
    return &security.Result{Name: c.Name(), Detected: false}
}

// 修复后
if c.Allowed[mt] {
    return &security.Result{Name: c.Name(), Detected: false}
}
```

### الخطأ #3 [متوسط] `protocol/xxe.go:15` — `&[a-z]+;` يطابق جميع كيانات HTML/XML القانونية خطأً

**المشكلة**: التعبير النمطي `(?i)&[a-z]+;` يطابق جميع مراجع الكيانات القياسية (`&amp;`، `&lt;`، `&gt;` وغيرها)، مما يؤدي إلى الإبلاغ الخاطئ عن أي طلب يحتوي HTML/XML قانونيًا باعتباره هجوم XXE.

**الإصلاح**: تقليص نطاق المطابقة إلى بادئات البروتوكولات الخبيثة المعروفة.

```go
// 修复前
regexp.MustCompile(`(?i)&[a-z]+;`),

// 修复后
regexp.MustCompile(`(?i)&(?:xxe|file|http|ftp|gopher|dict|data|expect);`),
```

---

## ثالثًا: المشكلات الثانوية المكتشفة (غير مُصلحة، تتطلب تقييمًا)

### المشكلة #1: حزمة `all` بدون تغطية اختبارات

دالة `RegisterAll()` في `all/all.go` لا تحتوي على أي اختبارات. يجب إضافة اختبارات للتحقق من أن جميع الكاشفات المسجلة يمكن استدعاؤها بشكل صحيح.

### المشكلة #2: اختبارات حزمة `httpval` مكتملة ✅ (تم الحل)

أُضيف `httpval/httpval_test.go` (32 حالة اختبار)، تغطي `BodySize` (7 اختبارات)، `ContentType` (7 اختبارات)، `CSRFOrigin` (8 اختبارات)، `IPBlacklist` (6 اختبارات)، `Method` (3 اختبارات). تتضمن قيمًا حدية، مدخلات خاطئة، والتحقق من رفض الكل عند AllowList فارغة.

### المشكلة #3: تعبير بطاقة الائتمان في `data/data_leak.go` واسع جدًا

`\b(?:\d[ -]*?){13,16}\b` يطابق أي تسلسل أرقام مكوّن من 13-16 رقمًا.

### المشكلة #4: الوحدة الفرعية `storage/redis/` غير مكتملة

- `go.mod` ينقصه إعلان الاعتماد على الوحدة الأم
- ينقصه ملف `go.sum`

### المشكلة #5: أسلوب receiver غير متسق بين حزمة protocol وحزمة injection

- حزمة `injection` تستخدم مستقبلات المؤشر: `func (d *XSS) Name() string`
- حزمة `protocol` تستخدم مستقبلات القيمة: `func (d CORS) Name() string`

### المشكلة #6: `injection/xss.go` — `&#x?[0-9a-f]+;?` يطابق مراجع الأرقام القانونية في HTML

---

## رابعًا: التقييم العام للبنية

| البُعد | الدرجة | الوصف |
|------|------|------|
| تصميم الواجهة | ★★★★☆ | واجهة `Detector` + نمط تنسيق `Engine` واضح |
| اتساق الكود | ★★★☆☆ | أسلوب receiver غير موحّد |
| معالجة الأخطاء | ★★★☆☆ | قبل الإصلاح كانت الأخطاء تُبتلع بصمت؛ تحسّن بعد الإصلاح |
| تغطية الاختبارات | ★★★★☆ | اكتملت اختبارات `httpval`، وحزمة `all` ما زالت ناقصة |
| القيم الافتراضية الآمنة | ★★★☆☆ | مشكلة AllowList الفارغة في ContentType تم إصلاحها |
| دقة الكشف | ★★★☆☆ | بعض التعبيرات النمطية تحمل خطر الإبلاغ الخاطئ (xxe أُصلح جزئيًا) |

---

## خامسًا: الأولويات المقترحة

| الأولوية | البند |
|--------|------|
| ~~P0~~ | ~~كتابة اختبارات حزمة `httpval`~~ ✅ اكتمل (32 اختبارًا، 5 كاشفات) |
| P1 | كتابة اختبارات حزمة `all` |
| P1 | إصلاح go.mod للوحدة الفرعية `storage/redis/` |
| P2 | توحيد أسلوب receiver إلى مستقبلات المؤشر |
| P2 | تقييم معدل الإبلاغ الخاطئ لتعبيري بطاقة الائتمان/XSS |

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

# حزمة كشف الهجمات — مواصفات التصميم

## نظرة عامة

مكتبة كشف هجمات خالصة بلغة Go، توفر واجهة موحّدة + نمط سجلّات، تغطي 6 فئات و36 كاشفًا. **اكتمل التنفيذ (2026-07-29)؛ وأُضيفت حزمة `session` في 2026-09-15.**

## بنية الحزمة

```
security-go/
├── go.mod
├── security.go              # Result, Severity, Detector interface, Engine
├── all/all.go               # RegisterAll — 注册所有内置 detector
├── injection/               # 注入类攻击 (10)
├── protocol/                # 协议与请求攻击 (9)
├── httpval/                 # HTTP 协议层校验 (7)
├── data/                    # 数据与序列化攻击 (5)
├── file/                    # 文件与敏感数据 (3)
├── session/                 # 会话安全 (2) — 不经过 Engine
│   ├── store.go             # Store interface + MemoryStore
│   ├── tracker.go           # Tracker — 客户端被劫持 / 异地登录
│   └── tamper.go            # Signer — 篡改数据
└── storage/                 # 可插拔存储后端
    ├── storage.go           # Backend interface
    ├── memory.go            # 内存实现 (带 TTL 清理)
    ├── file.go              # JSON 文件持久化
    └── redis/               # Redis 子模块 (可选依赖)
```

## واجهة API الأساسية

واجهات API الكاملة (`Result`، `Detector`، `Engine`، واجهة التخزين الخلفي `Backend`، مُدقّقات HTTP) موثّقة في وثيقة مستقلة: **[وثيقة واجهة API](../api.md)**

- تستخدم جميع الكاشفات أنماط regex مُجمّعة مسبقًا (All detectors use pre-compiled regex patterns)

## الكاشفات

| الفئة | الاسم | الأنماط الرئيسية |
|----------|------|-------------|
| injection | xss | `<script>`, `on[a-z]+=`, `javascript:`, SVG/CSS vectors |
| injection | sql | UNION SELECT, `/**/`, sleep/benchmark, boolean blind, schema enum |
| injection | command | backtick, `$()`, pipe, `/dev/tcp`, PHP exec functions |
| injection | nosql | MongoDB `$ne`/`$gt`/`$regex`/`$where`, auth bypass |
| injection | ldap | filter operators `(`, `)`, `&`, `|`, `*` |
| injection | xpath | boolean bypass `1=1`, `' or '1'='1` |
| injection | jndi | `${jndi:ldap://`, `${lower:j}`, `${env:}` |
| injection | ssi | `<!--#exec`, `<!--#include`, `<!--#echo` |
| injection | graphql | `__schema`, `__type`, deep nested query, mutation detect |
| injection | ssti | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO |
| protocol | ssrf | internal IP, 169.254.169.254, IPv6 loopback, gopher/dict |
| protocol | xxe | `<!ENTITY`, parameter entities, DOCTYPE |
| protocol | header_injection | CRLF `%0d%0a`, Set-Cookie/Location injection |
| protocol | host_header | CRLF Host injection, X-Forwarded-Host poisoning |
| protocol | request_smuggling | TE/CL mismatch, dual TE, folded header |
| protocol | open_redirect | `//evil.com`, `javascript:`, `data:` |
| protocol | cors | Origin: null, ACA* header injection |
| protocol | websocket | Upgrade injection, null Origin, ws:// |
| protocol | dns_rebinding | Host header internal IP, localhost, hostname without TLD |
| httpval | method | Whitelist GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH → 405 |
| httpval | body_size | Max size check → 413 (default 10MB) |
| httpval | content_type | MIME whitelist → 415 |
| httpval | csrf_origin | Cross-origin Origin vs Host match |
| httpval | ip_blacklist | Window-based rate limit → auto ban (5/60s → 15min) |
| httpval | nested_depth | JSON body bomb: nesting depth / element count exceeded (streamed; non-JSON never matches) |
| httpval | cookie_attrs | Set-Cookie missing Secure/HttpOnly/SameSite, overlong or empty value |
| data | deserialization | PHP `O:数字:`, `C:数字:`, unserialize() |
| data | csv_injection | `=`, `@`, `+`, `-` formula prefix |
| data | mail_header | Bcc/Cc/From/To injection, MIME |
| data | jwt_attack | alg:none, kid path traversal, empty signature |
| data | prototype_pollution | `__proto__`, `constructor`, `__defineGetter__` |
| file | path_traversal | `../`, `..\\`, php://filter, null byte |
| file | upload | Extension whitelist + PHP tag content scan |
| file | data_leak | Credit card, AWS key, private key, connection string, JWT secret |
| session | session_guard | ربط الـ token بالعميل: تغيّر UA/بصمة الجهاز (اختطاف العميل)، تغيّر نطاق IP/البلد (تسجيل الدخول من موقع بعيد)، سجل شبكات تسجيل الدخول |
| session | data_tamper | HMAC-SHA256 على معاملات مُنظَّمة، نافذة زمنية ±5m، عدّاد nonce لإعادة الإرسال |

## خارج نطاق الأهداف

- لا يوجد وسيط HTTP عام — الاستثناء الوحيد هو `session.Tracker.Guard`، غلاف رفيع يُرجع 401 عندما يكتشف `Check` إصابة
- لا يوجد اعتراض على الطلبات في الوقت الحقيقي (المستدعي هو من يستدعي الكشف)
- لا يوجد حظر للهجمات (كشف فقط؛ يوفر ip_blacklist دعم الحظر)

## حالة التنفيذ (2026-07-29)

- **تم تنفيذ الكاشفات الـ 32 بالكامل** — نقطة التسجيل `all.RegisterAll(engine)`
- **تغطية الاختبارات** — 7/8 حزم لديها اختبارات (حزمة `all` معلّقة)، أُضيفت 32 اختبارًا لحزمة httpval
- **اكتملت مراجعة الكود** — إصلاح 3 أخطاء (انظر تقرير المراجعة)، `go vet` بصفر تحذيرات
- **القيود المعروفة** — الوحدة الفرعية `storage/redis/` تتطلب `go mod tidy`؛ أسلوب receiver في حزمة protocol بانتظار التوحيد
- **التقرير** — `docs/superpowers/reports/2026-07-29-code-review-report.md` → [تقرير مراجعة الكود](../reports/2026-07-29-code-review-report.md)

## ملحق — حزمة `session` (2026-09-15)

أُضيف أمان الجلسات كفئة سادسة، مع نفس قيود التصميم المذكورة أعلاه:

- **`session.Tracker`** (`session_guard`) — يربط `Issue` الـ token بـ نطاق IP / UA / بصمة الجهاز؛ ويقارن `Check` مع كل طلب، فيُصيب `client_hijack` (تغيّر UA أو البصمة، Critical) أو `remote_login` (اختلاف البلد Critical / اختلاف النطاق High)؛ و`Guard` يُرجع 401 عند الإصابة؛ ويقارن `Observe` عند تسجيل الدخول النطاقات السابقة للمستخدم؛ و`Revoke` يُبطل الجلسة فورًا.
- **`session.Signer`** (`data_tamper`) — توقيع HMAC-SHA256 لمعاملات `<الطابع الزمني>.<nonce>.<التوقيع>`، وترتيب التحقق هو الطابع الزمني ← التوقيع ← عدّاد nonce، لذلك لا يمكن لتوقيع مزوّر أن يستهلك nonce صالحًا. يعيد عدّاد إعادة الإرسال استخدام `storage.Backend`.
- **التخزين** — لا يمكن التعبير عن بنية الجلسة بـ `storage.Backend` الذي يدعم العدّ/الحظر فقط، لذا أُضيفت `session.Store` (`Save` / `Load` / `Delete`) + `MemoryStore`؛ ولم يُعدَّل `storage.Backend` ولا تنفيذاته الثلاثة.
- **لا تُسجَّل في `Engine`** — لا يمكن لـ `Detector.Detect(input string)` الوصول إلى token / عنوان IP للعميل / UA، لذلك يستقبل `Tracker` قيمة `*http.Request` مباشرة؛ ويبقى `all.RegisterAll` يسجّل الكاشفات صفرية التكوين فقط.
- **الاختبارات** — حزمة `session` بها 3 ملفات اختبار (store / tracker / tamper)، و`go test ./... -race` ينجح.

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

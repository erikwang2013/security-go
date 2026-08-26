# حزمة كشف الهجمات — مواصفات التصميم

## نظرة عامة

مكتبة كشف هجمات خالصة بلغة Go، توفر واجهة موحّدة + نمط سجلّات، تغطي 5 فئات و32 كاشفًا. **اكتمل التنفيذ (2026-07-29).**

## بنية الحزمة

```
security-go/
├── go.mod
├── security.go              # Result, Severity, Detector interface, Engine
├── all/all.go               # RegisterAll — 注册所有内置 detector
├── injection/               # 注入类攻击 (10)
├── protocol/                # 协议与请求攻击 (9)
├── httpval/                 # HTTP 协议层校验 (5)
├── data/                    # 数据与序列化攻击 (5)
├── file/                    # 文件与敏感数据 (3)
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
| data | deserialization | PHP `O:数字:`, `C:数字:`, unserialize() |
| data | csv_injection | `=`, `@`, `+`, `-` formula prefix |
| data | mail_header | Bcc/Cc/From/To injection, MIME |
| data | jwt_attack | alg:none, kid path traversal, empty signature |
| data | prototype_pollution | `__proto__`, `constructor`, `__defineGetter__` |
| file | path_traversal | `../`, `..\\`, php://filter, null byte |
| file | upload | Extension whitelist + PHP tag content scan |
| file | data_leak | Credit card, AWS key, private key, connection string, JWT secret |

## خارج نطاق الأهداف

- لا يوجد وسيط HTTP (مكتبة كشف خالصة)
- لا يوجد اعتراض على الطلبات في الوقت الحقيقي (المستدعي هو من يستدعي الكشف)
- لا يوجد حظر للهجمات (كشف فقط؛ يوفر ip_blacklist دعم الحظر)

## حالة التنفيذ (2026-07-29)

- **تم تنفيذ الكاشفات الـ 32 بالكامل** — نقطة التسجيل `all.RegisterAll(engine)`
- **تغطية الاختبارات** — 7/8 حزم لديها اختبارات (حزمة `all` معلّقة)، أُضيفت 32 اختبارًا لحزمة httpval
- **اكتملت مراجعة الكود** — إصلاح 3 أخطاء (انظر تقرير المراجعة)، `go vet` بصفر تحذيرات
- **القيود المعروفة** — الوحدة الفرعية `storage/redis/` تتطلب `go mod tidy`؛ أسلوب receiver في حزمة protocol بانتظار التوحيد
- **التقرير** — `docs/superpowers/reports/2026-07-29-code-review-report.md` → [تقرير مراجعة الكود](../reports/2026-07-29-code-review-report.md)

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

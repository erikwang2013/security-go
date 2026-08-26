# Attack Detection Package — डिज़ाइन स्पेक

## अवलोकन

शुद्ध Go आक्रमण-पता लगाने वाली लाइब्रेरी, एकीकृत इंटरफ़ेस + रजिस्ट्री पैटर्न के साथ, 5 प्रमुख श्रेणियों में 32 डिटेक्टर कवर करती है। **कार्यान्वयन पूर्ण (2026-07-29)।**

## पैकेज संरचना

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

## मुख्य API

संपूर्ण API इंटरफ़ेस (`Result`, `Detector`, `Engine`, स्टोरेज बैकएंड `Backend`, HTTP वैलिडेटर) के लिए अलग दस्तावेज़ देखें: **[API दस्तावेज़](../api.md)**

- सभी डिटेक्टर प्री-कंपाइल्ड regex पैटर्न का उपयोग करते हैं

## डिटेक्टर

| श्रेणी | नाम | मुख्य पैटर्न |
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
| data | deserialization | PHP `O:अंक:`, `C:अंक:`, unserialize() |
| data | csv_injection | `=`, `@`, `+`, `-` formula prefix |
| data | mail_header | Bcc/Cc/From/To injection, MIME |
| data | jwt_attack | alg:none, kid path traversal, empty signature |
| data | prototype_pollution | `__proto__`, `constructor`, `__defineGetter__` |
| file | path_traversal | `../`, `..\\`, php://filter, null byte |
| file | upload | Extension whitelist + PHP tag content scan |
| file | data_leak | Credit card, AWS key, private key, connection string, JWT secret |

## गैर-लक्ष्य (Non-Goals)

- कोई HTTP मिडलवेयर नहीं (शुद्ध डिटेक्शन लाइब्रेरी)
- कोई रीयल-टाइम रिक्वेस्ट इंटरसेप्शन नहीं (कॉलर स्वयं डिटेक्शन बुलाता है)
- कोई आक्रमण-रोकथाम नहीं (केवल डिटेक्शन; ip_blacklist ब्लॉक-लिस्टिंग सहायता प्रदान करता है)

## कार्यान्वयन स्थिति (2026-07-29)

- **सभी 32 डिटेक्टर लागू** — पंजीकरण प्रवेश बिंदु `all.RegisterAll(engine)`
- **टेस्ट कवरेज** — 7/8 पैकेज में टेस्ट हैं (`all` पैकेज बाकी है), httpval के लिए 32 टेस्ट जोड़े गए
- **कोड समीक्षा पूर्ण** — 3 Bug फिक्स किए (समीक्षा रिपोर्ट देखें), `go vet` शून्य चेतावनी
- **ज्ञात सीमाएँ** — `storage/redis/` सबमॉड्यूल को `go mod tidy` की आवश्यकता है; protocol पैकेज की receiver शैली अभी एकरूप नहीं है
- **रिपोर्ट** — `docs/superpowers/reports/2026-07-29-code-review-report.md`

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

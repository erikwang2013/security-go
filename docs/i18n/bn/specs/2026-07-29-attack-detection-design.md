# আক্রমণ সনাক্তকরণ প্যাকেজ — ডিজাইন স্পেক

## সারসংক্ষেপ

বিশুদ্ধ Go আক্রমণ সনাক্তকরণ লাইব্রেরি, ইউনিফাইড ইন্টারফেস + রেজিস্ট্রি প্যাটার্ন সহ, ৫টি প্রধান শ্রেণীর ৩২টি ডিটেক্টর কভার করে। **বাস্তবায়ন সম্পন্ন (2026-07-29)।**

## প্যাকেজ স্ট্রাকচার

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

## কোর API

সম্পূর্ণ API ইন্টারফেস (`Result`, `Detector`, `Engine`, স্টোরেজ ব্যাকএন্ড `Backend`, HTTP ভ্যালিডেটর) আলাদা ডকুমেন্টে দেখুন: **[API ইন্টারফেস ডকুমেন্ট](../api.md)**

- সব ডিটেক্টর প্রি-কম্পাইলড রেজেক্স প্যাটার্ন ব্যবহার করে

## ডিটেক্টরসমূহ

| Category | Name | Key Patterns |
|----------|------|-------------|
| injection | xss | `<script>`, `on[a-z]+=`, `javascript:`, SVG/CSS ভেক্টর |
| injection | sql | UNION SELECT, `/**/`, sleep/benchmark, বুলিয়ান ব্লাইন্ড, স্কিমা এনুমারেশন |
| injection | command | ব্যাকটিক, `$()`, পাইপ, `/dev/tcp`, PHP exec ফাংশন |
| injection | nosql | MongoDB `$ne`/`$gt`/`$regex`/`$where`, অথ বাইপাস |
| injection | ldap | ফিল্টার অপারেটর `(`, `)`, `&`, `\|`, `*` |
| injection | xpath | বুলিয়ান বাইপাস `1=1`, `' or '1'='1` |
| injection | jndi | `${jndi:ldap://`, `${lower:j}`, `${env:}` |
| injection | ssi | `<!--#exec`, `<!--#include`, `<!--#echo` |
| injection | graphql | `__schema`, `__type`, গভীর নেস্টেড কোয়েরি, মিউটেশন সনাক্তকরণ |
| injection | ssti | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO |
| protocol | ssrf | অভ্যন্তরীণ IP, 169.254.169.254, IPv6 লুপব্যাক, gopher/dict |
| protocol | xxe | `<!ENTITY`, প্যারামিটার এন্টিটি, DOCTYPE |
| protocol | header_injection | CRLF `%0d%0a`, Set-Cookie/Location ইনজেকশন |
| protocol | host_header | CRLF Host ইনজেকশন, X-Forwarded-Host পয়জনিং |
| protocol | request_smuggling | TE/CL অসামঞ্জস্য, দ্বৈত TE, ফোল্ডেড হেডার |
| protocol | open_redirect | `//evil.com`, `javascript:`, `data:` |
| protocol | cors | Origin: null, ACA* হেডার ইনজেকশন |
| protocol | websocket | Upgrade ইনজেকশন, null Origin, ws:// |
| protocol | dns_rebinding | Host হেডারে অভ্যন্তরীণ IP, localhost, TLD-বিহীন হোস্টনেম |
| httpval | method | হোয়াইটলিস্ট GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH → 405 |
| httpval | body_size | সর্বোচ্চ সাইজ চেক → 413 (ডিফল্ট 10MB) |
| httpval | content_type | MIME হোয়াইটলিস্ট → 415 |
| httpval | csrf_origin | ক্রস-অরিজিন Origin বনাম Host মিল |
| httpval | ip_blacklist | উইন্ডো-ভিত্তিক রেট লিমিট → স্বয়ংক্রিয় ব্লক (5/60s → 15min) |
| data | deserialization | PHP `O:সংখ্যা:`, `C:সংখ্যা:`, unserialize() |
| data | csv_injection | `=`, `@`, `+`, `-` ফর্মুলা প্রিফিক্স |
| data | mail_header | Bcc/Cc/From/To ইনজেকশন, MIME |
| data | jwt_attack | alg:none, kid পাথ ট্রাভার্সাল, খালি সিগনেচার |
| data | prototype_pollution | `__proto__`, `constructor`, `__defineGetter__` |
| file | path_traversal | `../`, `..\\`, php://filter, null বাইট |
| file | upload | এক্সটেনশন হোয়াইটলিস্ট + PHP ট্যাগ কনটেন্ট স্ক্যান |
| file | data_leak | ক্রেডিট কার্ড, AWS কী, প্রাইভেট কী, কানেকশন স্ট্রিং, JWT সিক্রেট |

## অ-লক্ষ্য

- কোনো HTTP মিডলওয়্যার নেই (বিশুদ্ধ ডিটেকশন লাইব্রেরি)
- কোনো রিয়েল-টাইম রিকোয়েস্ট ইন্টারসেপশন নেই (কলার নিজে ডিটেকশন আহ্বান করে)
- কোনো আক্রমণ ব্লকিং নেই (শুধুমাত্র ডিটেকশন; ip_blacklist ব্লক-লিস্টিং সাপোর্ট প্রদান করে)

## বাস্তবায়নের অবস্থা (2026-07-29)

- **৩২টি ডিটেক্টর সম্পূর্ণ বাস্তবায়িত** — রেজিস্ট্রেশন এন্ট্রি পয়েন্ট `all.RegisterAll(engine)`
- **টেস্ট কভারেজ** — 7/8 প্যাকেজে টেস্ট আছে (`all` প্যাকেজ বাকি), httpval-এ 32টি টেস্ট যোগ করা হয়েছে
- **কোড রিভিউ সম্পন্ন** — 3টি বাগ মেরামত করা হয়েছে (রিভিউ রিপোর্ট দেখুন), `go vet` শূন্য ওয়ার্নিং
- **জ্ঞাত সীমাবদ্ধতা** — `storage/redis/` সাবমডিউলে `go mod tidy` প্রয়োজন; protocol প্যাকেজের receiver স্টাইল একীভূত করা বাকি
- **রিপোর্ট** — `docs/superpowers/reports/2026-07-29-code-review-report.md`

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

# আক্রমণ সনাক্তকরণ প্যাকেজ — ডিজাইন স্পেক

## সারসংক্ষেপ

বিশুদ্ধ Go আক্রমণ সনাক্তকরণ লাইব্রেরি, ইউনিফাইড ইন্টারফেস + রেজিস্ট্রি প্যাটার্ন সহ, ৬টি প্রধান শ্রেণীর ৩৪টি ডিটেক্টর কভার করে। **বাস্তবায়ন সম্পন্ন (2026-07-29); `session` প্যাকেজ 2026-09-15-এ যোগ করা হয়েছে।**

## প্যাকেজ স্ট্রাকচার

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
│   ├── lockout.go           # 失败计数、锁定查找与键
│   ├── bruteforce.go        # 渐进退避 / 撞库检测 / GuardLogin
│   └── tamper.go            # Signer — 篡改数据
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
| httpval | nested_depth | JSON body bomb: nesting depth / element count exceeded (streamed; non-JSON never matches) |
| httpval | cookie_attrs | Set-Cookie missing Secure/HttpOnly/SameSite, overlong or empty value |
| data | deserialization | PHP `O:সংখ্যা:`, `C:সংখ্যা:`, unserialize() |
| data | csv_injection | `=`, `@`, `+`, `-` ফর্মুলা প্রিফিক্স |
| data | mail_header | Bcc/Cc/From/To ইনজেকশন, MIME |
| data | jwt_attack | alg:none, kid পাথ ট্রাভার্সাল, খালি সিগনেচার |
| data | prototype_pollution | `__proto__`, `constructor`, `__defineGetter__` |
| file | path_traversal | `../`, `..\\`, php://filter, null বাইট |
| file | upload | এক্সটেনশন হোয়াইটলিস্ট + PHP ট্যাগ কনটেন্ট স্ক্যান |
| file | data_leak | ক্রেডিট কার্ড, AWS কী, প্রাইভেট কী, কানেকশন স্ট্রিং, JWT সিক্রেট |
| session | session_guard | টোকেন ↔ ক্লায়েন্ট বাইন্ডিং: UA/ফিঙ্গারপ্রিন্ট পরিবর্তন (ক্লায়েন্ট হাইজ্যাক), IP সাবনেট/দেশ পরিবর্তন (দূরবর্তী লগইন), লগইন-নেটওয়ার্ক ইতিহাস; brute-force lockout with progressive backoff and per-IP credential-stuffing detection |
| session | data_tamper | ক্যানোনিকাল প্যারামিটারে HMAC-SHA256, ±5m টাইমস্ট্যাম্প উইন্ডো, nonce রিপ্লে কাউন্টার |

## অ-লক্ষ্য

- সাধারণ উদ্দেশ্যের কোনো HTTP মিডলওয়্যার নেই — একমাত্র ব্যতিক্রম `session.Tracker.Guard`, একটি পাতলা র‍্যাপার যা `Check` সনাক্ত করলে 401 রিটার্ন করে
- কোনো রিয়েল-টাইম রিকোয়েস্ট ইন্টারসেপশন নেই (কলার নিজে ডিটেকশন আহ্বান করে)
- কোনো আক্রমণ ব্লকিং নেই (শুধুমাত্র ডিটেকশন; ip_blacklist ব্লক-লিস্টিং সাপোর্ট প্রদান করে)

## বাস্তবায়নের অবস্থা (2026-07-29)

- **৩২টি ডিটেক্টর সম্পূর্ণ বাস্তবায়িত** — রেজিস্ট্রেশন এন্ট্রি পয়েন্ট `all.RegisterAll(engine)`
- **টেস্ট কভারেজ** — 7/8 প্যাকেজে টেস্ট আছে (`all` প্যাকেজ বাকি), httpval-এ 32টি টেস্ট যোগ করা হয়েছে
- **কোড রিভিউ সম্পন্ন** — 3টি বাগ মেরামত করা হয়েছে (রিভিউ রিপোর্ট দেখুন), `go vet` শূন্য ওয়ার্নিং
- **জ্ঞাত সীমাবদ্ধতা** — `storage/redis/` সাবমডিউলে `go mod tidy` প্রয়োজন; protocol প্যাকেজের receiver স্টাইল একীভূত করা বাকি
- **রিপোর্ট** — `docs/superpowers/reports/2026-07-29-code-review-report.md`

## অ্যাডেন্ডাম — `session` প্যাকেজ (2026-09-15)

ষষ্ঠ শ্রেণী হিসেবে সেশন নিরাপত্তা যোগ করা হয়েছে, ডিজাইন সীমাবদ্ধতা উপরের মতোই:

- **`session.Tracker`** (`session_guard`) — `Issue` টোকেন → IP সাবনেট / UA / ডিভাইস ফিঙ্গারপ্রিন্ট বাইন্ড করে; `Check` প্রতি রিকোয়েস্টে মেলায়, ফলে `client_hijack` (UA বা ফিঙ্গারপ্রিন্ট পরিবর্তন, Critical) বা `remote_login` (দেশ পরিবর্তন Critical / সাবনেট পরিবর্তন High) ধরা পড়ে; `Guard` সনাক্ত হলে 401 দেয়; `Observe` লগইনের সময় ব্যবহারকারীর পূর্ববর্তী নেটওয়ার্কগুলো মেলায়; `Revoke` অবিলম্বে বাতিল করে।
- **`session.Signer`** (`data_tamper`) — প্যারামিটারে HMAC-SHA256 সিগনেচার `<টাইমস্ট্যাম্প>.<nonce>.<সিগনেচার>`, যাচাইয়ের ক্রম টাইমস্ট্যাম্প → সিগনেচার → nonce কাউন্টার, তাই জাল সিগনেচার বৈধ nonce খরচ করতে পারে না। রিপ্লে কাউন্টার `storage.Backend` পুনর্ব্যবহার করে।
- **ব্রুট-ফোর্স সুরক্ষা** — `RecordFailure(identity, r)` লগইন ব্যর্থতা গণনা করে ও সীমায় লক করে, প্রতিবার দ্বিগুণ হয়ে `MaxLockout` (ডিফল্ট ২৪ ঘণ্টা) পর্যন্ত; `CheckLogin` অতিরিক্তভাবে প্রতি ক্লায়েন্ট IP-এর ব্যর্থ হওয়া ভিন্ন আইডেন্টিটি গণনা করে এবং `StuffingLimit` (ডিফল্ট ১০)-এ `credential_stuffing` রিপোর্ট করে; `GuardLogin` প্রমাণীকরণ এন্ডপয়েন্টের মিডলওয়্যার, `Retry-After` সহ 429 দেয়। ক্রমবর্ধমান বিলম্বের উদ্দেশ্য — যেকোনো অ্যাকাউন্ট লক করে DoS করা যেন সম্ভব না হয়।
- **স্টোরেজ** — শুধু কাউন্ট/ব্লক সাপোর্ট করে এমন `storage.Backend` দিয়ে সেশন স্ট্রাকচার প্রকাশ করা যায় না, তাই `session.Store` (`Save` / `Load` / `Delete`) + `MemoryStore` যোগ করা হয়েছে; `storage.Backend` এবং তার তিনটি ইমপ্লিমেন্টেশন অপরিবর্তিত।
- **`Engine`-এ রেজিস্টার হয় না** — `Detector.Detect(input string)` টোকেন / ক্লায়েন্ট IP / UA পায় না, তাই `Tracker` সরাসরি `*http.Request` গ্রহণ করে; `all.RegisterAll` শুধু জিরো-কনফিগ ডিটেক্টর রেজিস্টার করে।
- **টেস্ট** — `session` প্যাকেজে 5টি টেস্ট ফাইল (store / tracker / tamper / lockout / bruteforce), `go test ./... -race` পাস করে।

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

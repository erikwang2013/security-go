# Security Go — আক্রমণ সনাক্তকরণ লাইব্রেরি

[简体中文](../../../README.md) · [English](../../../README-EN.md)

Go ভাষায় লেখা আক্রমণ সনাক্তকরণ প্যাকেজ, যা কভার করে **৩৪টি ডিটেক্টর** (detector), **৬টি প্রধান আক্রমণ শ্রেণী**, **৩টি প্লাগেবল স্টোরেজ ব্যাকএন্ড** (backend)। ইউনিফাইড ইন্টারফেস + রেজিস্ট্রি (registry) প্যাটার্ন, বিশুদ্ধ ডিটেকশন লাইব্রেরি, যেকোনো Go HTTP ফ্রেমওয়ার্কের সাথে মানিয়ে নেওয়া যায়।

## ডিজাইনের ধারণা

### মূল নীতি

- **শূন্য-নির্ভরতা ডিটেকশন** — সব ডিটেক্টর শুধুমাত্র Go স্ট্যান্ডার্ড লাইব্রেরির `regexp` ব্যবহার করে, কোনো বাহ্যিক নির্ভরতা নেই
- **ইউনিফাইড ইন্টারফেস** — প্রতিটি ডিটেক্টর `Detector` ইন্টারফেস (`Name()` + `Detect()`) বাস্তবায়ন করে, `Engine` রেজিস্ট্রির মাধ্যমে সমন্বিতভাবে পরিচালিত হয়
- **প্রি-কম্পাইলড রেজেক্স** — সব প্যাটার্ন `var` ইনিশিয়ালাইজেশনের সময় কম্পাইল হয়, রানটাইমে শূন্য ওভারহেড
- **চাহিদা অনুযায়ী কনফিগারেশন** — ইনজেকশন/প্রোটোকল/ডেটা/ফাইল ডিটেক্টর প্লাগ-এন্ড-প্লে; HTTP ভ্যালিডেটর ও সেশন নিরাপত্তা সনাক্তকরণের জন্য অ্যাপ্লিকেশন কাস্টম কনফিগারেশন প্রয়োজন

### ডিজাইন আর্কিটেকচার

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
   │     (7 个)      │                                         │  ┌──────────────┐   │
   │                 │                                         │  │   Backend    │   │
   │  method, size,  │                                         │  │   interface  │   │
   │  type, csrf,    │                                         │  └──┬───┬───┬───┘   │
   │  cookie,nested  │                                         │                    │
   │  ip_blacklist   │◄────── 使用 storage.Backend ──────────►│  Memory File Redis │
   │  (需配置参数)    │                                         │                    │
   └─────────────────┘                                         └────────────────────┘

   ┌─────────────────────────────────────────────────────────────────────┐
   │  session (2)   outside the Engine registry                          │
   │                                                                     │
   │  Tracker (session_guard)  +  Signer (data_tamper)                   │
   │  Issue / Check / Observe / Guard / Revoke    Sign / Verify          │
   └─────────────────────────────────────────────────────────────────────┘
```

> `session` প্যাকেজ `Engine` রেজিস্ট্রির মধ্য দিয়ে যায় না: সেশন ভ্যালিডেশনের জন্য সম্পূর্ণ `*http.Request` পড়া প্রয়োজন (token, ক্লায়েন্ট IP, User-Agent),
> এবং অ্যাপ্লিকেশনকে স্টোরেজ ও কী সরবরাহ করতে হয়, তাই এটি সরাসরি মিডলওয়্যার হিসেবে ব্যবহৃত হয়, নিচের "সেশন নিরাপত্তা কনফিগারেশন" অংশটি দেখুন।

### ডেটা ফ্লো

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

### তীব্রতার স্তর

| স্তর | বর্ণনা | সাধারণ দৃশ্য |
|------|--------|-------------|
| `SeverityLow` | কম ঝুঁকি | অবৈধ HTTP মেথড, Content-Type মেলে না |
| `SeverityMedium` | মাঝারি ঝুঁকি | দুর্বল সংকেত: CORS কনফিগারেশন সমস্যা, ওপেন রিডাইরেক্ট, GraphQL ইন্ট্রোস্পেকশন, এবং প্রতিটি ডিটেক্টর যে প্রসঙ্গহীন প্যাটার্নগুলো ইচ্ছাকৃতভাবে আলাদা রাখে (`../`, `on…=`, `javascript:`, `sleep(`, `sqlite_master`, ব্যাকটিক, `{#…#}`, `__proto__:`, PHP ম্যাজিক মেথড নাম) — টিউটোরিয়াল ও সাধারণ কনটেন্টে প্রচলিত |
| `SeverityHigh` | উচ্চ ঝুঁকি | শক্তিশালী সংকেত: XSS, SQL ইনজেকশন, SSRF, পাথ ট্রাভার্সাল, সেশন ব্যতিক্রম |
| `SeverityCritical` | গুরুতর | শক্তিশালী সংকেত: কমান্ড ইনজেকশন, JNDI, SSTI, XXE, ডেটা লিক, ডিসিরিয়ালাইজেশন (PHP সিরিয়ালাইজড অবজেক্ট / pickle / Java / .NET) |

## বাস্তবায়িত বৈশিষ্ট্য

### ইনজেকশন-ধরনের আক্রমণ (10)

| ডিটেক্টর | সনাক্তকরণ প্যাটার্ন |
|----------|---------------------|
| **XSS** | `<script>`, `on[a-z]+=` ইভেন্ট হ্যান্ডলার, `javascript:` সিউডো-প্রোটোকল, SVG/CSS ইনজেকশন, `eval()`, `document.cookie` |
| **SQL ইনজেকশন** | `UNION SELECT` (`/**/` বাইপাস সহ), `sleep/benchmark/pg_sleep`, বুলিয়ান ব্লাইন্ড, `information_schema` এনুমারেশন, `xp_cmdshell` |
| **কমান্ড ইনজেকশন** | ব্যাকটিক, `$()`, পাইপ, `/dev/tcp`, PHP `system/exec/shell_exec`, চেইনড এক্সিকিউশন `&&` `;` `\|\|` |
| **NoSQL ইনজেকশন** | MongoDB `$ne` `$gt` `$regex` `$where` অপারেটর, `$func`, JSON কী ইনজেকশন |
| **LDAP ইনজেকশন** | ফিল্টার অপারেটর `(\|(&(!`, `objectClass=*`, URL এনকোডিং বাইপাস |
| **XPATH ইনজেকশন** | বুলিয়ান বাইপাস `' or '1'='1`, `string-length()`, `count()` |
| **JNDI/Log4Shell** | `${jndi:ldap://`, `${lower:j}` অবফাসকেশন, `${env:}` এনভায়রনমেন্ট ভেরিয়েবল, `ldap/rmi/dns` প্রোটোকল |
| **SSI ইনজেকশন** | `<!--#exec cmd=`, `<!--#include file=`, `<!--#echo var=` |
| **GraphQL ইনজেকশন** | `__schema`/`__type` ইন্ট্রোস্পেকশন, গভীর-নেস্টেড DoS (5+ স্তর), `mutation` সনাক্তকরণ |
| **SSTI** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO ট্রাভার্সাল, `config/self` অ্যাক্সেস |

### প্রোটোকল ও রিকোয়েস্ট আক্রমণ (9)

| ডিটেক্টর | সনাক্তকরণ প্যাটার্ন |
|----------|---------------------|
| **SSRF** | অভ্যন্তরীণ IP (127/10/172.16/192.168), `169.254.169.254`, IPv6 লুপব্যাক, `gopher/dict/file/ftp` প্রোটোকল |
| **XXE** | `<!ENTITY SYSTEM/PUBLIC`, প্যারামিটার এন্টিটি `%entity;`, DOCTYPE ডিক্লারেশন |
| **HTTP হেডার ইনজেকশন** | CRLF `%0d%0a` / `\r\n`, Set-Cookie/Location/Content-Length ইনজেকশন |
| **Host হেডার আক্রমণ** | CRLF Host ইনজেকশন, `X-Forwarded-Host`, `X-Original-URL` পয়জনিং |
| **রিকোয়েস্ট স্মাগলিং** | Transfer-Encoding/Content-Length অসামঞ্জস্য, দ্বৈত TE হেডার, `\x0b` ফোল্ডেড-হেডার অবফাসকেশন |
| **ওপেন রিডাইরেক্ট** | `//evil.com` প্রোটোকল-রিলেটিভ URL, `javascript:/data:` সিউডো-প্রোটোকল |
| **CORS বাইপাস** | `Origin: null`, `Access-Control-Allow-*` হেডার ইনজেকশন |
| **WebSocket হাইজ্যাকিং** | Upgrade হেডার ইনজেকশন, null Origin বাইপাস, `ws://` URL |
| **DNS রিবাইন্ডিং** | Host হেডারে অভ্যন্তরীণ IP, localhost, TLD-বিহীন ছোট হোস্টনেম |

### HTTP প্রোটোকল-স্তর ভ্যালিডেশন (7)
| **JSON নেস্টিং ডেপথ** | `json.Decoder` দিয়ে স্ট্রিম স্ক্যান: নেস্টিং গভীরতা বা এলিমেন্ট সংখ্যা সীমা ছাড়ালে JSON বোমা শনাক্ত (ডিফল্ট গভীরতা 32); অবৈধ বা কাটা JSON-এ সতর্ক করে না |
| **কুকি অ্যাট্রিবিউট** | `Set-Cookie`-এ `Secure`/`HttpOnly`/`SameSite` অনুপস্থিত, মান অতিরিক্ত দীর্ঘ বা খালি হলে শনাক্ত; অনুপস্থিত অ্যাট্রিবিউট একই ফলাফলে |

| ডিটেক্টর | বর্ণনা |
|----------|--------|
| **HTTP মেথড** | শুধুমাত্র GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH অনুমোদিত, অন্যগুলোতে ওয়ার্নিং রিটার্ন |
| **রিকোয়েস্ট বডি সাইজ** | সীমা (ডিফল্ট 10MB) অতিক্রম করলে ওয়ার্নিং ট্রিগার |
| **Content-Type** | শুধুমাত্র কনফিগার করা MIME টাইপ হোয়াইটলিস্ট অনুমোদিত |
| **CSRF Origin** | ক্রস-ডোমেইন রিকোয়েস্টে Origin ও Host মিলছে কিনা পরীক্ষা করে, অতিরিক্ত হোয়াইটলিস্ট সাপোর্ট করে |
| **IP ব্ল্যাকলিস্ট** | উইন্ডো সময়ে N বার আক্রমণের পর স্বয়ংক্রিয় ব্লক (ডিফল্ট 5বার/60s → 15 মিনিট ব্লক), File/Redis/Memory স্টোরেজ সাপোর্ট |

### ডেটা ও সিরিয়ালাইজেশন আক্রমণ (5)

| ডিটেক্টর | সনাক্তকরণ প্যাটার্ন |
|----------|---------------------|
| **ডিসিরিয়ালাইজেশন** | `O:সংখ্যা:` / `C:সংখ্যা:` সিরিয়ালাইজড অবজেক্ট, `unserialize()`, ম্যাজিক মেথড (`__wakeup`/`__destruct`); PHP / pickle / Java / .NET পেলোড কভার করে |
| **CSV ইনজেকশন** | `=cmd\|`, `@SUM(`, `+`/`-` ফর্মুলা প্রিফিক্স, `HYPERLINK`/`DDE` |
| **মেইল হেডার ইনজেকশন** | Bcc/Cc/From/To ইনজেকশন, MIME multipart, boundary প্যারামিটার |
| **JWT আক্রমণ** | `alg: none` বাইপাস, `kid` পাথ ট্রাভার্সাল, খালি সিগনেচার সনাক্তকরণ (স্ট্রাকচারাল ডিকোড বিশ্লেষণ) |
| **প্রোটোটাইপ পলিউশন** | `__proto__`/`constructor` কী, `__defineGetter__`/`__defineSetter__` |

### ফাইল ও সংবেদনশীল ডেটা (3)

| ডিটেক্টর | সনাক্তকরণ প্যাটার্ন |
|----------|---------------------|
| **পাথ ট্রাভার্সাল** | `../`, `..\\`, `php://filter`/`php://input`, null বাইট, URL এনকোডিং বাইপাস, `/etc/passwd` |
| **ম্যালিসিয়াস আপলোড** | এক্সটেনশন হোয়াইটলিস্ট (15 ধরনের) + PHP ট্যাগ `<?php`/`<?=` কনটেন্ট স্ক্যান |
| **ডেটা লিক** | ক্রেডিট কার্ড নম্বর, AWS Access Key, প্রাইভেট কী `-----BEGIN`, ডেটাবেস কানেকশন স্ট্রিং, API Token, JWT Secret, GitHub PAT |

### সেশন নিরাপত্তা (2)

| ডিটেক্টর | সনাক্তকরণ প্যাটার্ন |
|----------|---------------------|
| **সেশন গার্ড** (`session_guard`) | সেশন প্রতিষ্ঠার সময় token-এর সাথে ক্লায়েন্ট বাইন্ডিং, প্রতি রিকোয়েস্টে তুলনা: User-Agent বা ডিভাইস ফিঙ্গারপ্রিন্ট পরিবর্তন হলে **ক্লায়েন্ট হাইজ্যাক** (Critical); ক্লায়েন্ট IP অন্য সাবনেট বা দেশে পড়লে **দূরবর্তী লগইন** (High/Critical); `Observe()` লগইনের সময় পূর্ববর্তী সাবনেট মেলায়, নতুন সাবনেট দেখা গেলেই সতর্ক করে। সেশন স্লাইডিং রিনিউ, `Revoke()` তাৎক্ষণিক বাতিল; `RecordFailure()` ব্যর্থ প্রচেষ্টা গণনা করে ও উইন্ডোর মধ্যে সীমা ছাড়ালে টোকেন লক করে, `Check()` তখন `token_locked` রিপোর্ট করে, আর সফল লগইনে `ClearFailures()` গণনা শূন্য করে; `CheckLogin()` অতিরিক্তভাবে ক্রেডেনশিয়াল স্টাফিং ধরে (এক ক্লায়েন্ট অনেক ভিন্ন আইডেন্টিটিতে ব্যর্থ হলে `credential_stuffing`), এবং প্রতিবার লক দ্বিগুণ হয় — সর্বোচ্চ ২৪ ঘণ্টা |
| **ডেটা ট্যাম্পারিং** (`data_tamper`) | রিকোয়েস্ট প্যারামিটারে HMAC-SHA256 সিগনেচার (`টাইমস্ট্যাম্প.nonce.সিগনেচার`), প্যারামিটার পরিবর্তন, কী মেলেনি, টাইমস্ট্যাম্প সীমা ছাড়ানো, সিগনেচার রিপ্লে (nonce কাউন্টার) শনাক্ত করে |

### স্টোরেজ ব্যাকএন্ড (3)

| ব্যাকএন্ড | বর্ণনা |
|-----------|--------|
| **Memory** | `sync.Mutex` + map, 30s পর মেয়াদোত্তীর্ণ এন্ট্রি স্বয়ংক্রিয় পরিষ্কার |
| **File** | JSON ফাইল পার্সিস্টেন্স, Close করার সময় flush |
| **Redis** | আলাদা সাবমডিউল, Pipeline Incr + TTL, `go-redis/v9` প্রয়োজন |

## ব্যবহারবিধি

### ইনস্টলেশন

```bash
go get github.com/erikwang2013/security-go
```

### দ্রুত শুরু

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

### HTTP রিকোয়েস্ট ডিটেকশন

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

### HTTP ভ্যালিডেটর কনফিগারেশন

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

### সেশন নিরাপত্তা কনফিগারেশন

`session` প্যাকেজ সরাসরি মিডলওয়্যার হিসেবে ব্যবহৃত হয়, `Engine`-এর মধ্য দিয়ে যায় না। স্টোরেজ অ্যাপ্লিকেশনকে নিজেই সরবরাহ করতে হয় (ডিফল্টভাবে মেমোরি ইমপ্লিমেন্টেশন দেওয়া হয়, Redis ইত্যাদি দিয়ে প্রতিস্থাপন করা যায়):

```go
import "github.com/erikwang2013/security-go/session"

st := session.NewMemoryStore()
defer st.Close()

tr := session.NewTracker(st)
tr.CountryOf = geo.Lookup // 可选：接入 GeoIP，用于识别跨国家登录

// 登录成功后绑定会话（token 由你的登录流程生成）
// 异地登录检测：比对该用户历史登录网段，出现新网段即告警
if res := tr.Observe("user-1", r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
if err := tr.Issue(token, r); err != nil {      // 绑定 token → IP 网段 / UA / 设备指纹
    http.Error(w, "session error", http.StatusInternalServerError)
    return
}

// 保护路由：命中劫持或异地登录直接返回 401
mux.Handle("/api/", tr.Guard(apiHandler))

// 或只做检测、自行决定处置
if res := tr.Check(r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}

// 登出
tr.Revoke(token)
```

ডেটা ট্যাম্পারিং সনাক্তকরণ: ক্লায়েন্ট ও সার্ভার একটি শেয়ারড কী ব্যবহার করে, ক্লায়েন্ট প্যারামিটারে সিগনেচার করে, সার্ভার পুনরায় হিসাব করে যাচাই করে:

```go
signer := session.NewSigner(secret, storage.NewMemory()) // 第二个参数用于拦截签名重放，可为 nil

sig, _ := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // 客户端：随参数一起提交

if res := signer.Verify(map[string]string{"amount": "100", "to": "bob"}, sig); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
```

> `TrustProxyHeaders` ডিফল্টভাবে বন্ধ: `X-Forwarded-For` / `X-Real-IP` ক্লায়েন্টের নিয়ন্ত্রণে থাকে, নিজের রিভার্স প্রক্সির পেছনে থাকলেই কেবল চালু করুন।
> `FailClosed` ডিফল্টভাবে বন্ধ (স্টোরেজ ব্যর্থ হলে অনুমোদন, `IPBlacklist`-এর সাথে সামঞ্জস্যপূর্ণ); সেশনের প্রতি সংবেদনশীল ব্যবসার জন্য চালু করার পরামর্শ দেওয়া হয়।

### কাস্টম ডিটেক্টর

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

### সম্পর্কিত ডকুমেন্টেশন

- [API ইন্টারফেস ডকুমেন্ট](api.md) — কোর টাইপ, Detector/Engine ইন্টারফেস, স্টোরেজ ব্যাকএন্ড ইন্টারফেস, HTTP ভ্যালিডেটর
- [ডিজাইন স্পেক](specs/2026-07-29-attack-detection-design.md) — প্যাকেজ স্ট্রাকচার, ডিটেক্টর ডিরেক্টরি
- [বাস্তবায়ন পরিকল্পনা](plans/2026-07-29-attack-detection-plan.md) — ধাপে ধাপে টাস্ক পরিকল্পনা ও বাস্তবায়ন বিচ্যুতির তুলনা
- [কোড রিভিউ রিপোর্ট](reports/2026-07-29-code-review-report.md) — বাগ ফিক্স, টেস্ট কভারেজ, আর্কিটেকচার মূল্যায়ন

---

## বহুভাষিক ডকুমেন্টেশন

| ভাষা | ডকুমেন্ট |
|------|----------|
| 简体中文 | [README.md](../../../README.md) |
| English | [README.md](../en/README.md) |
| 한국어 | [README.md](../ko/README.md) |
| Русский | [README.md](../ru/README.md) |
| Deutsch | [README.md](../de/README.md) |
| Français | [README.md](../fr/README.md) |
| Español | [README.md](../es/README.md) |
| Português | [README.md](../pt/README.md) |
| हिन्दी | [README.md](../hi/README.md) |
| العربية | [README.md](../ar/README.md) |
| বাংলা | [README.md](README.md) |
| Bahasa Indonesia | [README.md](../id/README.md) |
| 日本語 | [README.md](../ja/README.md) |

- [docs/i18n/README.md](../README.md) — ডকুমেন্টেশন সূচক

---

## দান সহায়তা

যদি এই প্রজেক্টটি আপনার কাজে লাগে, তাহলে দান করে সহায়তা করতে পারেন:

| পদ্ধতি | QR কোড |
|--------|--------|
| আলিপে (Alipay) | ![আলিপে](images/alipay.png) |
| উইচ্যাট পে (WeChat Pay) | ![উইচ্যাট পে](images/weixinpay.png) |

### বিশ্বব্যাপী ব্যাংক ট্রান্সফার দান

**প্রাপকের তথ্য**

- প্রাপকের নাম: WANG KEXUN
- প্রাপকের অ্যাকাউন্ট নম্বর: 881015918251

**প্রাপক ব্যাংক (ZA Bank)**

- SWIFT Code: `AABLHKHHXXX`
- ব্যাংকের নাম: ZA Bank Limited
- ব্যাংক কোড: 387
- ব্যাংকের ঠিকানা: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

**ক্রস-বর্ডার রেমিট্যান্স করেসপন্ডেন্ট ব্যাংক (যদি প্রয়োজন হয়)**

> মনে রাখবেন, এটি ক্রস-বর্ডার রেমিট্যান্স করেসপন্ডেন্ট (মধ্যস্থ) ব্যাংকের তথ্য, প্রাপক ব্যাংকের তথ্য নয়। রেমিট্যান্স পাঠানোর ব্যাংককে জিজ্ঞাসা করুন, ক্রস-বর্ডার রেমিট্যান্স করেসপন্ডেন্ট ব্যাংকের তথ্য প্রয়োজন কিনা।

- হংকং ডলার, চীনা ইউয়ান ও মার্কিন ডলার রেমিট্যান্সের করেসপন্ডেন্ট ব্যাংক হলো Citibank:
  - ব্যাংকের নাম: Citibank N.A. Hong Kong
  - SWIFT Code: `CITIHKHXXXX`
  - ব্যাংক কোড: 006
  - শাখার নাম: Hong Kong Branch
  - শাখা কোড: 391
  - ব্যাংকের ঠিকানা: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong
- অন্যান্য মুদ্রায় রেমিট্যান্সের করেসপন্ডেন্ট ব্যাংক হলো BNY Mellon:
  - ব্যাংকের নাম: THE BANK OF NEW YORK MELLON
  - SWIFT Code: `IRVTUS3NXXX`
  - ব্যাংকের ঠিকানা: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## English

সম্পূর্ণ ইংরেজি ডকুমেন্টেশনের জন্য [README-EN.md](../../../README-EN.md) দেখুন।

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

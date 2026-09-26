# Security Go — আক্রমণ সনাক্তকরণ লাইব্রেরি

[简体中文](../../../README.md) · [English](../../../README-EN.md) · [API ইন্টারফেস ডকুমেন্ট](api.md)

Go ভাষায় লেখা আক্রমণ সনাক্তকরণ প্যাকেজ, যা কভার করে **৩৬টি ডিটেক্টর** (detector), **৬টি প্রধান আক্রমণ শ্রেণী**, **৩টি প্লাগেবল স্টোরেজ ব্যাকএন্ড** (backend)। ইউনিফাইড ইন্টারফেস + রেজিস্ট্রি (registry) প্যাটার্ন, বিশুদ্ধ ডিটেকশন লাইব্রেরি, যেকোনো Go HTTP ফ্রেমওয়ার্কের সাথে মানিয়ে নেওয়া যায়।

<p align="center">
  <img src="../../../pet/pet.svg" width="190" alt="Sentinel Gopher">
  <br>
  <sub>প্রজেক্টের মাসকট <b>Sentinel Gopher</b> (哨兵鼠) — ঢাল হাতে পাহারায় দাঁড়ানো একটি Go গোফার।<br>ঢালের <b>৩৬</b> সংখ্যাটি ডিটেক্টরের সংখ্যা; আর আতশকাচটি প্রতিটি রিকোয়েস্টের স্ক্যান।</sub>
</p>

[আর্কিটেকচার](#ডিজাইন-আর্কিটেকচার) · [বৈশিষ্ট্য](#বাস্তবায়িত-বৈশিষ্ট্য) · [জীবনচক্র](#জীবনচক্র) · [প্রকল্প কাঠামো](#প্রকল্প-কাঠামো) · [মাসকট](#মাসকট)

## ডিজাইনের ধারণা

### মূল নীতি

- **শূন্য-নির্ভরতা ডিটেকশন** — সব ডিটেক্টর শুধুমাত্র Go স্ট্যান্ডার্ড লাইব্রেরির `regexp` ব্যবহার করে, কোনো বাহ্যিক নির্ভরতা নেই
- **ইউনিফাইড ইন্টারফেস** — প্রতিটি ডিটেক্টর `Detector` ইন্টারফেস (`Name()` + `Detect()`) বাস্তবায়ন করে, `Engine` রেজিস্ট্রির মাধ্যমে সমন্বিতভাবে পরিচালিত হয়
- **প্রি-কম্পাইলড রেজেক্স** — সব প্যাটার্ন `var` ইনিশিয়ালাইজেশনের সময় কম্পাইল হয়, রানটাইমে শূন্য ওভারহেড
- **চাহিদা অনুযায়ী কনফিগারেশন** — ইনজেকশন/প্রোটোকল/ডেটা/ফাইল ডিটেক্টর প্লাগ-এন্ড-প্লে; HTTP ভ্যালিডেটর ও সেশন নিরাপত্তা সনাক্তকরণের জন্য অ্যাপ্লিকেশন কাস্টম কনফিগারেশন প্রয়োজন

### ডিজাইন আর্কিটেকচার

![আর্কিটেকচার](../../../docs/images/architecture.svg)

> `session` প্যাকেজ `Engine` রেজিস্ট্রির মধ্য দিয়ে যায় না: সেশন ভ্যালিডেশনের জন্য সম্পূর্ণ `*http.Request` পড়া প্রয়োজন (token, ক্লায়েন্ট IP, User-Agent),
> এবং অ্যাপ্লিকেশনকে স্টোরেজ ও কী সরবরাহ করতে হয়, তাই এটি সরাসরি মিডলওয়্যার হিসেবে ব্যবহৃত হয়, নিচের "সেশন নিরাপত্তা কনফিগারেশন" অংশটি দেখুন।

### জীবনচক্র

একটি রিকোয়েস্টের সম্পূর্ণ চক্র — প্রবেশ থেকে শুরু করে সনাক্তকরণ পেরিয়ে স্তরভিত্তিক ব্যবস্থাপনা পর্যন্ত (IP ব্লক চক্র ও URL-ডিকোডের পর পুনঃস্ক্যানসহ), আর একটি সেশনের বাইন্ডিং থেকে বাতিল পর্যন্ত যাত্রা:

![জীবনচক্র](../../../docs/images/lifecycle.svg)

### তীব্রতার স্তর

| স্তর | বর্ণনা | সাধারণ দৃশ্য |
|------|--------|-------------|
| `SeverityLow` | কম ঝুঁকি | অবৈধ HTTP মেথড, Content-Type মেলে না |
| `SeverityMedium` | মাঝারি ঝুঁকি | দুর্বল সংকেত: CORS কনফিগারেশন সমস্যা, ওপেন রিডাইরেক্ট, GraphQL ইন্ট্রোস্পেকশন, এবং প্রতিটি ডিটেক্টর যে প্রসঙ্গহীন প্যাটার্নগুলো ইচ্ছাকৃতভাবে আলাদা রাখে (`../`, `on…=`, `javascript:`, `sleep(`, `sqlite_master`, ব্যাকটিক, `{#…#}`, `__proto__:`, PHP ম্যাজিক মেথড নাম) — টিউটোরিয়াল ও সাধারণ কনটেন্টে প্রচলিত |
| `SeverityHigh` | উচ্চ ঝুঁকি | শক্তিশালী সংকেত: XSS, SQL ইনজেকশন, SSRF, পাথ ট্রাভার্সাল, সেশন ব্যতিক্রম |
| `SeverityCritical` | গুরুতর | শক্তিশালী সংকেত: কমান্ড ইনজেকশন, JNDI, SSTI, XXE, ডেটা লিক, ডিসিরিয়ালাইজেশন (PHP সিরিয়ালাইজড অবজেক্ট / pickle / Java / .NET) |

## বাস্তবায়িত বৈশিষ্ট্য

### বৈশিষ্ট্যের সংক্ষিপ্ত বিবরণ

![বৈশিষ্ট্যের ডিজাইন](../../../docs/images/features.svg)

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

## প্রকল্প কাঠামো

```
security-go/
├── security.go            # কোর: Result / Severity / Detector ইন্টারফেস / Engine রেজিস্ট্রি
├── injection/             # ইনজেকশন ডিটেক্টর (10): xss, sql, command, nosql, ldap,
│                          #   xpath, jndi, ssi, graphql, ssti
├── protocol/              # প্রোটোকল ও রিকোয়েস্ট ডিটেক্টর (9): ssrf, xxe, header, host,
│                          #   smuggling, redirect, cors, websocket, dns_rebinding
├── data/                  # ডেটা ও সিরিয়ালাইজেশন ডিটেক্টর (5): deserialization, csv,
│                          #   mail, jwt, prototype_pollution
├── file/                  # ফাইল ও সংবেদনশীল-ডেটা ডিটেক্টর (3): path_traversal,
│                          #   upload, data_leak
├── httpval/               # HTTP প্রোটোকল ভ্যালিডেটর (7), প্রতিটির জন্য অ্যাপ-প্রদত্ত সেটিংস দরকার
├── session/               # সেশন নিরাপত্তা (2): session_guard, data_tamper
│                          #   Engine বাইপাস করে সরাসরি মিডলওয়্যার হিসেবে ব্যবহৃত হয়
├── storage/               # স্টোরেজ ব্যাকএন্ড
│   ├── storage.go         #   ব্যাকএন্ড ইন্টারফেস: Incr / Get / Block / IsBlocked / Close
│   ├── memory.go          #   Memory: Mutex + map, 30s পর ব্যাকগ্রাউন্ড পরিষ্কার
│   ├── file.go            #   File: JSON পার্সিস্টেন্স, Close-এ flush
│   └── redis/             #   Redis: নিজস্ব go.mod সহ আলাদা সাবমডিউল
├── all/                   # এক কলে ২৭টি জিরো-কনফিগ ডিটেক্টর রেজিস্টার
├── pet/                   # প্রজেক্ট মাসকট: এমবেডেড SVG (Calm/Watchful/Alarmed অবস্থাসহ) + স্টার্টআপ ব্যানার
├── docs/
│   ├── api.md             # API রেফারেন্স
│   ├── images/            # আর্কিটেকচার / বৈশিষ্ট্য / জীবনচক্রের SVG
│   ├── i18n/              # অনূদিত ডকুমেন্টেশন (১২টি ভাষা)
│   └── superpowers/       # ডিজাইন স্পেক, বাস্তবায়ন পরিকল্পনা, কোড রিভিউ রিপোর্ট
└── tests/                 # কভারেজ রিপোর্ট
```

প্রতিটি ডিটেক্টর প্যাকেজ `xxx.go`-এর সাথে `xxx_test.go` জোড়া লাগায়; `all` অতিরিক্তভাবে রিগ্রেশন টেস্ট বহন করে।

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
    all.RegisterAll(e) // এক কলে ২৭টি জিরো-কনফিগ ডিটেক্টর রেজিস্টার করে

    // একক সনাক্তকরণ
    r := e.Detect("xss", "<script>alert(1)</script>")
    fmt.Printf("শনাক্ত: %v, তীব্রতা: %d\n", r.Detected, r.Severity)

    // সম্পূর্ণ সনাক্তকরণ
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
            log.Printf("আক্রমণ শনাক্ত: [%s] %s", result.Name, result.Message)
        }
    }
}
```

### HTTP ভ্যালিডেটর কনফিগারেশন

```go
// মেথড ভ্যালিডেশন
e.Register(&httpval.Method{})

// রিকোয়েস্ট বডি সাইজের সীমা
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type হোয়াইটলিস্ট
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF Origin পরীক্ষা
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP ব্ল্যাকলিস্ট (স্বয়ংক্রিয় ব্লক: ৫টি আক্রমণ/60s → ১৫ মিনিট ব্লক)
mem := storage.NewMemory()
defer mem.Close()
bl := httpval.NewIPBlacklist(mem)
e.Register(bl)

// আক্রমণ রেকর্ড করুন
blocked, _ := bl.RecordAttack(clientIP)
```

### সেশন নিরাপত্তা কনফিগারেশন

`session` প্যাকেজ সরাসরি মিডলওয়্যার হিসেবে ব্যবহৃত হয়, `Engine`-এর মধ্য দিয়ে যায় না। স্টোরেজ অ্যাপ্লিকেশনকে নিজেই সরবরাহ করতে হয় (ডিফল্টভাবে মেমোরি ইমপ্লিমেন্টেশন দেওয়া হয়, Redis ইত্যাদি দিয়ে প্রতিস্থাপন করা যায়):

```go
import "github.com/erikwang2013/security-go/session"

st := session.NewMemoryStore()
defer st.Close()

tr := session.NewTracker(st)
tr.CountryOf = geo.Lookup // ঐচ্ছিক: দেশ-পারাপার লগইন ধরতে GeoIP যুক্ত করুন

// সফল লগইনের পর সেশন বাইন্ড করুন (token আসে আপনার লগইন ফ্লো থেকে)
// দূরবর্তী লগইন সনাক্তকরণ: ব্যবহারকারীর আগের সাবনেটের সাথে মিলিয়ে দেখুন, নতুন সাবনেট হলেই সতর্ক করুন
if res := tr.Observe("user-1", r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
if err := tr.Issue(token, r); err != nil {      // token বাইন্ড → IP সাবনেট / UA / ডিভাইস ফিঙ্গারপ্রিন্ট
    http.Error(w, "session error", http.StatusInternalServerError)
    return
}

// রুট সুরক্ষা: হাইজ্যাক বা দূরবর্তী লগইনে সরাসরি 401 ফেরান
mux.Handle("/api/", tr.Guard(apiHandler))

// অথবা শুধু সনাক্ত করে নিজেই সিদ্ধান্ত নিন
if res := tr.Check(r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}

// লগআউট
tr.Revoke(token)
```

ডেটা ট্যাম্পারিং সনাক্তকরণ: ক্লায়েন্ট ও সার্ভার একটি শেয়ারড কী ব্যবহার করে, ক্লায়েন্ট প্যারামিটারে সিগনেচার করে, সার্ভার পুনরায় হিসাব করে যাচাই করে:

```go
signer := session.NewSigner(secret, storage.NewMemory()) // দ্বিতীয় আর্গুমেন্টটি সিগনেচার রিপ্লে আটকায়, nil হতে পারে

sig, _ := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // ক্লায়েন্ট: প্যারামিটারের সাথে 함께 পাঠান

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
        Severity: security.SeverityHigh, Message: "ক্ষতিকর কনটেন্ট শনাক্ত",
    }
}

e.Register(&MyDetector{})
```

### মাসকট

`pet` প্যাকেজ `go:embed`-এর মাধ্যমে কম্পাইল-সময়ে Sentinel Gopher-কে SVG হিসেবে এমবেড করে — রানটাইমে কোনো ফাইল-নির্ভরতা নেই, কোনো তৃতীয়-পক্ষ নির্ভরতাও যোগ হয় না:

```go
import "github.com/erikwang2013/security-go/pet"

log.Println(pet.Banner())              // স্টার্টআপ ব্যানার: টার্মিনাল-বান্ধব প্লেইন টেক্সট
http.Handle("/pet.svg", pet.Handler()) // ডিবাগ রুট: image/svg+xml হিসেবে পরিবেশিত, একদিন ক্যাশ করা
svg := pet.SVG()                       // অথবা কাঁচা SVG বাইট নিন
```

মাসকট কোনো স্থির ছবি নয় — এটিকে চালায় **শনাক্তকরণের ফলাফল**। `pet.MoodOf` একটি স্ক্যানকে তিনটি অবস্থায় ভাগ করে, আর সেই অনুযায়ী ঢাল, রাডার ও আতশকাচের রং বদলায়:

| অবস্থা | কখন সক্রিয় হয় | দেখতে কেমন |
|------|-----------|------------|
| `Calm` | স্ক্যান পরিষ্কার | সায়ান (উপরের স্থির ছবি) |
| `Watchful` | কিছু সক্রিয় হয়েছে, তবে High বা Critical নয় | অ্যাম্বার |
| `Alarmed` | অন্তত একটি High বা Critical | লাল, সঙ্গে একটি সতর্কতা বলয় |

<p align="center">
  <img src="../../../pet/pet.svg" width="140" alt="Calm — সায়ান">
  <img src="../../../pet/mood-watchful.svg" width="140" alt="Watchful — অ্যাম্বার">
  <img src="../../../pet/mood-alarmed.svg" width="140" alt="Alarmed — লাল, সঙ্গে একটি সতর্কতা বলয়">
  <br>
  <sub><b>Calm</b> · <b>Watchful</b> · <b>Alarmed</b></sub>
</p>

ইঞ্জিনের সাথে যুক্ত করলে পাবেন লাইভ ট্রাফিক অনুসরণ করা থ্রেট-স্টেট ছবি:

```go
http.Handle("/pet.svg", pet.MoodHandler(func(r *http.Request) pet.Mood {
    return pet.MoodOf(e.DetectRequest(r))
}))
```

`MoodHandler` `Cache-Control: no-store` পাঠায় — স্থির `Handler`-এর বিপরীতে এর আউটপুট প্রতি স্ক্যানে বদলায়, তাই এক দিনের ক্যাশে বাসি অবস্থা দেখাবে।

### সম্পর্কিত ডকুমেন্টেশন

- [API ইন্টারফেস ডকুমেন্ট](api.md) — কোর টাইপ, Detector/Engine ইন্টারফেস, স্টোরেজ ব্যাকএন্ড ইন্টারফেস, HTTP ভ্যালিডেটর
- [ডিজাইন স্পেক](specs/2026-07-29-attack-detection-design.md) — প্যাকেজ স্ট্রাকচার, ডিটেক্টর ডিরেক্টরি
- [বাস্তবায়ন পরিকল্পনা](plans/2026-07-29-attack-detection-plan.md) — ধাপে ধাপে টাস্ক পরিকল্পনা ও বাস্তবায়ন বিচ্যুতির তুলনা
- [কোড রিভিউ রিপোর্ট](reports/2026-07-29-code-review-report.md) — বাগ ফিক্স, টেস্ট কভারেজ, আর্কিটেকচার মূল্যায়ন
- [কোড রিভিউ রিপোর্ট v2](reports/2026-07-29-code-review-report-v2.md) — দ্বিতীয় পাস: 4টি সমস্যা মেরামত করা হয়েছে, 18টি টেস্ট ফাইল যোগ করা হয়েছে

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

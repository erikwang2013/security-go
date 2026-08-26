# আক্রমণ সনাক্তকরণ প্যাকেজ — বাস্তবায়ন পরিকল্পনা

> **এজেন্টিক ওয়ার্কারদের জন্য:** আবশ্যক সাব-স্কিল: এই পরিকল্পনাটি টাস্ক-বাই-টাস্ক বাস্তবায়নের জন্য superpowers:subagent-driven-development (প্রস্তাবিত) অথবা superpowers:executing-plans ব্যবহার করুন।

**লক্ষ্য:** বিশুদ্ধ Go আক্রমণ সনাক্তকরণ লাইব্রেরি তৈরি করা, যাতে ৫টি শ্রেণীতে ৩২টি ডিটেক্টর, ৩টি প্লাগেবল স্টোরেজ ব্যাকএন্ড এবং একটি ইউনিফাইড Engine রেজিস্ট্রি থাকবে। **অবস্থা: সম্পন্ন (2026-07-29)।**

**আর্কিটেকচার:** ফ্ল্যাট ইন্টারফেস ডিজাইন — প্রতিটি ডিটেক্টর `Detector` (Name + Detect) বাস্তবায়ন করে। প্রি-কম্পাইলড রেজেক্স প্যাটার্ন। Engine রেজিস্ট্রি, নাম-ভিত্তিক লুকআপ এবং সম্পূর্ণ HTTP রিকোয়েস্ট স্ক্যানিংয়ের জন্য `DetectRequest` প্রদান করে। RegisterAll-এর অবস্থান `all/all.go`-তে (আলাদা প্যাকেজ)।

**টেক স্ট্যাক:** Go 1.21+, স্ট্যান্ডার্ড লাইব্রেরির `regexp` + `net/http`, Redis ব্যাকএন্ডের জন্য `go-redis` (অপশনাল সাবমডিউল `storage/redis/`)।

---

### টাস্ক 1: Go মডিউল ও কোর টাইপ ইনিশিয়ালাইজেশন

**ফাইল:**
- তৈরি করুন: `go.mod`
- তৈরি করুন: `security.go`

- [x] **ধাপ 1: Go মডিউল ইনিশিয়ালাইজেশন**

```bash
cd /home/wwwroot/bag/security-go && go mod init github.com/erikwang2013/security-go
```

- [x] **ধাপ 2: security.go তৈরি করুন — Result, Severity, Detector interface, Engine**

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

- [x] **ধাপ 3: বিল্ড** — `go build ./...`
- [x] **ধাপ 4: কমিট** — `feat: initialize Go module with core types and Engine`

---

### টাস্ক 2: স্টোরেজ ব্যাকএন্ড ইন্টারফেস ও মেমোরি

**ফাইল:**
- তৈরি করুন: `storage/storage.go`
- তৈরি করুন: `storage/memory.go`

- [x] **ধাপ 1: storage/storage.go** — Backend ইন্টারফেস (Incr, Get, Block, IsBlocked, Close)
- [x] **ধাপ 2: storage/memory.go** — sync.Map ভিত্তিক ইমপ্লিমেন্টেশন, TTL reap goroutine সহ
- [x] **ধাপ 3: বিল্ড** — `go build ./storage/...`
- [x] **ধাপ 4: কমিট** — `feat: add storage interface and memory backend`

---

### টাস্ক 3: ফাইল ও Redis স্টোরেজ

**ফাইল:**
- তৈরি করুন: `storage/file.go`
- তৈরি করুন: `storage/redis.go`
- পরিবর্তন করুন: `go.mod` (go-redis ডিপেন্ডেন্সি যোগ)

- [x] **ধাপ 1: storage/file.go** — lazy flush সহ JSON ফাইল পার্সিস্টেন্স
- [x] **ধাপ 2: storage/redis.go** — go-redis/v9 ব্যবহার করে Redis ব্যাকএন্ড
- [x] **ধাপ 3: বিল্ড** — `go build ./storage/...`
- [x] **ধাপ 4: কমিট** — `feat: add file and redis storage backends`

---

### টাস্ক 4: ইনজেকশন ডিটেক্টর — XSS, SQL

**ফাইল:**
- তৈরি করুন: `injection/xss.go`
- তৈরি করুন: `injection/sql.go`

- [x] **ধাপ 1: injection/xss.go** — `<script>`, `on[a-z]+=`, `javascript:`, SVG/CSS প্যাটার্ন
- [x] **ধাপ 2: injection/sql.go** — UNION SELECT (`/**/` বাইপাস সহ), sleep/benchmark, বুলিয়ান ব্লাইন্ড, স্কিমা এনুমারেশন, স্টোর্ড প্রসিডিউর
- [x] **ধাপ 3: বিল্ড** — `go build ./injection/...`
- [x] **ধাপ 4: কমিট** — `feat: add XSS and SQL injection detectors`

---

### টাস্ক 5: ইনজেকশন ডিটেক্টর — কমান্ড, NoSQL, LDAP, XPATH

**ফাইল:**
- তৈরি করুন: `injection/command.go`
- তৈরি করুন: `injection/nosql.go`
- তৈরি করুন: `injection/ldap.go`
- তৈরি করুন: `injection/xpath.go`

- [x] **ধাপ 1: injection/command.go** — ব্যাকটিক, `$()`, পাইপ, `/dev/tcp`, PHP exec ফাংশন
- [x] **ধাপ 2: injection/nosql.go** — MongoDB `$ne`/`$gt`/`$regex`/`$where`, অথ বাইপাস
- [x] **ধাপ 3: injection/ldap.go** — ফিল্টার অপারেটর `(`, `)`, `&`, `|`, `*`
- [x] **ধাপ 4: injection/xpath.go** — বুলিয়ান বাইপাস, string-length, count
- [x] **ধাপ 5: বিল্ড ও কমিট**

---

### টাস্ক 6: ইনজেকশন ডিটেক্টর — JNDI, SSI, GraphQL, SSTI

**ফাইল:**
- তৈরি করুন: `injection/jndi.go`
- তৈরি করুন: `injection/ssi.go`
- তৈরি করুন: `injection/graphql.go`
- তৈরি করুন: `injection/ssti.go`

- [x] **ধাপ 1: injection/jndi.go** — `${jndi:ldap://`, `${lower:j}`, `${env:}`, rmi/dns প্রোটোকল
- [x] **ধাপ 2: injection/ssi.go** — `<!--#exec`, `<!--#include`, `<!--#echo`
- [x] **ধাপ 3: injection/graphql.go** — `__schema`, `__type`, গভীর নেস্টেড কোয়েরি, মিউটেশন
- [x] **ধাপ 4: injection/ssti.go** — Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO
- [x] **ধাপ 5: বিল্ড ও কমিট**

---

### টাস্ক 7: প্রোটোকল ডিটেক্টর — SSRF, XXE, হেডার ইনজেকশন

**ফাইল:**
- তৈরি করুন: `protocol/ssrf.go`
- তৈরি করুন: `protocol/xxe.go`
- তৈরি করুন: `protocol/header_injection.go`

- [x] **ধাপ 1: protocol/ssrf.go** — অভ্যন্তরীণ IP, 169.254.169.254, IPv6 লুপব্যাক, gopher/dict
- [x] **ধাপ 2: protocol/xxe.go** — `<!ENTITY SYSTEM/PUBLIC`, প্যারামিটার এন্টিটি, DOCTYPE
- [x] **ধাপ 3: protocol/header_injection.go** — CRLF, Set-Cookie/Location ইনজেকশন
- [x] **ধাপ 4: বিল্ড ও কমিট**

---

### টাস্ক 8: প্রোটোকল ডিটেক্টর — Host হেডার, রিকোয়েস্ট স্মাগলিং, ওপেন রিডাইরেক্ট, CORS, WebSocket, DNS রিবাইন্ডিং

**ফাইল:**
- তৈরি করুন: `protocol/host_header.go`
- তৈরি করুন: `protocol/request_smuggling.go`
- তৈরি করুন: `protocol/open_redirect.go`
- তৈরি করুন: `protocol/cors.go`
- তৈরি করুন: `protocol/websocket.go`
- তৈরি করুন: `protocol/dns_rebinding.go`

- [x] **ধাপ 1: সব 6টি প্রোটোকল ডিটেক্টর** — প্রতিটির জন্য একটি ফাইল, প্রি-কম্পাইলড রেজেক্স প্যাটার্ন
- [x] **ধাপ 2: বিল্ড ও কমিট**

---

### টাস্ক 9: HTTP ভ্যালিডেশন ডিটেক্টর

**ফাইল:**
- তৈরি করুন: `httpval/method.go`
- তৈরি করুন: `httpval/body_size.go`
- তৈরি করুন: `httpval/content_type.go`
- তৈরি করুন: `httpval/csrf_origin.go`
- তৈরি করুন: `httpval/ip_blacklist.go`

- [x] **ধাপ 1: httpval/method.go** — হোয়াইটলিস্ট GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH
- [x] **ধাপ 2: httpval/body_size.go** — সর্বোচ্চ সাইজ চেক, ডিফল্ট 10MB
- [x] **ধাপ 3: httpval/content_type.go** — MIME হোয়াইটলিস্ট
- [x] **ধাপ 4: httpval/csrf_origin.go** — ক্রস-অরিজিন Origin বনাম Host মিল
- [x] **ধাপ 5: httpval/ip_blacklist.go** — উইন্ডো রেট লিমিট (5/60s → 15min ব্লক), storage.Backend ব্যবহার করে
- [x] **ধাপ 6: বিল্ড ও কমিট**

---

### টাস্ক 10: ডেটা/সিরিয়ালাইজেশন ডিটেক্টর

**ফাইল:**
- তৈরি করুন: `data/deserialization.go`
- তৈরি করুন: `data/csv_injection.go`
- তৈরি করুন: `data/mail_header.go`
- তৈরি করুন: `data/jwt_attack.go`
- তৈরি করুন: `data/prototype_pollution.go`

- [x] **ধাপ 1: data/deserialization.go** — PHP `O:সংখ্যা:`, `C:সংখ্যা:`, unserialize(), ম্যাজিক মেথড
- [x] **ধাপ 2: data/csv_injection.go** — `=cmd|`, `@SUM(`, `+`, `-` ফর্মুলা প্রিফিক্স
- [x] **ধাপ 3: data/mail_header.go** — Bcc/Cc/From/To ইনজেকশন, MIME multipart
- [x] **ধাপ 4: data/jwt_attack.go** — alg:none, kid পাথ ট্রাভার্সাল, খালি সিগনেচার (স্ট্রাকচারাল ডিকোড)
- [x] **ধাপ 5: data/prototype_pollution.go** — `__proto__`, `constructor`, `__defineGetter__/Setter__`
- [x] **ধাপ 6: বিল্ড ও কমিট**

---

### টাস্ক 11: ফাইল ও সংবেদনশীল ডেটা ডিটেক্টর

**ফাইল:**
- তৈরি করুন: `file/path_traversal.go`
- তৈরি করুন: `file/upload.go`
- তৈরি করুন: `file/data_leak.go`

- [x] **ধাপ 1: file/path_traversal.go** — `../`, `..\\`, php://filter, null বাইট, URL এনকোডিং বাইপাস
- [x] **ধাপ 2: file/upload.go** — এক্সটেনশন হোয়াইটলিস্ট + PHP ট্যাগ কনটেন্ট স্ক্যান
- [x] **ধাপ 3: file/data_leak.go** — ক্রেডিট কার্ড, AWS কী, প্রাইভেট কী, DB কানেকশন স্ট্রিং, API টোকেন, JWT সিক্রেট
- [x] **ধাপ 4: বিল্ড ও কমিট**

---

### টাস্ক 12: Engine ইন্টিগ্রেশন — RegisterAll

**ফাইল:**
- পরিবর্তন করুন: `security.go`

- [x] **ধাপ 1: RegisterAll() যোগ করুন** — সব 32টি বিল্ট-ইন ডিটেক্টর নিবন্ধন করে
- [x] **ধাপ 2: বিল্ড** — `go build ./...`
- [x] **ধাপ 3: কমিট** — `feat: add RegisterAll for built-in detectors`

---

### টাস্ক 13: টেস্ট

**ফাইল:**
- তৈরি করুন: `security_test.go`
- তৈরি করুন: `injection/xss_test.go`, `sql_test.go`, `jndi_test.go`, `ssti_test.go`
- তৈরি করুন: `protocol/ssrf_test.go`
- তৈরি করুন: `file/path_traversal_test.go`, `data_leak_test.go`
- তৈরি করুন: `data/jwt_attack_test.go`
- তৈরি করুন: `storage/memory_test.go`

- [x] **ধাপ 1: টেস্ট লিখুন** — প্রতিটিতে পজিটিভ ও নেগেটিভ টেস্ট কেস
- [x] **ধাপ 2: চালান** — `go test ./... -v`
- [x] **ধাপ 3: কমিট** — `test: add core engine and detector tests`

---

### টাস্ক 14: বাস্তবায়ন-পরবর্তী কোড রিভিউ ও ফিক্স (2026-07-29)

- [x] **সম্পূর্ণ কোড রিভিউ** — 42টি Go সোর্স ফাইল, 8টি প্যাকেজ
- [x] **Bug ফিক্স #1** — `storage/file.go`: JSON সিরিয়ালাইজেশন এরর নীরবে উপেক্ষা করা হতো → এরর চেক করে রিটার্ন করা হয়েছে
- [x] **Bug ফিক্স #2** — `httpval/content_type.go`: খালি AllowList সব Content-Type পাস করত → deny-all ডিফল্ট মান
- [x] **Bug ফিক্স #3** — `protocol/xxe.go`: `&[a-z]+;` বৈধ HTML এন্টিটি ভুলভাবে ম্যাচ করত → পরিচিত ম্যালিসিয়াস প্রোটোকলের তালিকায় সংকুচিত
- [x] **httpval টেস্ট যোগ করা** — 32টি টেস্ট কেস, 5টি ডিটেক্টর কভার করে (BodySize, ContentType, CSRFOrigin, IPBlacklist, Method)
- [x] **সম্পূর্ণ টেস্ট** — `go test -count=1 ./...` 7/7 প্যাকেজ পাস, `go vet` শূন্য ওয়ার্নিং

---

## প্রকৃত বনাম পরিকল্পিত বিচ্যুতি

| পরিকল্পনা | প্রকৃত | কারণ |
|-----------|--------|------|
| RegisterAll `security.go`-তে | `all/all.go` আলাদা প্যাকেজ | সার্কুলার রেফারেন্স এড়াতে; httpval storage-এর উপর নির্ভরশীল কিন্তু অন্য ডিটেক্টর নয় |
| Redis রুট go.mod-এ | `storage/redis/` সাবমডিউল | অপশনাল ডিপেন্ডেন্সি আলাদা রাখতে |
| Receiver সব পয়েন্টার | protocol প্যাকেজ ভ্যালু রিসিভার ব্যবহার করত | ✅ v2 রিভিউতে সব পয়েন্টার রিসিভারে পরিবর্তন করা হয়েছে |
| টাস্ক 4-12 Build & Commit | ধাপে ধাপে কমিট করা হয়নি | সব কোড একবারে বাস্তবায়িত হয়েছে |

## টেস্ট কভারেজ সারসংক্ষেপ

| প্যাকেজ | টেস্ট ফাইল | টেস্ট সংখ্যা |
|---------|------------|--------------|
| security | security_test.go | 5 |
| data | deserialization_test.go, csv_injection_test.go, mail_header_test.go, jwt_attack_test.go, prototype_pollution_test.go | 8 |
| file | path_traversal_test.go, data_leak_test.go, upload_test.go | 5 |
| httpval | httpval_test.go | 32 |
| injection | xss_test.go, sql_test.go, command_test.go, nosql_test.go, ldap_test.go, xpath_test.go, jndi_test.go, ssi_test.go, graphql_test.go, ssti_test.go | 10 |
| protocol | ssrf_test.go, xxe_test.go, header_injection_test.go, host_header_test.go, request_smuggling_test.go, open_redirect_test.go, cors_test.go, websocket_test.go, dns_rebinding_test.go | 9 |
| storage | memory_test.go | 4 |
| all | (নেই) | 0 |

> সম্পূর্ণ রিপোর্ট দেখুন: `../reports/2026-07-29-code-review-report-v2.md`

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

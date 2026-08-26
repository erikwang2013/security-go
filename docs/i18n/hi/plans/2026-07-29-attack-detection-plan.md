# Attack Detection Package — कार्यान्वयन योजना

> **एजेंटिक वर्कर के लिए:** आवश्यक उप-कौशल: इस योजना को कार्य-दर-कार्य लागू करने के लिए superpowers:subagent-driven-development (अनुशंसित) या superpowers:executing-plans का उपयोग करें।

**लक्ष्य:** 5 श्रेणियों में 32 डिटेक्टर, 3 प्लगेबल स्टोरेज बैकएंड और एक एकीकृत Engine रजिस्ट्री वाली शुद्ध Go आक्रमण-पता लगाने वाली लाइब्रेरी बनाना। **स्थिति: पूर्ण (2026-07-29)।**

**आर्किटेक्चर:** फ्लैट इंटरफ़ेस डिज़ाइन — प्रत्येक डिटेक्टर `Detector` (Name + Detect) लागू करता है। प्री-कंपाइल्ड regex पैटर्न। Engine रजिस्ट्री, नाम-आधारित लुकअप और पूर्ण HTTP अनुरोध स्कैनिंग के लिए `DetectRequest` प्रदान करता है। RegisterAll `all/all.go` में रहता है (अलग पैकेज)।

**टेक स्टैक:** Go 1.21+, मानक लाइब्रेरी `regexp` + `net/http`, Redis बैकएंड के लिए `go-redis` (वैकल्पिक सबमॉड्यूल `storage/redis/` पर)।

---

### कार्य 1: Go मॉड्यूल और मुख्य प्रकार इनिशियलाइज़ करें

**फ़ाइलें:**
- बनाएँ: `go.mod`
- बनाएँ: `security.go`

- [x] **चरण 1: Go मॉड्यूल इनिशियलाइज़ करें**

```bash
cd /home/wwwroot/bag/security-go && go mod init github.com/erikwang2013/security-go
```

- [x] **चरण 2: security.go बनाएँ — Result, Severity, Detector interface, Engine**

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

- [x] **चरण 3: बिल्ड** — `go build ./...`
- [x] **चरण 4: कमिट** — `feat: initialize Go module with core types and Engine`

---

### कार्य 2: स्टोरेज बैकएंड इंटरफ़ेस और Memory

**फ़ाइलें:**
- बनाएँ: `storage/storage.go`
- बनाएँ: `storage/memory.go`

- [x] **चरण 1: storage/storage.go** — Backend interface (Incr, Get, Block, IsBlocked, Close)
- [x] **चरण 2: storage/memory.go** — sync.Map आधारित कार्यान्वयन, TTL reap goroutine के साथ
- [x] **चरण 3: बिल्ड** — `go build ./storage/...`
- [x] **चरण 4: कमिट** — `feat: add storage interface and memory backend`

---

### कार्य 3: File और Redis स्टोरेज

**फ़ाइलें:**
- बनाएँ: `storage/file.go`
- बनाएँ: `storage/redis.go`
- संशोधित करें: `go.mod` (go-redis निर्भरता जोड़ें)

- [x] **चरण 1: storage/file.go** — लेज़ी flush के साथ JSON फ़ाइल पर्सिस्टेंस
- [x] **चरण 2: storage/redis.go** — go-redis/v9 उपयोग करते हुए Redis बैकएंड
- [x] **चरण 3: बिल्ड** — `go build ./storage/...`
- [x] **चरण 4: कमिट** — `feat: add file and redis storage backends`

---

### कार्य 4: इंजेक्शन डिटेक्टर — XSS, SQL

**फ़ाइलें:**
- बनाएँ: `injection/xss.go`
- बनाएँ: `injection/sql.go`

- [x] **चरण 1: injection/xss.go** — `<script>`, `on[a-z]+=`, `javascript:`, SVG/CSS पैटर्न
- [x] **चरण 2: injection/sql.go** — UNION SELECT (`/**/` बायपास सहित), sleep/benchmark, बूलियन ब्लाइंड, schema enum, stored proc
- [x] **चरण 3: बिल्ड** — `go build ./injection/...`
- [x] **चरण 4: कमिट** — `feat: add XSS and SQL injection detectors`

---

### कार्य 5: इंजेक्शन डिटेक्टर — Command, NoSQL, LDAP, XPATH

**फ़ाइलें:**
- बनाएँ: `injection/command.go`
- बनाएँ: `injection/nosql.go`
- बनाएँ: `injection/ldap.go`
- बनाएँ: `injection/xpath.go`

- [x] **चरण 1: injection/command.go** — backtick, `$()`, pipe, `/dev/tcp`, PHP exec फ़ंक्शन
- [x] **चरण 2: injection/nosql.go** — MongoDB `$ne`/`$gt`/`$regex`/`$where`, auth bypass
- [x] **चरण 3: injection/ldap.go** — फ़िल्टर ऑपरेटर `(`, `)`, `&`, `|`, `*`
- [x] **चरण 4: injection/xpath.go** — बूलियन बायपास, string-length, count
- [x] **चरण 5: बिल्ड और कमिट**

---

### कार्य 6: इंजेक्शन डिटेक्टर — JNDI, SSI, GraphQL, SSTI

**फ़ाइलें:**
- बनाएँ: `injection/jndi.go`
- बनाएँ: `injection/ssi.go`
- बनाएँ: `injection/graphql.go`
- बनाएँ: `injection/ssti.go`

- [x] **चरण 1: injection/jndi.go** — `${jndi:ldap://`, `${lower:j}`, `${env:}`, rmi/dns प्रोटोकॉल
- [x] **चरण 2: injection/ssi.go** — `<!--#exec`, `<!--#include`, `<!--#echo`
- [x] **चरण 3: injection/graphql.go** — `__schema`, `__type`, डीप-नेस्टेड query, mutation
- [x] **चरण 4: injection/ssti.go** — Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO
- [x] **चरण 5: बिल्ड और कमिट**

---

### कार्य 7: प्रोटोकॉल डिटेक्टर — SSRF, XXE, Header Injection

**फ़ाइलें:**
- बनाएँ: `protocol/ssrf.go`
- बनाएँ: `protocol/xxe.go`
- बनाएँ: `protocol/header_injection.go`

- [x] **चरण 1: protocol/ssrf.go** — इंटरनल IP, 169.254.169.254, IPv6 loopback, gopher/dict
- [x] **चरण 2: protocol/xxe.go** — `<!ENTITY SYSTEM/PUBLIC`, पैरामीटर एंटिटी, DOCTYPE
- [x] **चरण 3: protocol/header_injection.go** — CRLF, Set-Cookie/Location इंजेक्शन
- [x] **चरण 4: बिल्ड और कमिट**

---

### कार्य 8: प्रोटोकॉल डिटेक्टर — Host Header, Request Smuggling, Open Redirect, CORS, WebSocket, DNS Rebinding

**फ़ाइलें:**
- बनाएँ: `protocol/host_header.go`
- बनाएँ: `protocol/request_smuggling.go`
- बनाएँ: `protocol/open_redirect.go`
- बनाएँ: `protocol/cors.go`
- बनाएँ: `protocol/websocket.go`
- बनाएँ: `protocol/dns_rebinding.go`

- [x] **चरण 1: सभी 6 प्रोटोकॉल डिटेक्टर** — प्रत्येक एक फ़ाइल, प्री-कंपाइल्ड regex पैटर्न
- [x] **चरण 2: बिल्ड और कमिट**

---

### कार्य 9: HTTP वैलिडेशन डिटेक्टर

**फ़ाइलें:**
- बनाएँ: `httpval/method.go`
- बनाएँ: `httpval/body_size.go`
- बनाएँ: `httpval/content_type.go`
- बनाएँ: `httpval/csrf_origin.go`
- बनाएँ: `httpval/ip_blacklist.go`

- [x] **चरण 1: httpval/method.go** — व्हाइटलिस्ट GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH
- [x] **चरण 2: httpval/body_size.go** — अधिकतम साइज़ जाँच, डिफ़ॉल्ट 10MB
- [x] **चरण 3: httpval/content_type.go** — MIME व्हाइटलिस्ट
- [x] **चरण 4: httpval/csrf_origin.go** — क्रॉस-ओरिजिन Origin बनाम Host मेल
- [x] **चरण 5: httpval/ip_blacklist.go** — विंडो रेट लिमिट (5/60s → 15min बैन), storage.Backend उपयोग करता है
- [x] **चरण 6: बिल्ड और कमिट**

---

### कार्य 10: डेटा/सीरियलाइज़ेशन डिटेक्टर

**फ़ाइलें:**
- बनाएँ: `data/deserialization.go`
- बनाएँ: `data/csv_injection.go`
- बनाएँ: `data/mail_header.go`
- बनाएँ: `data/jwt_attack.go`
- बनाएँ: `data/prototype_pollution.go`

- [x] **चरण 1: data/deserialization.go** — PHP `O:अंक:`, `C:अंक:`, unserialize(), मैजिक मेथड
- [x] **चरण 2: data/csv_injection.go** — `=cmd|`, `@SUM(`, `+`, `-` फॉर्मूला प्रीफ़िक्स
- [x] **चरण 3: data/mail_header.go** — Bcc/Cc/From/To इंजेक्शन, MIME multipart
- [x] **चरण 4: data/jwt_attack.go** — alg:none, kid पाथ ट्रैवर्सल, खाली सिग्नेचर (संरचनात्मक डीकोड)
- [x] **चरण 5: data/prototype_pollution.go** — `__proto__`, `constructor`, `__defineGetter__/Setter__`
- [x] **चरण 6: बिल्ड और कमिट**

---

### कार्य 11: फ़ाइल और संवेदनशील डेटा डिटेक्टर

**फ़ाइलें:**
- बनाएँ: `file/path_traversal.go`
- बनाएँ: `file/upload.go`
- बनाएँ: `file/data_leak.go`

- [x] **चरण 1: file/path_traversal.go** — `../`, `..\\`, php://filter, null बाइट, URL-एन्कोडिंग बायपास
- [x] **चरण 2: file/upload.go** — एक्सटेंशन व्हाइटलिस्ट + PHP टैग कंटेंट स्कैन
- [x] **चरण 3: file/data_leak.go** — क्रेडिट कार्ड, AWS key, प्राइवेट key, DB कनेक्शन स्ट्रिंग, API टोकन, JWT secret
- [x] **चरण 4: बिल्ड और कमिट**

---

### कार्य 12: Engine इंटीग्रेशन — RegisterAll

**फ़ाइलें:**
- संशोधित करें: `security.go`

- [x] **चरण 1: RegisterAll() जोड़ें** — सभी 32 बिल्ट-इन डिटेक्टर पंजीकृत करता है
- [x] **चरण 2: बिल्ड** — `go build ./...`
- [x] **चरण 3: कमिट** — `feat: add RegisterAll for built-in detectors`

---

### कार्य 13: टेस्ट

**फ़ाइलें:**
- बनाएँ: `security_test.go`
- बनाएँ: `injection/xss_test.go`, `sql_test.go`, `jndi_test.go`, `ssti_test.go`
- बनाएँ: `protocol/ssrf_test.go`
- बनाएँ: `file/path_traversal_test.go`, `data_leak_test.go`
- बनाएँ: `data/jwt_attack_test.go`
- बनाएँ: `storage/memory_test.go`

- [x] **चरण 1: टेस्ट लिखें** — प्रत्येक में पॉज़िटिव और नेगेटिव टेस्ट केस
- [x] **चरण 2: चलाएँ** — `go test ./... -v`
- [x] **चरण 3: कमिट** — `test: add core engine and detector tests`

---

### कार्य 14: कार्यान्वयन-पश्चात कोड समीक्षा और फिक्स (2026-07-29)

- [x] **व्यापक कोड समीक्षा** — 42 Go स्रोत फ़ाइलें, 8 पैकेज
- [x] **Bug फिक्स #1** — `storage/file.go`: JSON सीरियलाइज़ेशन त्रुटि चुपचाप अनदेखी हो रही थी → अब त्रुटि जाँचकर वापस लौटाई जाती है
- [x] **Bug फिक्स #2** — `httpval/content_type.go`: खाली AllowList सभी Content-Type को पास कर देता था → deny-all डिफ़ॉल्ट
- [x] **Bug फिक्स #3** — `protocol/xxe.go`: `&[a-z]+;` वैध HTML एंटिटी को गलत तरीके से मैच कर रहा था → ज्ञात दुर्भावनापूर्ण प्रोटोकॉल सूची तक सीमित किया गया
- [x] **httpval टेस्ट जोड़े** — 32 टेस्ट केस, 5 डिटेक्टर कवर (BodySize, ContentType, CSRFOrigin, IPBlacklist, Method)
- [x] **पूर्ण टेस्ट** — `go test -count=1 ./...` 7/7 पैकेज पास, `go vet` शून्य चेतावनी

---

## वास्तविक बनाम नियोजित विचलन

| योजना | वास्तविक | कारण |
|------|----------|------|
| RegisterAll `security.go` में | `all/all.go` अलग पैकेज | सर्कुलर इम्पोर्ट से बचने के लिए; httpval storage पर निर्भर है लेकिन अन्य डिटेक्टर नहीं |
| Redis रूट go.mod में | `storage/redis/` सबमॉड्यूल | वैकल्पिक निर्भरता को अलग करने के लिए |
| Receiver एकरूप पॉइंटर | protocol पैकेज वैल्यू receiver उपयोग करता है | ✅ v2 समीक्षा में सभी को पॉइंटर receiver में बदल दिया गया |
| कार्य 4-12 Build और Commit | चरणबद्ध कमिट नहीं किए | सभी कोड एक बार में लागू किया गया |

## टेस्ट कवरेज सारांश

| पैकेज | टेस्ट फ़ाइलें | टेस्ट संख्या |
|----|---------|--------|
| security | security_test.go | 5 |
| data | deserialization_test.go, csv_injection_test.go, mail_header_test.go, jwt_attack_test.go, prototype_pollution_test.go | 8 |
| file | path_traversal_test.go, data_leak_test.go, upload_test.go | 5 |
| httpval | httpval_test.go | 32 |
| injection | xss_test.go, sql_test.go, command_test.go, nosql_test.go, ldap_test.go, xpath_test.go, jndi_test.go, ssi_test.go, graphql_test.go, ssti_test.go | 10 |
| protocol | ssrf_test.go, xxe_test.go, header_injection_test.go, host_header_test.go, request_smuggling_test.go, open_redirect_test.go, cors_test.go, websocket_test.go, dns_rebinding_test.go | 9 |
| storage | memory_test.go | 4 |
| all | (कोई नहीं) | 0 |

> पूर्ण रिपोर्ट के लिए `../reports/2026-07-29-code-review-report-v2.md` देखें

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

# Attack Detection Package — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a pure Go attack detection library with 32 detectors across 5 categories, 3 pluggable storage backends, and a unified Engine registry.

**Architecture:** Flat interface design — every detector implements `Detector` (Name + Detect). Pre-compiled regex patterns. Engine provides registry, by-name lookup, and `DetectRequest` for full HTTP request scanning.

**Tech Stack:** Go 1.21+, stdlib `regexp` + `net/http`, `go-redis` for Redis backend.

---

### Task 1: Initialize Go Module & Core Types

**Files:**
- Create: `go.mod`
- Create: `security.go`

- [ ] **Step 1: Init Go module**

```bash
cd /home/wwwroot/bag/security-go && go mod init github.com/bag/security-go
```

- [ ] **Step 2: Create security.go — Result, Severity, Detector interface, Engine**

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

- [ ] **Step 3: Build** — `go build ./...`
- [ ] **Step 4: Commit** — `feat: initialize Go module with core types and Engine`

---

### Task 2: Storage Backend Interface & Memory

**Files:**
- Create: `storage/storage.go`
- Create: `storage/memory.go`

- [ ] **Step 1: storage/storage.go** — Backend interface (Incr, Get, Block, IsBlocked, Close)
- [ ] **Step 2: storage/memory.go** — sync.Map based implementation with TTL reap goroutine
- [ ] **Step 3: Build** — `go build ./storage/...`
- [ ] **Step 4: Commit** — `feat: add storage interface and memory backend`

---

### Task 3: File & Redis Storage

**Files:**
- Create: `storage/file.go`
- Create: `storage/redis.go`
- Modify: `go.mod` (add go-redis dependency)

- [ ] **Step 1: storage/file.go** — JSON file persistence with lazy flush
- [ ] **Step 2: storage/redis.go** — Redis backend using go-redis/v9
- [ ] **Step 3: Build** — `go build ./storage/...`
- [ ] **Step 4: Commit** — `feat: add file and redis storage backends`

---

### Task 4: Injection Detectors — XSS, SQL

**Files:**
- Create: `injection/xss.go`
- Create: `injection/sql.go`

- [ ] **Step 1: injection/xss.go** — `<script>`, `on[a-z]+=`, `javascript:`, SVG/CSS patterns
- [ ] **Step 2: injection/sql.go** — UNION SELECT (with `/**/` bypass), sleep/benchmark, boolean blind, schema enum, stored proc
- [ ] **Step 3: Build** — `go build ./injection/...`
- [ ] **Step 4: Commit** — `feat: add XSS and SQL injection detectors`

---

### Task 5: Injection Detectors — Command, NoSQL, LDAP, XPATH

**Files:**
- Create: `injection/command.go`
- Create: `injection/nosql.go`
- Create: `injection/ldap.go`
- Create: `injection/xpath.go`

- [ ] **Step 1: injection/command.go** — backtick, `$()`, pipe, `/dev/tcp`, PHP exec functions
- [ ] **Step 2: injection/nosql.go** — MongoDB `$ne`/`$gt`/`$regex`/`$where`, auth bypass
- [ ] **Step 3: injection/ldap.go** — filter operators `(`, `)`, `&`, `|`, `*`
- [ ] **Step 4: injection/xpath.go** — boolean bypass, string-length, count
- [ ] **Step 5: Build & Commit**

---

### Task 6: Injection Detectors — JNDI, SSI, GraphQL, SSTI

**Files:**
- Create: `injection/jndi.go`
- Create: `injection/ssi.go`
- Create: `injection/graphql.go`
- Create: `injection/ssti.go`

- [ ] **Step 1: injection/jndi.go** — `${jndi:ldap://`, `${lower:j}`, `${env:}`, rmi/dns protocols
- [ ] **Step 2: injection/ssi.go** — `<!--#exec`, `<!--#include`, `<!--#echo`
- [ ] **Step 3: injection/graphql.go** — `__schema`, `__type`, deep nested query, mutation
- [ ] **Step 4: injection/ssti.go** — Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO
- [ ] **Step 5: Build & Commit**

---

### Task 7: Protocol Detectors — SSRF, XXE, Header Injection

**Files:**
- Create: `protocol/ssrf.go`
- Create: `protocol/xxe.go`
- Create: `protocol/header_injection.go`

- [ ] **Step 1: protocol/ssrf.go** — internal IP, 169.254.169.254, IPv6 loopback, gopher/dict
- [ ] **Step 2: protocol/xxe.go** — `<!ENTITY SYSTEM/PUBLIC`, parameter entities, DOCTYPE
- [ ] **Step 3: protocol/header_injection.go** — CRLF, Set-Cookie/Location injection
- [ ] **Step 4: Build & Commit**

---

### Task 8: Protocol Detectors — Host Header, Request Smuggling, Open Redirect, CORS, WebSocket, DNS Rebinding

**Files:**
- Create: `protocol/host_header.go`
- Create: `protocol/request_smuggling.go`
- Create: `protocol/open_redirect.go`
- Create: `protocol/cors.go`
- Create: `protocol/websocket.go`
- Create: `protocol/dns_rebinding.go`

- [ ] **Step 1: All 6 protocol detectors** — one file each, pre-compiled regex patterns
- [ ] **Step 2: Build & Commit**

---

### Task 9: HTTP Validation Detectors

**Files:**
- Create: `httpval/method.go`
- Create: `httpval/body_size.go`
- Create: `httpval/content_type.go`
- Create: `httpval/csrf_origin.go`
- Create: `httpval/ip_blacklist.go`

- [ ] **Step 1: httpval/method.go** — whitelist GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH
- [ ] **Step 2: httpval/body_size.go** — max size check, default 10MB
- [ ] **Step 3: httpval/content_type.go** — MIME whitelist
- [ ] **Step 4: httpval/csrf_origin.go** — cross-origin Origin vs Host match
- [ ] **Step 5: httpval/ip_blacklist.go** — window rate limit (5/60s → 15min ban), uses storage.Backend
- [ ] **Step 6: Build & Commit**

---

### Task 10: Data/Serialization Detectors

**Files:**
- Create: `data/deserialization.go`
- Create: `data/csv_injection.go`
- Create: `data/mail_header.go`
- Create: `data/jwt_attack.go`
- Create: `data/prototype_pollution.go`

- [ ] **Step 1: data/deserialization.go** — PHP `O:数字:`, `C:数字:`, unserialize(), magic methods
- [ ] **Step 2: data/csv_injection.go** — `=cmd|`, `@SUM(`, `+`, `-` formula prefix
- [ ] **Step 3: data/mail_header.go** — Bcc/Cc/From/To injection, MIME multipart
- [ ] **Step 4: data/jwt_attack.go** — alg:none, kid path traversal, empty signature (structural decode)
- [ ] **Step 5: data/prototype_pollution.go** — `__proto__`, `constructor`, `__defineGetter__/Setter__`
- [ ] **Step 6: Build & Commit**

---

### Task 11: File & Sensitive Data Detectors

**Files:**
- Create: `file/path_traversal.go`
- Create: `file/upload.go`
- Create: `file/data_leak.go`

- [ ] **Step 1: file/path_traversal.go** — `../`, `..\\`, php://filter, null byte, URL encoding bypass
- [ ] **Step 2: file/upload.go** — extension whitelist + PHP tag content scan
- [ ] **Step 3: file/data_leak.go** — credit card, AWS key, private key, DB conn string, API token, JWT secret
- [ ] **Step 4: Build & Commit**

---

### Task 12: Engine Integration — RegisterAll

**Files:**
- Modify: `security.go`

- [ ] **Step 1: Add RegisterAll()** — registers all 32 built-in detectors
- [ ] **Step 2: Build** — `go build ./...`
- [ ] **Step 3: Commit** — `feat: add RegisterAll for built-in detectors`

---

### Task 13: Tests

**Files:**
- Create: `security_test.go`
- Create: `injection/xss_test.go`, `sql_test.go`, `jndi_test.go`, `ssti_test.go`
- Create: `protocol/ssrf_test.go`
- Create: `file/path_traversal_test.go`, `data_leak_test.go`
- Create: `data/jwt_attack_test.go`
- Create: `storage/memory_test.go`

- [ ] **Step 1: Write tests** — each with positive and negative test cases
- [ ] **Step 2: Run** — `go test ./... -v`
- [ ] **Step 3: Commit** — `test: add core engine and detector tests`

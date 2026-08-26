# Attack Detection Package — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a pure Go attack detection library with 32 detectors across 5 categories, 3 pluggable storage backends, and a unified Engine registry. **Status: Complete (2026-07-29).**

**Architecture:** Flat interface design — every detector implements `Detector` (Name + Detect). Pre-compiled regex patterns. Engine provides registry, by-name lookup, and `DetectRequest` for full HTTP request scanning. RegisterAll lives in `all/all.go` (separate package).

**Tech Stack:** Go 1.21+, stdlib `regexp` + `net/http`, `go-redis` for Redis backend (optional submodule at `storage/redis/`).

---

### Task 1: Initialize Go Module & Core Types

**Files:**
- Create: `go.mod`
- Create: `security.go`

- [x] **Step 1: Init Go module**

```bash
cd /home/wwwroot/bag/security-go && go mod init github.com/erikwang2013/security-go
```

- [x] **Step 2: Create security.go — Result, Severity, Detector interface, Engine**

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

- [x] **Step 3: Build** — `go build ./...`
- [x] **Step 4: Commit** — `feat: initialize Go module with core types and Engine`

---

### Task 2: Storage Backend Interface & Memory

**Files:**
- Create: `storage/storage.go`
- Create: `storage/memory.go`

- [x] **Step 1: storage/storage.go** — Backend interface (Incr, Get, Block, IsBlocked, Close)
- [x] **Step 2: storage/memory.go** — sync.Map based implementation with TTL reap goroutine
- [x] **Step 3: Build** — `go build ./storage/...`
- [x] **Step 4: Commit** — `feat: add storage interface and memory backend`

---

### Task 3: File & Redis Storage

**Files:**
- Create: `storage/file.go`
- Create: `storage/redis.go`
- Modify: `go.mod` (add go-redis dependency)

- [x] **Step 1: storage/file.go** — JSON file persistence with lazy flush
- [x] **Step 2: storage/redis.go** — Redis backend using go-redis/v9
- [x] **Step 3: Build** — `go build ./storage/...`
- [x] **Step 4: Commit** — `feat: add file and redis storage backends`

---

### Task 4: Injection Detectors — XSS, SQL

**Files:**
- Create: `injection/xss.go`
- Create: `injection/sql.go`

- [x] **Step 1: injection/xss.go** — `<script>`, `on[a-z]+=`, `javascript:`, SVG/CSS patterns
- [x] **Step 2: injection/sql.go** — UNION SELECT (with `/**/` bypass), sleep/benchmark, boolean blind, schema enum, stored proc
- [x] **Step 3: Build** — `go build ./injection/...`
- [x] **Step 4: Commit** — `feat: add XSS and SQL injection detectors`

---

### Task 5: Injection Detectors — Command, NoSQL, LDAP, XPATH

**Files:**
- Create: `injection/command.go`
- Create: `injection/nosql.go`
- Create: `injection/ldap.go`
- Create: `injection/xpath.go`

- [x] **Step 1: injection/command.go** — backtick, `$()`, pipe, `/dev/tcp`, PHP exec functions
- [x] **Step 2: injection/nosql.go** — MongoDB `$ne`/`$gt`/`$regex`/`$where`, auth bypass
- [x] **Step 3: injection/ldap.go** — filter operators `(`, `)`, `&`, `|`, `*`
- [x] **Step 4: injection/xpath.go** — boolean bypass, string-length, count
- [x] **Step 5: Build & Commit**

---

### Task 6: Injection Detectors — JNDI, SSI, GraphQL, SSTI

**Files:**
- Create: `injection/jndi.go`
- Create: `injection/ssi.go`
- Create: `injection/graphql.go`
- Create: `injection/ssti.go`

- [x] **Step 1: injection/jndi.go** — `${jndi:ldap://`, `${lower:j}`, `${env:}`, rmi/dns protocols
- [x] **Step 2: injection/ssi.go** — `<!--#exec`, `<!--#include`, `<!--#echo`
- [x] **Step 3: injection/graphql.go** — `__schema`, `__type`, deep nested query, mutation
- [x] **Step 4: injection/ssti.go** — Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO
- [x] **Step 5: Build & Commit**

---

### Task 7: Protocol Detectors — SSRF, XXE, Header Injection

**Files:**
- Create: `protocol/ssrf.go`
- Create: `protocol/xxe.go`
- Create: `protocol/header_injection.go`

- [x] **Step 1: protocol/ssrf.go** — internal IP, 169.254.169.254, IPv6 loopback, gopher/dict
- [x] **Step 2: protocol/xxe.go** — `<!ENTITY SYSTEM/PUBLIC`, parameter entities, DOCTYPE
- [x] **Step 3: protocol/header_injection.go** — CRLF, Set-Cookie/Location injection
- [x] **Step 4: Build & Commit**

---

### Task 8: Protocol Detectors — Host Header, Request Smuggling, Open Redirect, CORS, WebSocket, DNS Rebinding

**Files:**
- Create: `protocol/host_header.go`
- Create: `protocol/request_smuggling.go`
- Create: `protocol/open_redirect.go`
- Create: `protocol/cors.go`
- Create: `protocol/websocket.go`
- Create: `protocol/dns_rebinding.go`

- [x] **Step 1: All 6 protocol detectors** — one file each, pre-compiled regex patterns
- [x] **Step 2: Build & Commit**

---

### Task 9: HTTP Validation Detectors

**Files:**
- Create: `httpval/method.go`
- Create: `httpval/body_size.go`
- Create: `httpval/content_type.go`
- Create: `httpval/csrf_origin.go`
- Create: `httpval/ip_blacklist.go`

- [x] **Step 1: httpval/method.go** — whitelist GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH
- [x] **Step 2: httpval/body_size.go** — max size check, default 10MB
- [x] **Step 3: httpval/content_type.go** — MIME whitelist
- [x] **Step 4: httpval/csrf_origin.go** — cross-origin Origin vs Host match
- [x] **Step 5: httpval/ip_blacklist.go** — window rate limit (5/60s → 15min ban), uses storage.Backend
- [x] **Step 6: Build & Commit**

---

### Task 10: Data/Serialization Detectors

**Files:**
- Create: `data/deserialization.go`
- Create: `data/csv_injection.go`
- Create: `data/mail_header.go`
- Create: `data/jwt_attack.go`
- Create: `data/prototype_pollution.go`

- [x] **Step 1: data/deserialization.go** — PHP `O:número:`, `C:número:`, unserialize(), magic methods
- [x] **Step 2: data/csv_injection.go** — `=cmd|`, `@SUM(`, `+`, `-` formula prefix
- [x] **Step 3: data/mail_header.go** — Bcc/Cc/From/To injection, MIME multipart
- [x] **Step 4: data/jwt_attack.go** — alg:none, kid path traversal, empty signature (structural decode)
- [x] **Step 5: data/prototype_pollution.go** — `__proto__`, `constructor`, `__defineGetter__/Setter__`
- [x] **Step 6: Build & Commit**

---

### Task 11: File & Sensitive Data Detectors

**Files:**
- Create: `file/path_traversal.go`
- Create: `file/upload.go`
- Create: `file/data_leak.go`

- [x] **Step 1: file/path_traversal.go** — `../`, `..\\`, php://filter, null byte, URL encoding bypass
- [x] **Step 2: file/upload.go** — extension whitelist + PHP tag content scan
- [x] **Step 3: file/data_leak.go** — credit card, AWS key, private key, DB conn string, API token, JWT secret
- [x] **Step 4: Build & Commit**

---

### Task 12: Engine Integration — RegisterAll

**Files:**
- Modify: `security.go`

- [x] **Step 1: Add RegisterAll()** — registers all 32 built-in detectors
- [x] **Step 2: Build** — `go build ./...`
- [x] **Step 3: Commit** — `feat: add RegisterAll for built-in detectors`

---

### Task 13: Tests

**Files:**
- Create: `security_test.go`
- Create: `injection/xss_test.go`, `sql_test.go`, `jndi_test.go`, `ssti_test.go`
- Create: `protocol/ssrf_test.go`
- Create: `file/path_traversal_test.go`, `data_leak_test.go`
- Create: `data/jwt_attack_test.go`
- Create: `storage/memory_test.go`

- [x] **Step 1: Write tests** — each with positive and negative test cases
- [x] **Step 2: Run** — `go test ./... -v`
- [x] **Step 3: Commit** — `test: add core engine and detector tests`

---

### Task 14: Post-Implementation Code Review & Fixes (2026-07-29)

- [x] **Revisão de código abrangente** — 42 arquivos-fonte Go, 8 pacotes
- [x] **Correção de bug #1** — `storage/file.go`: erros de serialização JSON eram silenciosamente ignorados → passou a verificar o erro e retorná-lo
- [x] **Correção de bug #2** — `httpval/content_type.go`: AllowList vazia liberava todos os Content-Type → padrão deny-all
- [x] **Correção de bug #3** — `protocol/xxe.go`: `&[a-z]+;` gerava falso positivo em entidades HTML legítimas → reduzido à lista de protocolos maliciosos conhecidos
- [x] **Testes complementares para httpval** — 32 casos de teste cobrindo 5 detectors (BodySize, ContentType, CSRFOrigin, IPBlacklist, Method)
- [x] **Testes completos** — `go test -count=1 ./...` 7/7 pacotes aprovados, `go vet` sem avisos

---

## Actual vs Planned Deviations

| Plano | Real | Motivo |
|------|------|------|
| RegisterAll em `security.go` | Pacote separado `all/all.go` | Evitar importação cíclica; httpval depende de storage mas os demais detectors não dependem |
| Redis no go.mod raiz | Submódulo `storage/redis/` | Isolar dependência opcional |
| Receiver unificado por ponteiro | O pacote protocol usava value receivers | ✅ Todos foram convertidos para pointer receivers na revisão v2 |
| Tarefas 4-12 Build & Commit | Sem commits em etapas | Todo o código foi implementado de uma vez |

## Test Coverage Summary

| Pacote | Arquivos de teste | Nº de testes |
|----|---------|--------|
| security | security_test.go | 5 |
| data | deserialization_test.go, csv_injection_test.go, mail_header_test.go, jwt_attack_test.go, prototype_pollution_test.go | 8 |
| file | path_traversal_test.go, data_leak_test.go, upload_test.go | 5 |
| httpval | httpval_test.go | 32 |
| injection | xss_test.go, sql_test.go, command_test.go, nosql_test.go, ldap_test.go, xpath_test.go, jndi_test.go, ssi_test.go, graphql_test.go, ssti_test.go | 10 |
| protocol | ssrf_test.go, xxe_test.go, header_injection_test.go, host_header_test.go, request_smuggling_test.go, open_redirect_test.go, cors_test.go, websocket_test.go, dns_rebinding_test.go | 9 |
| storage | memory_test.go | 4 |
| all | (nenhum) | 0 |

> Relatório completo em [Relatório de revisão de código v2](../reports/2026-07-29-code-review-report-v2.md)

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

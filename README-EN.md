# Security Go — Attack Detection Library

[中文](README.md)

A pure Go attack detection library with **32 detectors** across **5 categories**, **3 pluggable storage backends**, and a unified `Detector` interface + `Engine` registry. Zero external dependencies for all detection logic.

## Design

### Core Principles

- **Zero-dependency detection** — all detectors use only Go standard library `regexp`, no external dependencies
- **Unified interface** — every detector implements the `Detector` interface (`Name()` + `Detect()`), managed through the `Engine` registry
- **Pre-compiled regex** — all patterns compiled in `var` blocks, zero runtime overhead
- **On-demand config** — injection/protocol/data/file detectors are plug-and-play; HTTP validators require app-specific configuration

### Architecture

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
   │    (10)     │   │    (9)      │   │        (5)          │   │     (3)       │
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
   │      (5)        │                                         │  ┌──────────────┐   │
   │                 │                                         │  │   Backend    │   │
   │  method, size,  │                                         │  │   interface  │   │
   │  type, csrf,    │                                         │  └──┬───┬───┬───┘   │
   │  ip_blacklist   │◄────── uses storage.Backend ──────────►│  Memory File Redis │
   │  (needs config) │                                         │                    │
   └─────────────────┘                                         └────────────────────┘
```

### Severity Levels

| Level | Description | Typical Scenario |
|-------|-------------|-----------------|
| `SeverityLow` | Low risk | Invalid HTTP method, Content-Type mismatch |
| `SeverityMedium` | Medium risk | CORS misconfig, open redirect, GraphQL introspection |
| `SeverityHigh` | High risk | XSS, SQL injection, SSRF, path traversal |
| `SeverityCritical` | Critical | Command injection, JNDI, SSTI, XXE, data leak |

## Features

### Injection Attacks (10)

| Detector | Detection Patterns |
|----------|-------------------|
| **XSS** | `<script>`, `on[a-z]+=` handlers, `javascript:` pseudo-protocol, SVG/CSS injection, `eval()`, `document.cookie` |
| **SQL Injection** | `UNION SELECT` (incl. `/**/` bypass), `sleep/benchmark/pg_sleep`, boolean blind, `information_schema` enumeration, `xp_cmdshell` |
| **Command Injection** | Backticks, `$()`, pipes, `/dev/tcp`, PHP `system/exec/shell_exec`, chained `&&` `;` `\|\|` |
| **NoSQL Injection** | MongoDB `$ne` `$gt` `$regex` `$where` operators, `$func`, JSON key injection |
| **LDAP Injection** | Filter operators `(\|(&(!`, `objectClass=*`, URL encoding bypass |
| **XPATH Injection** | Boolean bypass `' or '1'='1`, `string-length()`, `count()` |
| **JNDI/Log4Shell** | `${jndi:ldap://`, `${lower:j}` obfuscation, `${env:}` env vars, `ldap/rmi/dns` protocols |
| **SSI Injection** | `<!--#exec cmd=`, `<!--#include file=`, `<!--#echo var=` |
| **GraphQL Injection** | `__schema`/`__type` introspection, deep nesting DoS (5+ levels), `mutation` detection |
| **SSTI** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO traversal, `config/self` access |

### Protocol & Request Attacks (9)

| Detector | Detection Patterns |
|----------|-------------------|
| **SSRF** | Internal IPs (127/10/172.16/192.168), `169.254.169.254`, IPv6 loopback, `gopher/dict/file/ftp` protocols |
| **XXE** | `<!ENTITY SYSTEM/PUBLIC`, parameter entities `%entity;`, DOCTYPE declarations |
| **HTTP Header Injection** | CRLF `%0d%0a` / `\r\n`, Set-Cookie/Location/Content-Length injection |
| **Host Header Attack** | CRLF Host injection, `X-Forwarded-Host`, `X-Original-URL` poisoning |
| **Request Smuggling** | Transfer-Encoding/Content-Length mismatch, dual TE headers, `\x0b` folding |
| **Open Redirect** | `//evil.com` protocol-relative URL, `javascript:/data:` pseudo-protocols |
| **CORS Bypass** | `Origin: null`, `Access-Control-Allow-*` header injection |
| **WebSocket Hijack** | Upgrade header injection, null Origin bypass, `ws://` URLs |
| **DNS Rebinding** | Host header with internal IP, localhost, short hostname without TLD |

### HTTP Validation (5)

| Detector | Description |
|----------|-------------|
| **HTTP Method** | Only allows GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH |
| **Body Size** | Alerts when body exceeds limit (default 10MB) |
| **Content-Type** | Only allows configured MIME type whitelist |
| **CSRF Origin** | Checks cross-origin request Origin against Host, supports additional whitelist |
| **IP Blacklist** | Auto-blocks IP after N attacks in window (default: 5/60s → 15min ban), supports File/Redis/Memory backends |

### Data & Serialization Attacks (5)

| Detector | Detection Patterns |
|----------|-------------------|
| **PHP Deserialization** | `O:number:` / `C:number:` serialized objects, `unserialize()`, magic methods |
| **CSV Injection** | `=cmd\|`, `@SUM(`, `+`/`-` formula prefixes, `HYPERLINK`/`DDE` |
| **Mail Header Injection** | Bcc/Cc/From/To injection, MIME multipart, boundary params |
| **JWT Attack** | `alg: none` bypass, `kid` path traversal, empty signature detection (structural decode) |
| **Prototype Pollution** | `__proto__`/`constructor` keys, `__defineGetter__`/`__defineSetter__` |

### File & Sensitive Data (3)

| Detector | Detection Patterns |
|----------|-------------------|
| **Path Traversal** | `../`, `..\\`, `php://filter`/`php://input`, null byte, URL-encoded bypass, `/etc/passwd` |
| **Malicious Upload** | Extension whitelist (15 types) + PHP tag `<?php`/`<?=` content scan |
| **Data Leak** | Credit card numbers, AWS Access Key, private keys, DB connection strings, API tokens, JWT secrets, GitHub PAT |

### Storage Backends (3)

| Backend | Description |
|---------|-------------|
| **Memory** | `sync.Mutex` + map, 30s TTL cleanup |
| **File** | JSON persistence, auto-save every 30s + flush on Close |
| **Redis** | Separate sub-module, Pipeline Incr + TTL, requires `go-redis/v9` |

## Usage

### Installation

```bash
go get github.com/erikwang2013/security-go
```

### Quick Start

```go
package main

import (
    "fmt"
    "github.com/erikwang2013/security-go"
    "github.com/erikwang2013/security-go/all"
)

func main() {
    e := security.NewEngine()
    all.RegisterAll(e) // register all 27 zero-config detectors

    // Single detection
    r := e.Detect("xss", "<script>alert(1)</script>")
    fmt.Printf("Detected: %v, Severity: %d\n", r.Detected, r.Severity)

    // Batch detection
    for _, r := range e.DetectAll("' OR '1'='1") {
        fmt.Printf("[%s] %s\n", r.Name, r.Message)
    }
}
```

### HTTP Request Detection

```go
func handler(w http.ResponseWriter, r *http.Request) {
    e := security.NewEngine()
    all.RegisterAll(e)

    for _, result := range e.DetectRequest(r) {
        if result.Detected {
            log.Printf("Attack detected: [%s] %s", result.Name, result.Message)
        }
    }
}
```

### HTTP Validator Configuration

```go
// Method validation
e.Register(&httpval.Method{})

// Body size limit
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type whitelist
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF Origin check
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP blacklist (auto-ban: 5 attacks/60s → 15min ban)
mem := storage.NewMemory()
defer mem.Close()
bl := httpval.NewIPBlacklist(mem)
e.Register(bl)

// Record attack
blocked, _ := bl.RecordAttack(clientIP)
```

### Custom Detector

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "Malicious content detected",
    }
}

e.Register(&MyDetector{})
```

### Documentation

- [Design Spec](docs/superpowers/specs/2026-07-29-attack-detection-design-en.md) — Package structure, core API, detector catalog
- [Implementation Plan](docs/superpowers/plans/2026-07-29-attack-detection-plan-en.md) — Task-by-task plan with actual vs planned deviations
- [Code Review Report](docs/superpowers/reports/2026-07-29-code-review-report-en.md) — Bug fixes, test coverage, architecture review

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

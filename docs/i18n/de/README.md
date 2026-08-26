# Security Go — Bibliothek zur Angriffserkennung

[简体中文](../../../README.md) · [English](../../../README-EN.md)

Ein in Go geschriebenes Paket zur Angriffserkennung mit **32 Detektoren**, **5 Angriffskategorien** und **3 steckbaren Speicher-Backends**. Einheitliche Schnittstelle + Registry-Muster, reine Erkennungsbibliothek, passend für jedes Go-HTTP-Framework.

## Designphilosophie

### Kernprinzipien

- **Erkennung ohne Abhängigkeiten** — Alle Detektoren nutzen ausschließlich die Go-Standardbibliothek `regexp`, keine externen Abhängigkeiten
- **Einheitliche Schnittstelle** — Jeder Detektor implementiert die `Detector`-Schnittstelle (`Name()` + `Detect()`), zentral verwaltet über die `Engine`-Registry
- **Vorkompilierte Regexe** — Alle Muster werden bei der Initialisierung der `var`-Blöcke kompiliert, zur Laufzeit null Overhead
- **Konfiguration nach Bedarf** — Injektions-/Protokoll-/Daten-/Datei-Detektoren sind Plug-and-Play einsatzbereit; HTTP-Validator erfordern eine anwendungsspezifische Konfiguration

### Architektur

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
   │     (5 个)      │                                         │  ┌──────────────┐   │
   │                 │                                         │  │   Backend    │   │
   │  method, size,  │                                         │  │   interface  │   │
   │  type, csrf,    │                                         │  └──┬───┬───┬───┘   │
   │  ip_blacklist   │◄────── 使用 storage.Backend ──────────►│  Memory File Redis │
   │  (需配置参数)    │                                         │                    │
   └─────────────────┘                                         └────────────────────┘
```

### Datenfluss

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

### Schweregrade

| Stufe | Beschreibung | Typische Szenarien |
|-------|--------------|--------------------|
| `SeverityLow` | Geringes Risiko | Unzulässige HTTP-Methode, Content-Type stimmt nicht überein |
| `SeverityMedium` | Mittleres Risiko | CORS-Konfigurationsprobleme, offene Weiterleitung, GraphQL-Introspektion |
| `SeverityHigh` | Hohes Risiko | XSS, SQL-Injektion, SSRF, Pfad-Traversal |
| `SeverityCritical` | Kritisch | Befehlsinjektion, JNDI, SSTI, XXE, Datenlecks |

## Implementierte Funktionen

### Injektionsangriffe (10)

| Detektor | Erkennungsmuster |
|----------|------------------|
| **XSS** | `<script>`, `on[a-z]+=`-Event-Handler, `javascript:`-Pseudo-Protokoll, SVG/CSS-Injektion, `eval()`, `document.cookie` |
| **SQL-Injektion** | `UNION SELECT` (einschließlich `/**/`-Bypass), `sleep/benchmark/pg_sleep`, boolesche Blindinjektion, `information_schema`-Enumeration, `xp_cmdshell` |
| **Befehlsinjektion** | Backticks, `$()`, Pipe-Zeichen, `/dev/tcp`, PHP `system/exec/shell_exec`, verkettete Ausführung `&&` `;` `\|\|` |
| **NoSQL-Injektion** | MongoDB-Operatoren `$ne` `$gt` `$regex` `$where`, `$func`, JSON-Key-Injektion |
| **LDAP-Injektion** | Filter-Operatoren `(\|(&(!`, `objectClass=*`, URL-Encoding-Bypass |
| **XPATH-Injektion** | Boolescher Bypass `' or '1'='1`, `string-length()`, `count()` |
| **JNDI/Log4Shell** | `${jndi:ldap://`, `${lower:j}`-Verschleierung, `${env:}`-Umgebungsvariablen, `ldap/rmi/dns`-Protokolle |
| **SSI-Injektion** | `<!--#exec cmd=`, `<!--#include file=`, `<!--#echo var=` |
| **GraphQL-Injektion** | `__schema`/`__type`-Introspektion, tief verschachteltes DoS (5+ Ebenen), `mutation`-Erkennung |
| **SSTI** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python-MRO-Traversal, Zugriff auf `config/self` |

### Protokoll- und Request-Angriffe (9)

| Detektor | Erkennungsmuster |
|----------|------------------|
| **SSRF** | Interne IPs (127/10/172.16/192.168), `169.254.169.254`, IPv6-Loopback, `gopher/dict/file/ftp`-Protokolle |
| **XXE** | `<!ENTITY SYSTEM/PUBLIC`, Parameter-Entitäten `%entity;`, DOCTYPE-Deklaration |
| **HTTP-Header-Injektion** | CRLF `%0d%0a` / `\r\n`, Set-Cookie/Location/Content-Length-Injektion |
| **Host-Header-Angriff** | CRLF-Host-Injektion, `X-Forwarded-Host`, `X-Original-URL`-Poisoning |
| **Request-Smuggling** | Transfer-Encoding/Content-Length-Inkonsistenz, doppelte TE-Header, `\x0b`-gefaltete Header-Verwirrung |
| **Offene Weiterleitung** | `//evil.com`-protokollrelative URLs, `javascript:/data:`-Pseudo-Protokolle |
| **CORS-Bypass** | `Origin: null`, `Access-Control-Allow-*`-Header-Injektion |
| **WebSocket-Entführung** | Upgrade-Header-Injektion, null-Origin-Bypass, `ws://`-URLs |
| **DNS-Rebinding** | Interne IPs im Host-Header, localhost, kurze Hostnamen ohne TLD |

### HTTP-Protokoll-Validierung (5)

| Detektor | Beschreibung |
|----------|--------------|
| **HTTP-Methode** | Nur GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH erlaubt, andere erzeugen eine Warnung |
| **Request-Body-Größe** | Warnung bei Überschreitung des Limits (Standard 10 MB) |
| **Content-Type** | Nur die konfigurierte MIME-Typ-Whitelist ist erlaubt |
| **CSRF-Origin** | Prüft bei Cross-Origin-Anfragen, ob Origin und Host übereinstimmen, optionale zusätzliche Whitelist |
| **IP-Blacklist** | Automatische Sperrung nach N Angriffen im Zeitfenster (Standard 5/60 s → Sperre 15 Minuten), unterstützt File-/Redis-/Memory-Speicherung |

### Daten- und Serialisierungsangriffe (5)

| Detektor | Erkennungsmuster |
|----------|------------------|
| **PHP-Deserialisierung** | `O:Zahl:` / `C:Zahl:`-serialisierte Objekte, `unserialize()`, magische Methoden (`__wakeup`/`__destruct`) |
| **CSV-Injektion** | `=cmd\|`, `@SUM(`, `+`/`-`-Formelpräfixe, `HYPERLINK`/`DDE` |
| **E-Mail-Header-Injektion** | Bcc/Cc/From/To-Injektion, MIME-Multipart, boundary-Parameter |
| **JWT-Angriffe** | `alg: none`-Bypass, `kid`-Pfad-Traversal, Erkennung leerer Signaturen (Struktur-Decodierung) |
| **Prototype-Pollution** | `__proto__`/`constructor`-Keys, `__defineGetter__`/`__defineSetter__` |

### Dateien und sensible Daten (3)

| Detektor | Erkennungsmuster |
|----------|------------------|
| **Pfad-Traversal** | `../`, `..\\`, `php://filter`/`php://input`, Null-Byte, URL-Encoding-Bypass, `/etc/passwd` |
| **Bösartige Uploads** | Erweiterungs-Whitelist (15 Typen) + Inhalts-Scan nach PHP-Tags `<?php`/`<?=` |
| **Datenlecks** | Kreditkartennummern, AWS Access Key, private Schlüssel `-----BEGIN`, Datenbank-Verbindungsstrings, API-Token, JWT-Secret, GitHub-PAT |

### Speicher-Backends (3)

| Backend | Beschreibung |
|---------|--------------|
| **Memory** | `sync.Mutex` + map, automatische Bereinigung abgelaufener Einträge nach 30 s |
| **File** | JSON-Datei-Persistenz, flush bei Close |
| **Redis** | Eigenständiges Untermodul, Pipeline Incr + TTL, erfordert `go-redis/v9` |

## Verwendung

### Installation

```bash
go get github.com/erikwang2013/security-go
```

### Schnellstart

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

### HTTP-Request-Erkennung

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

### Konfiguration der HTTP-Validator

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

### Benutzerdefinierte Detektoren

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

### Weitere Dokumentation

- [API-Referenz](api.md) — Kerntypen, Detector-/Engine-Schnittstellen, Storage-Backend-Schnittstelle, HTTP-Validator
- [Design-Spezifikation](specs/2026-07-29-attack-detection-design.md) — Paketstruktur, Detektor-Verzeichnis
- [Implementierungsplan](plans/2026-07-29-attack-detection-plan.md) — Schritt-für-Schritt-Aufgabenplan und Abweichungsvergleich
- [Code-Review-Bericht](reports/2026-07-29-code-review-report.md) — Bug-Fixes, Testabdeckung, Architekturbewertung

---

## Mehrsprachige Dokumentation

| Sprache | Dokument |
|---------|----------|
| 简体中文 | [README.md](../../../README.md) |
| English | [README-EN.md](../../../README-EN.md) · [README.md](../en/README.md) |
| 한국어 | [README.md](../ko/README.md) |
| Русский | [README.md](../ru/README.md) |
| Deutsch | [README.md](README.md) |
| Français | [README.md](../fr/README.md) |
| Español | [README.md](../es/README.md) |
| Português | [README.md](../pt/README.md) |
| हिन्दी | [README.md](../hi/README.md) |
| العربية | [README.md](../ar/README.md) |
| বাংলা | [README.md](../bn/README.md) |
| Bahasa Indonesia | [README.md](../id/README.md) |
| 日本語 | [README.md](../ja/README.md) |

Index: [docs/i18n/README.md](../README.md)

---

## Spendenunterstützung

Wenn dieses Projekt für Sie hilfreich ist, freuen wir uns über eine Spende:

| Methode | QR-Code |
|---------|---------|
| Alipay | ![Alipay](images/alipay.png) |
| WeChat Pay | ![WeChat Pay](images/weixinpay.png) |

### Spende per internationaler Überweisung (Banküberweisung)

**Empfängerinformationen**

- Empfängername: WANG KEXUN
- Empfängerkontonummer: 881015918251

**Empfängerbank (ZA Bank)**

- SWIFT-Code: `AABLHKHHXXX`
- Bankname: ZA Bank Limited
- Bankleitzahl: 387
- Bankadresse: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

**Korrespondenzbank für grenzüberschreitende Überweisungen (falls erforderlich)**

> Bitte beachten Sie: Hierbei handelt es sich um Informationen zur Korrespondenzbank (Zwischenbank) für grenzüberschreitende Überweisungen, nicht um die Empfängerbank. Erkundigen Sie sich bei Ihrer Bank, ob Angaben zur Korrespondenzbank benötigt werden.

- Für Überweisungen in Hongkong-Dollar, Chinesischen Renminbi und US-Dollar ist die Korrespondenzbank Citibank:
  - Bankname: Citibank N.A. Hong Kong
  - SWIFT-Code: `CITIHKHXXXX`
  - Bankleitzahl: 006
  - Filiale: Hong Kong Branch
  - Filialnummer: 391
  - Bankadresse: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong
- Für Überweisungen in anderen Währungen ist die Korrespondenzbank BNY Mellon:
  - Bankname: THE BANK OF NEW YORK MELLON
  - SWIFT-Code: `IRVTUS3NXXX`
  - Bankadresse: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## Englisch

Die vollständige englische Dokumentation finden Sie in [README-EN.md](../../../README-EN.md).

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

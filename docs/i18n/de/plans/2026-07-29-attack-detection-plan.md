# Paket zur Angriffserkennung — Implementierungsplan

> **Für agentische Worker:** ERFORDERLICHE SUB-SKILL: Verwenden Sie superpowers:subagent-driven-development (empfohlen) oder superpowers:executing-plans, um diesen Plan Aufgabe für Aufgabe umzusetzen.

**Ziel:** Eine reine Go-Bibliothek zur Angriffserkennung mit 32 Detektoren in 5 Kategorien, 3 steckbaren Speicher-Backends und einer einheitlichen Engine-Registry. **Status: Abgeschlossen (2026-07-29).**

**Architektur:** Flaches Schnittstellendesign — jeder Detektor implementiert `Detector` (Name + Detect). Vorkompilierte Regex-Muster. Die Engine stellt Registry, Namenssuche und `DetectRequest` für die vollständige HTTP-Request-Analyse bereit. RegisterAll lebt in `all/all.go` (separates Paket).

**Technologie-Stack:** Go 1.21+, Standardbibliothek `regexp` + `net/http`, `go-redis` für das Redis-Backend (optionales Untermodul unter `storage/redis/`).

---

### Aufgabe 1: Go-Modul & Kerntypen initialisieren

**Dateien:**
- Erstellen: `go.mod`
- Erstellen: `security.go`

- [x] **Schritt 1: Go-Modul initialisieren**

```bash
cd /home/wwwroot/bag/security-go && go mod init github.com/erikwang2013/security-go
```

- [x] **Schritt 2: security.go erstellen — Result, Severity, Detector interface, Engine**

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

- [x] **Schritt 3: Build** — `go build ./...`
- [x] **Schritt 4: Commit** — `feat: initialize Go module with core types and Engine`

---

### Aufgabe 2: Storage-Backend-Schnittstelle & Memory

**Dateien:**
- Erstellen: `storage/storage.go`
- Erstellen: `storage/memory.go`

- [x] **Schritt 1: storage/storage.go** — Backend-Schnittstelle (Incr, Get, Block, IsBlocked, Close)
- [x] **Schritt 2: storage/memory.go** — Implementierung auf Basis von sync.Map mit TTL-Aufräum-Goroutine
- [x] **Schritt 3: Build** — `go build ./storage/...`
- [x] **Schritt 4: Commit** — `feat: add storage interface and memory backend`

---

### Aufgabe 3: File- & Redis-Speicherung

**Dateien:**
- Erstellen: `storage/file.go`
- Erstellen: `storage/redis.go`
- Ändern: `go.mod` (go-redis-Abhängigkeit hinzufügen)

- [x] **Schritt 1: storage/file.go** — JSON-Datei-Persistenz mit verzögertem flush
- [x] **Schritt 2: storage/redis.go** — Redis-Backend mit go-redis/v9
- [x] **Schritt 3: Build** — `go build ./storage/...`
- [x] **Schritt 4: Commit** — `feat: add file and redis storage backends`

---

### Aufgabe 4: Injektions-Detektoren — XSS, SQL

**Dateien:**
- Erstellen: `injection/xss.go`
- Erstellen: `injection/sql.go`

- [x] **Schritt 1: injection/xss.go** — `<script>`, `on[a-z]+=`, `javascript:`, SVG/CSS-Muster
- [x] **Schritt 2: injection/sql.go** — UNION SELECT (mit `/**/`-Bypass), sleep/benchmark, boolesche Blindinjektion, Schema-Enumeration, gespeicherte Prozeduren
- [x] **Schritt 3: Build** — `go build ./injection/...`
- [x] **Schritt 4: Commit** — `feat: add XSS and SQL injection detectors`

---

### Aufgabe 5: Injektions-Detektoren — Command, NoSQL, LDAP, XPATH

**Dateien:**
- Erstellen: `injection/command.go`
- Erstellen: `injection/nosql.go`
- Erstellen: `injection/ldap.go`
- Erstellen: `injection/xpath.go`

- [x] **Schritt 1: injection/command.go** — Backticks, `$()`, Pipe, `/dev/tcp`, PHP-exec-Funktionen
- [x] **Schritt 2: injection/nosql.go** — MongoDB `$ne`/`$gt`/`$regex`/`$where`, Auth-Bypass
- [x] **Schritt 3: injection/ldap.go** — Filter-Operatoren `(`, `)`, `&`, `|`, `*`
- [x] **Schritt 4: injection/xpath.go** — Boolescher Bypass, string-length, count
- [x] **Schritt 5: Build & Commit**

---

### Aufgabe 6: Injektions-Detektoren — JNDI, SSI, GraphQL, SSTI

**Dateien:**
- Erstellen: `injection/jndi.go`
- Erstellen: `injection/ssi.go`
- Erstellen: `injection/graphql.go`
- Erstellen: `injection/ssti.go`

- [x] **Schritt 1: injection/jndi.go** — `${jndi:ldap://`, `${lower:j}`, `${env:}`, rmi/dns-Protokolle
- [x] **Schritt 2: injection/ssi.go** — `<!--#exec`, `<!--#include`, `<!--#echo`
- [x] **Schritt 3: injection/graphql.go** — `__schema`, `__type`, tief verschachtelte Query, mutation
- [x] **Schritt 4: injection/ssti.go** — Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO
- [x] **Schritt 5: Build & Commit**

---

### Aufgabe 7: Protokoll-Detektoren — SSRF, XXE, Header-Injektion

**Dateien:**
- Erstellen: `protocol/ssrf.go`
- Erstellen: `protocol/xxe.go`
- Erstellen: `protocol/header_injection.go`

- [x] **Schritt 1: protocol/ssrf.go** — Interne IPs, 169.254.169.254, IPv6-Loopback, gopher/dict
- [x] **Schritt 2: protocol/xxe.go** — `<!ENTITY SYSTEM/PUBLIC`, Parameter-Entitäten, DOCTYPE
- [x] **Schritt 3: protocol/header_injection.go** — CRLF, Set-Cookie/Location-Injektion
- [x] **Schritt 4: Build & Commit**

---

### Aufgabe 8: Protokoll-Detektoren — Host-Header, Request-Smuggling, offene Weiterleitung, CORS, WebSocket, DNS-Rebinding

**Dateien:**
- Erstellen: `protocol/host_header.go`
- Erstellen: `protocol/request_smuggling.go`
- Erstellen: `protocol/open_redirect.go`
- Erstellen: `protocol/cors.go`
- Erstellen: `protocol/websocket.go`
- Erstellen: `protocol/dns_rebinding.go`

- [x] **Schritt 1: Alle 6 Protokoll-Detektoren** — je eine Datei, vorkompilierte Regex-Muster
- [x] **Schritt 2: Build & Commit**

---

### Aufgabe 9: HTTP-Validierungs-Detektoren

**Dateien:**
- Erstellen: `httpval/method.go`
- Erstellen: `httpval/body_size.go`
- Erstellen: `httpval/content_type.go`
- Erstellen: `httpval/csrf_origin.go`
- Erstellen: `httpval/ip_blacklist.go`

- [x] **Schritt 1: httpval/method.go** — Whitelist GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH
- [x] **Schritt 2: httpval/body_size.go** — Maximale Größe prüfen, Standard 10 MB
- [x] **Schritt 3: httpval/content_type.go** — MIME-Whitelist
- [x] **Schritt 4: httpval/csrf_origin.go** — Cross-Origin-Abgleich Origin vs. Host
- [x] **Schritt 5: httpval/ip_blacklist.go** — Fensterbasiertes Ratenlimit (5/60 s → 15-min-Sperre), nutzt storage.Backend
- [x] **Schritt 6: Build & Commit**

---

### Aufgabe 10: Daten-/Serialisierungs-Detektoren

**Dateien:**
- Erstellen: `data/deserialization.go`
- Erstellen: `data/csv_injection.go`
- Erstellen: `data/mail_header.go`
- Erstellen: `data/jwt_attack.go`
- Erstellen: `data/prototype_pollution.go`

- [x] **Schritt 1: data/deserialization.go** — PHP `O:Zahl:`, `C:Zahl:`, unserialize(), magische Methoden
- [x] **Schritt 2: data/csv_injection.go** — `=cmd|`, `@SUM(`, `+`, `-` Formel-Präfixe
- [x] **Schritt 3: data/mail_header.go** — Bcc/Cc/From/To-Injektion, MIME-Multipart
- [x] **Schritt 4: data/jwt_attack.go** — alg:none, kid-Pfad-Traversal, leere Signatur (strukturelle Decodierung)
- [x] **Schritt 5: data/prototype_pollution.go** — `__proto__`, `constructor`, `__defineGetter__/Setter__`
- [x] **Schritt 6: Build & Commit**

---

### Aufgabe 11: Datei- & sensible-Daten-Detektoren

**Dateien:**
- Erstellen: `file/path_traversal.go`
- Erstellen: `file/upload.go`
- Erstellen: `file/data_leak.go`

- [x] **Schritt 1: file/path_traversal.go** — `../`, `..\\`, php://filter, Null-Byte, URL-Encoding-Bypass
- [x] **Schritt 2: file/upload.go** — Erweiterungs-Whitelist + Inhalts-Scan nach PHP-Tags
- [x] **Schritt 3: file/data_leak.go** — Kreditkarten, AWS-Key, privater Schlüssel, DB-Verbindungsstring, API-Token, JWT-Secret
- [x] **Schritt 4: Build & Commit**

---

### Aufgabe 12: Engine-Integration — RegisterAll

**Dateien:**
- Ändern: `security.go`

- [x] **Schritt 1: RegisterAll() hinzufügen** — registriert alle 32 eingebauten Detektoren
- [x] **Schritt 2: Build** — `go build ./...`
- [x] **Schritt 3: Commit** — `feat: add RegisterAll for built-in detectors`

---

### Aufgabe 13: Tests

**Dateien:**
- Erstellen: `security_test.go`
- Erstellen: `injection/xss_test.go`, `sql_test.go`, `jndi_test.go`, `ssti_test.go`
- Erstellen: `protocol/ssrf_test.go`
- Erstellen: `file/path_traversal_test.go`, `data_leak_test.go`
- Erstellen: `data/jwt_attack_test.go`
- Erstellen: `storage/memory_test.go`

- [x] **Schritt 1: Tests schreiben** — jeweils mit positiven und negativen Testfällen
- [x] **Schritt 2: Ausführen** — `go test ./... -v`
- [x] **Schritt 3: Commit** — `test: add core engine and detector tests`

---

### Aufgabe 14: Code-Review nach der Implementierung & Fixes (2026-07-29)

- [x] **Umfassendes Code-Review** — 42 Go-Quelldateien, 8 Pakete
- [x] **Bug-Fix #1** — `storage/file.go`: JSON-Serialisierungsfehler wurde stillschweigend ignoriert → Fehler wird nun geprüft und zurückgegeben
- [x] **Bug-Fix #2** — `httpval/content_type.go`: leere AllowList ließ alle Content-Types durch → deny-all als Standard
- [x] **Bug-Fix #3** — `protocol/xxe.go`: `&[a-z]+;` erkannte fälschlicherweise legitime HTML-Entitäten → auf Liste bekannter bösartiger Protokolle eingegrenzt
- [x] **httpval-Tests ergänzt** — 32 Testfälle, decken 5 Detektoren ab (BodySize, ContentType, CSRFOrigin, IPBlacklist, Method)
- [x] **Vollständige Tests** — `go test -count=1 ./...` 7/7 Pakete bestanden, `go vet` ohne Warnungen

---

## Ist- vs. Plan-Abweichungen

| Plan | Ist | Grund |
|------|-----|-------|
| RegisterAll in `security.go` | separates Paket `all/all.go` | vermeidet zirkuläre Importe: httpval hängt von storage ab, andere Detektoren jedoch nicht |
| Redis im Root-`go.mod` | Untermodul `storage/redis/` | isoliert optionale Abhängigkeit |
| Receiver einheitlich als Pointer | protocol-Paket verwendet Wert-Receiver | ✅ in der v2-Prüfung vollständig auf Pointer-Receiver umgestellt |
| Aufgaben 4–12 Build & Commit | nicht schrittweise committet | gesamter Code in einem Durchgang implementiert |

## Zusammenfassung der Testabdeckung

| Paket | Testdateien | Anzahl der Tests |
|-------|-------------|------------------|
| security | security_test.go | 5 |
| data | deserialization_test.go, csv_injection_test.go, mail_header_test.go, jwt_attack_test.go, prototype_pollution_test.go | 8 |
| file | path_traversal_test.go, data_leak_test.go, upload_test.go | 5 |
| httpval | httpval_test.go | 32 |
| injection | xss_test.go, sql_test.go, command_test.go, nosql_test.go, ldap_test.go, xpath_test.go, jndi_test.go, ssi_test.go, graphql_test.go, ssti_test.go | 10 |
| protocol | ssrf_test.go, xxe_test.go, header_injection_test.go, host_header_test.go, request_smuggling_test.go, open_redirect_test.go, cors_test.go, websocket_test.go, dns_rebinding_test.go | 9 |
| storage | memory_test.go | 4 |
| all | (keine) | 0 |

> Vollständiger Bericht siehe [2026-07-29-code-review-report-v2.md](../reports/2026-07-29-code-review-report-v2.md)

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

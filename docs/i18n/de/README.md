# Security Go — Bibliothek zur Angriffserkennung

[简体中文](../../../README.md) · [English](../../../README-EN.md) · [API-Referenz](api.md)

Ein in Go geschriebenes Paket zur Angriffserkennung mit **36 Detektoren**, **6 Angriffskategorien** und **3 steckbaren Speicher-Backends**. Einheitliche Schnittstelle + Registry-Muster, reine Erkennungsbibliothek, passend für jedes Go-HTTP-Framework.

<p align="center">
  <img src="../../../pet/pet.svg" width="190" alt="Sentinel Gopher">
  <br>
  <sub>Projekt-Maskottchen <b>Sentinel Gopher</b> (哨兵鼠) — ein Go-Gopher, der mit einem Schild Wache hält.<br>Die <b>36</b> auf dem Schild ist die Anzahl der Detektoren; die Lupe steht für den Scan bei jeder Anfrage.</sub>
</p>

[Architektur](#architektur) · [Funktionen](#implementierte-funktionen) · [Lebenszyklus](#lebenszyklus) · [Projektstruktur](#projektstruktur) · [Das Maskottchen](#das-maskottchen)

## Designphilosophie

### Kernprinzipien

- **Erkennung ohne Abhängigkeiten** — Alle Detektoren nutzen ausschließlich die Go-Standardbibliothek `regexp`, keine externen Abhängigkeiten
- **Einheitliche Schnittstelle** — Jeder Detektor implementiert die `Detector`-Schnittstelle (`Name()` + `Detect()`), zentral verwaltet über die `Engine`-Registry
- **Vorkompilierte Regexe** — Alle Muster werden bei der Initialisierung der `var`-Blöcke kompiliert, zur Laufzeit null Overhead
- **Konfiguration nach Bedarf** — Injektions-/Protokoll-/Daten-/Datei-Detektoren sind Plug-and-Play einsatzbereit; HTTP-Validator und die Sitzungssicherheitsprüfung erfordern eine anwendungsspezifische Konfiguration

### Architektur

![Architektur](../../../docs/images/architecture.svg)

> Das Paket `session` wird nicht über die `Engine` registriert: Die Sitzungsprüfung muss den vollständigen `*http.Request` lesen (Token, Client-IP, User-Agent),
> und die Anwendung muss Speicher und Schlüssel bereitstellen; deshalb wird es direkt als Middleware aufgerufen, siehe unten „Konfiguration der Sitzungssicherheit“.

### Lebenszyklus

Der vollständige Kreislauf einer Anfrage, vom Eingang über die Erkennung bis zur abgestuften Behandlung (einschließlich des IP-Sperrzyklus und des erneuten Scans nach URL-Dekodierung), dazu der Weg einer Sitzung von der Bindung bis zum Widerruf:

![Lebenszyklus](../../../docs/images/lifecycle.svg)

### Schweregrade

| Stufe | Beschreibung | Typische Szenarien |
|-------|--------------|--------------------|
| `SeverityLow` | Geringes Risiko | Unzulässige HTTP-Methode, Content-Type stimmt nicht überein |
| `SeverityMedium` | Mittleres Risiko | Schwache Signale: CORS-Fehlkonfiguration, offene Weiterleitung, GraphQL-Introspektion, dazu die kontextfreien Muster, die jeder Detektor bewusst abtrennt (`../`, `on…=`, `javascript:`, `sleep(`, `sqlite_master`, Backticks, `{#…#}`, `__proto__:`, PHP-Magic-Method-Namen) — in Tutorials und normalen Inhalten häufig |
| `SeverityHigh` | Hohes Risiko | Starke Signale: XSS, SQL-Injektion, SSRF, Pfad-Traversal, Sitzungsanomalien |
| `SeverityCritical` | Kritisch | Starke Signale: Befehlsinjektion, JNDI, SSTI, XXE, Datenleck, Deserialisierung (PHP-serialisierte Objekte / pickle / Java / .NET) |

## Implementierte Funktionen

### Funktionsübersicht

![Funktionsdesign](../../../docs/images/features.svg)

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

### HTTP-Protokoll-Validierung (7)
| **JSON-Verschachtelungstiefe** | Streamt mit `json.Decoder`: erkennt eine JSON-Bombe, sobald Verschachtelungstiefe oder Elementanzahl das Limit überschreiten (Standardtiefe 32). Ungültiges oder abgeschnittenes JSON löst nie aus |
| **Set-Cookie-Attribute** | Meldet `Set-Cookie` ohne `Secure`/`HttpOnly`/`SameSite`, bei überlangem oder leerem Wert; fehlende Attribute gebündelt in einem Ergebnis |

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
| **Deserialisierung** | `O:Zahl:` / `C:Zahl:`-serialisierte Objekte, `unserialize()`, magische Methoden (`__wakeup`/`__destruct`); deckt PHP- / pickle- / Java- / .NET-Nutzlasten ab |
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

### Sitzungssicherheit (2)

| Detektor | Erkennungsmuster |
|----------|------------------|
| **Sitzungswächter** (`session_guard`) | Bindung des Tokens an den Client zum Zeitpunkt des Sitzungsaufbaus, Vergleich bei jeder Anfrage: Änderung von User-Agent oder Gerätefingerabdruck gilt als **Client-Entführung** (Critical); fällt die Client-IP in ein anderes Subnetz oder Land, gilt das als **Anmeldung von einem anderen Ort** (High/Critical); `Observe()` vergleicht bei der Anmeldung die historischen Subnetze und warnt bei einem neuen Subnetz. Die Sitzung wird gleitend verlängert, `Revoke()` kann sie sofort ungültig machen; `RecordFailure()` zählt Fehlversuche und sperrt das Token, sobald die Schwelle im Fenster erreicht ist, `Check()` meldet dann `token_locked`, und `ClearFailures()` setzt den Zähler bei erfolgreicher Anmeldung zurück; `CheckLogin()` erkennt zusätzlich Credential-Stuffing (ein Client gegen zu viele verschiedene Identitäten → `credential_stuffing`), und die Sperre verdoppelt sich mit jeder Wiederholung, begrenzt auf 24 h |
| **Datenmanipulation** (`data_tamper`) | HMAC-SHA256-Signatur über die Anfrageparameter (`Zeitstempel.nonce.Signatur`), erkennt geänderte Parameter, abweichende Schlüssel, überschrittene Zeitstempel-Toleranz und Signatur-Replays (Nonce-Zähler) |

### Speicher-Backends (3)

| Backend | Beschreibung |
|---------|--------------|
| **Memory** | `sync.Mutex` + map, automatische Bereinigung abgelaufener Einträge nach 30 s |
| **File** | JSON-Datei-Persistenz, flush bei Close |
| **Redis** | Eigenständiges Untermodul, Pipeline Incr + TTL, erfordert `go-redis/v9` |

## Projektstruktur

```
security-go/
├── security.go            # Kern: Result / Severity / Detector-Schnittstelle / Engine-Registry
├── injection/             # Injektions-Detektoren (10): xss, sql, command, nosql, ldap,
│                          #   xpath, jndi, ssi, graphql, ssti
├── protocol/              # Protokoll- und Request-Detektoren (9): ssrf, xxe, header, host,
│                          #   smuggling, redirect, cors, websocket, dns_rebinding
├── data/                  # Daten- und Serialisierungs-Detektoren (5): deserialization, csv,
│                          #   mail, jwt, prototype_pollution
├── file/                  # Datei- und Detektoren für sensible Daten (3): path_traversal,
│                          #   upload, data_leak
├── httpval/               # HTTP-Protokoll-Validatoren (7), jeder braucht anwendungsseitige Einstellungen
├── session/               # Sitzungssicherheit (2): session_guard, data_tamper
│                          #   Umgeht die Engine und wird direkt als Middleware verwendet
├── storage/               # Speicher-Backends
│   ├── storage.go         #   Backend-Schnittstelle: Incr / Get / Block / IsBlocked / Close
│   ├── memory.go          #   Memory: Mutex + map, Hintergrundbereinigung alle 30 s
│   ├── file.go            #   File: JSON-Persistenz, Flush beim Close
│   └── redis/             #   Redis: separates Untermodul mit eigener go.mod
├── all/                   # Einmalige Registrierung der 27 Detektoren ohne Konfiguration
├── pet/                   # Projekt-Maskottchen: eingebettetes SVG + Startbanner
├── docs/
│   ├── api.md             # API-Referenz
│   ├── images/            # SVGs für Architektur / Funktionen / Lebenszyklus
│   ├── i18n/              # Übersetzte Dokumentation (12 Sprachen)
│   └── superpowers/       # Design-Spezifikation, Implementierungsplan, Code-Review-Berichte
└── tests/                 # Coverage-Berichte
```

Jedes Detektor-Paket kombiniert `xxx.go` mit `xxx_test.go`; `all` enthält zusätzlich Regressionstests.

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
    all.RegisterAll(e) // registriert alle 27 Detektoren ohne Konfiguration

    // Einzelprüfung
    r := e.Detect("xss", "<script>alert(1)</script>")
    fmt.Printf("Erkannt: %v, Schweregrad: %d\n", r.Detected, r.Severity)

    // Massenprüfung
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
            log.Printf("Angriff erkannt: [%s] %s", result.Name, result.Message)
        }
    }
}
```

### Konfiguration der HTTP-Validator

```go
// Methodenprüfung
e.Register(&httpval.Method{})

// Limit für die Request-Body-Größe
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type-Whitelist
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF-Origin-Prüfung
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP-Blacklist (automatische Sperre: 5 Angriffe/60 s → 15 Min. Sperre)
mem := storage.NewMemory()
defer mem.Close()
bl := httpval.NewIPBlacklist(mem)
e.Register(bl)

// Angriff protokollieren
blocked, _ := bl.RecordAttack(clientIP)
```

### Konfiguration der Sitzungssicherheit

Das Paket `session` wird direkt als Middleware verwendet, nicht über die `Engine`. Der Speicher muss von der Anwendung bereitgestellt werden (standardmäßig ist eine In-Memory-Implementierung verfügbar, austauschbar z. B. gegen Redis):

```go
import "github.com/erikwang2013/security-go/session"

st := session.NewMemoryStore()
defer st.Close()

tr := session.NewTracker(st)
tr.CountryOf = geo.Lookup // optional: GeoIP anbinden, um länderübergreifende Anmeldungen zu erkennen

// Sitzung nach erfolgreicher Anmeldung binden (das Token stammt aus Ihrem Login-Ablauf)
// Erkennung von Anmeldungen von einem anderen Ort: mit den früheren Login-Subnetzen des Nutzers vergleichen und bei einem neuen Subnetz warnen
if res := tr.Observe("user-1", r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
if err := tr.Issue(token, r); err != nil {      // Token binden → IP-Subnetz / UA / Gerätefingerabdruck
    http.Error(w, "session error", http.StatusInternalServerError)
    return
}

// Routen schützen: bei Entführung oder Anmeldung von einem anderen Ort direkt 401 zurückgeben
mux.Handle("/api/", tr.Guard(apiHandler))

// oder nur erkennen und selbst über die Reaktion entscheiden
if res := tr.Check(r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}

// Abmelden
tr.Revoke(token)
```

Erkennung von Datenmanipulation: Client und Server teilen sich einen Schlüssel, der Client signiert die Parameter, der Server berechnet die Prüfung neu:

```go
signer := session.NewSigner(secret, storage.NewMemory()) // das zweite Argument blockiert Signatur-Replays, kann nil sein

sig, _ := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // Client: zusammen mit den Parametern übermitteln

if res := signer.Verify(map[string]string{"amount": "100", "to": "bob"}, sig); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
```

> `TrustProxyHeaders` ist standardmäßig deaktiviert: `X-Forwarded-For` / `X-Real-IP` sind vom Client kontrollierbar, daher nur hinter einem eigenen Reverse-Proxy aktivieren.
> `FailClosed` ist standardmäßig deaktiviert (Freigabe bei Speicherfehlern, konsistent mit `IPBlacklist`); für sitzungssensitive Anwendungen wird die Aktivierung empfohlen.

### Benutzerdefinierte Detektoren

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "Schadinhalt erkannt",
    }
}

e.Register(&MyDetector{})
```

### Das Maskottchen

Das Paket `pet` bettet den Sentinel Gopher zur Kompilierzeit über `go:embed` als SVG ein — keine Dateiabhängigkeit zur Laufzeit, keine zusätzliche Fremdabhängigkeit:

```go
import "github.com/erikwang2013/security-go/pet"

log.Println(pet.Banner())              // Startbanner: terminalfreundlicher Klartext
http.Handle("/pet.svg", pet.Handler()) // Debug-Route: wird als image/svg+xml ausgeliefert, einen Tag gecacht
svg := pet.SVG()                       // oder die rohen SVG-Bytes nehmen
```

### Weitere Dokumentation

- [API-Referenz](api.md) — Kerntypen, Detector-/Engine-Schnittstellen, Storage-Backend-Schnittstelle, HTTP-Validator
- [Design-Spezifikation](specs/2026-07-29-attack-detection-design.md) — Paketstruktur, Detektor-Verzeichnis
- [Implementierungsplan](plans/2026-07-29-attack-detection-plan.md) — Schritt-für-Schritt-Aufgabenplan und Abweichungsvergleich
- [Code-Review-Bericht](reports/2026-07-29-code-review-report.md) — Bug-Fixes, Testabdeckung, Architekturbewertung
- [Code-Review-Bericht v2](reports/2026-07-29-code-review-report-v2.md) — Zweiter Durchgang: 4 Probleme behoben, 18 Testdateien ergänzt

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

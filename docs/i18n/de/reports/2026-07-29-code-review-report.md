# Security-Go Code-Review-Bericht

**Datum**: 2026-07-29  
**Projekt**: github.com/erikwang2013/security-go  
**Prüfungsumfang**: 42 Go-Quelldateien, 8 Pakete (security, all, data, file, httpval, injection, protocol, storage)

---

## 1. Testergebnisse

```
ok      github.com/erikwang2013/security-go       0.004s
?       github.com/erikwang2013/security-go/all   [no test files]
ok      github.com/erikwang2013/security-go/data  0.005s
ok      github.com/erikwang2013/security-go/file  0.006s
ok      github.com/erikwang2013/security-go/httpval 0.004s  (已补写 32 个测试)
ok      github.com/erikwang2013/security-go/injection 0.005s
ok      github.com/erikwang2013/security-go/protocol  0.005s
ok      github.com/erikwang2013/security-go/storage   0.159s
```

- `go vet ./...` bestanden, keine Warnungen
- Alle Tests bestanden
- **Pakete ohne Tests**: `all` (als einziges)

---

## 2. Behobene Bugs

### Bug #1 [Kritisch] `storage/file.go:101` — JSON-Serialisierungsfehler wurde stillschweigend ignoriert

**Problem**: In der Methode `Close()` wurde bei `data, _ := json.Marshal(out)` der Serialisierungsfehler ignoriert. Wenn die JSON-Serialisierung fehlschlägt, ist `data` nil und `os.WriteFile` schreibt leere Daten — **die gesamten persistierten Daten gehen verloren**.

**Fix**: Rückgabewert des Fehlers von `json.Marshal` prüfen, bei Fehler sofort error zurückgeben.

```go
// 修复前
data, _ := json.Marshal(out)
return os.WriteFile(f.path, data, 0644)

// 修复后
data, err := json.Marshal(out)
if err != nil {
    return err
}
return os.WriteFile(f.path, data, 0644)
```

### Bug #2 [Kritisch] `httpval/content_type.go:34` — leere AllowList lässt alle Content-Types durch

**Problem**: Die Bedingung `if len(c.Allowed) == 0 || c.Allowed[mt]` bedeutet: Wenn die AllowList leer ist, werden **alle Content-Types durchgelassen**. Der sichere Standardwert sollte deny-all sein.

**Fix**: Die Bedingung `len(c.Allowed) == 0` entfernen — eine leere AllowList fällt in den Ablehnungszweig.

```go
// 修复前
if len(c.Allowed) == 0 || c.Allowed[mt] {
    return &security.Result{Name: c.Name(), Detected: false}
}

// 修复后
if c.Allowed[mt] {
    return &security.Result{Name: c.Name(), Detected: false}
}
```

### Bug #3 [Mittel] `protocol/xxe.go:15` — `&[a-z]+;` matcht fälschlicherweise alle legitimen HTML/XML-Entitäten

**Problem**: Der reguläre Ausdruck `(?i)&[a-z]+;` matcht alle Standard-Entitätsreferenzen (`&amp;`, `&lt;`, `&gt;` usw.), sodass jede Anfrage mit legitimen HTML/XML-Inhalten fälschlich als XXE-Angriff gemeldet wird.

**Fix**: Der Matcher wird auf bekannte bösartige Protokoll-Präfixe eingegrenzt.

```go
// 修复前
regexp.MustCompile(`(?i)&[a-z]+;`),

// 修复后
regexp.MustCompile(`(?i)&(?:xxe|file|http|ftp|gopher|dict|data|expect);`),
```

---

## 3. Festgestellte Nebenprobleme (nicht behoben, müssen bewertet werden)

### Problem #1: Paket `all` hat keine Testabdeckung

Die Funktion `RegisterAll()` in `all/all.go` hat keinerlei Tests. Es sollte ein Test hinzugefügt werden, der verifiziert, dass alle registrierten Detektoren ordnungsgemäß aufrufbar sind.

### Problem #2: Tests für Paket `httpval` ergänzt ✅ (gelöst)

Es wurde `httpval/httpval_test.go` hinzugefügt (32 Testfälle), abdeckend `BodySize` (7 Tests), `ContentType` (7 Tests), `CSRFOrigin` (8 Tests), `IPBlacklist` (6 Tests), `Method` (3 Tests). Inklusive Grenzwerten, Fehleingaben und Verifikation des deny-all bei leerer AllowList.

### Problem #3: Regex für Kreditkartennummern in `data/data_leak.go` zu breit

`\b(?:\d[ -]*?){13,16}\b` matcht jede 13- bis 16-stellige Ziffernfolge.

### Problem #4: Untermodul `storage/redis/` unvollständig

- Dem `go.mod` fehlt die Abhängigkeitsdeklaration zum übergeordneten Modul
- Die Datei `go.sum` fehlt

### Problem #5: Uneinheitlicher Receiver-Stil zwischen protocol- und injection-Paket

- Paket `injection` verwendet Pointer-Receiver: `func (d *XSS) Name() string`
- Paket `protocol` verwendet Wert-Receiver: `func (d CORS) Name() string`

### Problem #6: `injection/xss.go` — `&#x?[0-9a-f]+;?` matcht legitime numerische HTML-Zeichenreferenzen

---

## 4. Architektur-Gesamtbewertung

| Dimension | Bewertung | Beschreibung |
|-----------|-----------|--------------|
| Schnittstellendesign | ★★★★☆ | `Detector`-Schnittstelle + `Engine`-Orchestrierungsmuster klar |
| Code-Konsistenz | ★★★☆☆ | Receiver-Stil nicht einheitlich |
| Fehlerbehandlung | ★★★☆☆ | Vor dem Fix stillschweigend verschluckte Fehler; nach dem Fix verbessert |
| Testabdeckung | ★★★★☆ | `httpval`-Tests ergänzt, Paket `all` fehlt weiterhin |
| Sichere Standardwerte | ★★★☆☆ | Problem der leeren AllowList bei ContentType behoben |
| Erkennungsgenauigkeit | ★★★☆☆ | Einige Regexe bergen Fehlalarmrisiko (xxe teilweise behoben) |

---

## 5. Empfohlene Prioritäten

| Priorität | Maßnahme |
|-----------|----------|
| ~~P0~~ | ~~Tests für Paket `httpval` ergänzen~~ ✅ erledigt (32 Tests, 5 Detektoren) |
| P1 | Tests für Paket `all` ergänzen |
| P1 | go.mod des Untermoduls `storage/redis/` reparieren |
| P2 | Receiver-Stil einheitlich auf Pointer-Receiver umstellen |
| P2 | Fehlalarmrate der Kreditkarten-/XSS-Regexe bewerten |

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

# Security Go — API-Referenz

Dieses Dokument fasst alle öffentlichen APIs von `security-go` zusammen: Kerntypen, die `Detector`-Schnittstelle, die `Engine`-Registry, die Storage-Backend-Schnittstelle und die Konstruktoren der HTTP-Validator.

## Kerntypen

### Result

Die von jedem Detektor zurückgegebene Ergebnisstruktur:

```go
type Result struct {
    Name     string                 // Detektorname
    Detected bool                   // ob ein Angriff erkannt wurde
    Message  string                 // Ergebnisbeschreibung
    Severity Severity               // Schweregrad
    Details  map[string]interface{} // zusätzliche Details
}
```

### Severity

Schweregrade:

```go
type Severity int

const (
    SeverityLow      Severity = iota // niedriges Risiko
    SeverityMedium                   // mittleres Risiko
    SeverityHigh                     // hohes Risiko
    SeverityCritical                 // kritisch
)
```

## Detector-Schnittstelle

Alle Detektoren müssen diese Schnittstelle implementieren:

```go
type Detector interface {
    Name() string                // eindeutiger Name des Detektors
    Detect(input string) *Result // führt die Prüfung der Eingabe aus und liefert das Ergebnis
}
```

## Engine-Registry

`Engine` ist der zentrale Einstiegspunkt und verwaltet Detektoren, registriert nach Name:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // erstellt eine leere Engine
func (e *Engine) Register(d Detector)             // registriert einen Detektor
func (e *Engine) Detect(name, input string) *Result // prüft eine einzelne Eingabe nach Namen
func (e *Engine) DetectAll(input string) []*Result  // prüft alles (liefert nur Detected=true)
func (e *Engine) DetectRequest(r *http.Request) []*Result // prüft eine vollständige HTTP-Anfrage
```

`DetectRequest` sammelt automatisch URL, Query, Headers und Cookies der Anfrage als Eingaben. Jede Eingabe wird zusätzlich nach URL-Dekodierung erneut geprüft, sodass kodierte Nutzlasten wie `%3Cscript%3E` die Erkennung nicht umgehen.

## Registrierungseinstieg

```go
// Das Paket all registriert mit einem Aufruf alle Detektoren ohne Konfiguration (27 Stück)
all.RegisterAll(engine)
```

## Hilfsfunktionen

```go
// FirstMatch liefert das erste Muster, das auf input passt; ohne Treffer ("", false)
func FirstMatch(input string, patterns []*regexp.Regexp) (string, bool)
```

Damit können benutzerdefinierte Detektoren die eingebauten vorkompilierten Muster wiederverwenden, ohne reguläre Ausdrücke erneut zu kompilieren.

## Storage-Backend-Schnittstelle

`httpval.IPBlacklist` nutzt über diese Schnittstelle steckbare Speicherung:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // Zähler im Fenster +1
    Get(key string) (int, error)                          // liest den Zähler
    Block(key string, duration time.Duration) error       // sperrt für die angegebene Dauer
    IsBlocked(key string) (bool, error)                   // ob bereits gesperrt
    Close() error                                         // schließt und gibt Ressourcen frei
}
```

Implementierungen:

| Backend | Beschreibung |
|---------|--------------|
| `storage.NewMemory() *Memory` | In-Memory-Implementierung, `sync.Mutex` + map, automatische Bereinigung abgelaufener Einträge nach 30 s |
| `storage.NewFile(path) (*File, error)` | JSON-Datei-Persistenz, automatisches Speichern alle 30 s + flush bei Close |
| `redis.New(addr, password string, db int) *Backend` | Redis-Untermodul, Pipeline Incr + TTL, erfordert `go-redis/v9` |

## HTTP-Validator

```go
// Prüfung der HTTP-Methoden-Whitelist
e.Register(&httpval.Method{})

// Begrenzung der Request-Body-Größe (Standard 10 MB)
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type-Whitelist (leere Whitelist = alles ablehnen)
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF-Origin-Prüfung (bei Cross-Origin-Anfragen wird Origin gegen Host geprüft)
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP-Blacklist (automatische Sperre nach N Angriffen im Fenster; Standard 5/60 s → 15 Minuten Sperre)
bl := httpval.NewIPBlacklist(mem) // mem ist eine beliebige storage.Backend-Implementierung
e.Register(bl)
blocked, _ := bl.RecordAttack(clientIP)
```

### JSON-Verschachtelungstiefe und Cookie-Attribute

| Konstruktor | Beschreibung |
|--------|------|
| `NewNestedDepth(maxDepth, maxKeys) *NestedDepth` | Streamt einen JSON-Body: meldet `nested_depth` bei Überschreitung der Tiefe (Standard 32) oder der Elementanzahl. Nicht-JSON und abgeschnittenes JSON treffen nie |
| `NewCookieAttrs(requireSecure, requireHttpOnly, requireSameSite) *CookieAttrs` | Prüft ein `Set-Cookie`: fehlende Attribute, überlanger Wert (`MaxValueLen`), leerer Wert (`RequireNonEmpty`) |

## Sitzungssicherheit

Das Paket `session` erkennt **Client-Entführung**, **Datenmanipulation** und **Anmeldung von einem anderen Ort**. Es benötigt den vollständigen `*http.Request` (Token, Client-IP, User-Agent) sowie den von der Anwendung bereitgestellten Speicher und Schlüssel; deshalb wird es nicht in die `Engine` registriert, sondern direkt als Middleware/Funktion aufgerufen.

### Store-Schnittstelle

Die Sitzungsbindung lässt sich nicht mit `storage.Backend` ausdrücken (nur Zähler und Sperren), daher bringt `session` eine eigene kleine Schnittstelle mit:

```go
type Store interface {
    Save(key string, value []byte, ttl time.Duration) error
    Load(key string) ([]byte, error)   // liefert (nil, nil), wenn nicht vorhanden oder abgelaufen
    Delete(key string) error
}

session.NewMemoryStore() *MemoryStore // In-Memory-Implementierung, räumt abgelaufene Einträge alle 30 s auf, Close stoppt die Bereinigung
```

### Session

```go
type Session struct {
    IP          string    `json:"ip"`           // Client-IP beim Aufbau der Sitzung
    UserAgent   string    `json:"ua,omitempty"`
    Fingerprint string    `json:"fp,omitempty"` // Gerätefingerabdruck (Header X-Device-Fingerprint)
    Country     string    `json:"country,omitempty"`
    IssuedAt    time.Time `json:"issued_at"`
    LastSeen    time.Time `json:"last_seen"`    // gleitende Verlängerung bei jedem Check
}
```

### Tracker

Detektorname `session_guard` (siehe `Tracker.Name()`).

```go
type Tracker struct {
    Store             Store
    TTL               time.Duration              // Lebensdauer der Sitzung, Standard 30m, gleitende Verlängerung bei jedem Check
    SubnetBits        int                        // Präfix für die Gleichort-Prüfung, Standard 24 (IPv6 automatisch +24)
    CountryOf         func(ip string) string     // optionaler GeoIP-Hook; bei nil entfällt die Länderprüfung
    KnownNets         int                        // Anzahl der von Observe je Benutzer behaltenen Anmeldenetze, Standard 8
    KnownNetTTL       time.Duration              // Aufbewahrungsdauer der Anmeldenetze, Standard 90 Tage
    TokenSource       func(*http.Request) string // Standard DefaultTokenSource
    TrustProxyHeaders bool                       // Standard false
    FailClosed        bool                       // Standard false
    Failures          int                        // Schwellwert der Fehlversuche im Fenster für die token-Sperre, Standard 5
    FailureWindow     time.Duration              // Aufbewahrungsdauer des Fehlerzählers, ältere zählen nicht, Standard 5m
    Lockout           time.Duration              // Sperrdauer beim ersten Erreichen der Schwelle, verdoppelt sich jedes Mal, Standard 15m
    MaxLockout        time.Duration              // Obergrenze der Verdopplung je Sperre, Standard 24h
    BackoffWindow     time.Duration              // Aufbewahrungsdauer des Eskalationszählers, Standard 24h
    StuffingLimit     int                        // Obergrenze verschiedener Identitäten, gegen die dieselbe IP scheitern darf, Standard 10
}
```

| Methode | Beschreibung |
|------|------|
| `NewTracker(store) *Tracker` | Erstellt den Tracker und füllt die Standardwerte ein |
| `Issue(token, r) error` | Bindet nach erfolgreicher Anmeldung token → IP-Subnetz / UA / Fingerabdruck; ein leeres token gibt einen Fehler zurück |
| `Check(r) *Result` | Prüft bei jeder Anfrage, liefert bei Treffer `Detected: true`; bei Erfolg gleitende Verlängerung |
| `Observe(user, r) *Result` | Vergleicht bei der Anmeldung die historischen Subnetze des Benutzers und warnt bei einem neuen Subnetz; die erste Anmeldung hat keine Basislinie und warnt nicht |
| `Guard(http.Handler) http.Handler` | Middleware-Wrapper, der bei Treffer von `Check` 401 zurückgibt |
| `Revoke(token) error` | Abmeldung, die Sitzung wird sofort ungültig |
| `DefaultTokenSource(r) string` | Liest `Authorization: Bearer <token>`, andernfalls das Cookie `session` |
| `RecordFailure(identity, r) error` | Zählt eine fehlgeschlagene Anmeldung (identity ist der Authentifizierungsschlüssel wie der Benutzername, r liefert die Client-IP). Bei Erreichen von `Failures` (Standard 5 in 5 Minuten) wird gesperrt, jede Sperre verdoppelt sich bis `MaxLockout` (Standard 24 h) |
| `CheckLogin(identity, r) *Result` | Vorabprüfung eines Anmeldeversuchs: `token_locked` bei gesperrter Identität, `credential_stuffing`, wenn die Client-IP bereits gegen `StuffingLimit` (Standard 10) verschiedene Identitäten gescheitert ist — beide Critical |
| `GuardLogin(next, identity) http.Handler` | Middleware für einen Authentifizierungs-Endpunkt: 429 mit `Retry-After` bei Treffer; danach zählt 401 als Fehlversuch und 2xx setzt den Zähler zurück |
| `IsLocked(token) (bool, time.Time)` | Ob das Token gesperrt ist und bis wann; ein Speicherfehler gilt als nicht gesperrt |
| `ClearFailures(token) error` | Setzt den Fehlerzähler nach erfolgreicher Anmeldung zurück (eine Sperre läuft über ihren eigenen Timer) |

Werte von `Details["reason"]`:

| reason | Auslösebedingung | Schweregrad |
|--------|---------|---------|
| `missing_token` | Die Anfrage enthält kein token | High |
| `unknown_token` | token wurde nicht ausgestellt, wurde per `Revoke` beendet oder ist abgelaufen | High |
| `token_locked` | Fehlerschwelle im Fenster erreicht, Token gesperrt | Critical |
| `credential_stuffing` | Eine Client-IP ist im Fenster gegen `StuffingLimit` verschiedene Identitäten gescheitert | Critical |
| `client_hijack` | UA geändert oder Gerätefingerabdruck geändert | Critical |
| `remote_login` | `CountryOf` stellt einen Länderwechsel fest (Critical) / IP in einem anderen Subnetz (High); wird von `Check` und `Observe` gemeinsam genutzt | Critical / High |
| `store_error` | Speicherlesefehler und `FailClosed = true` | High |

> `TrustProxyHeaders` ist standardmäßig deaktiviert: `X-Forwarded-For` / `X-Real-IP` sind vom Client kontrollierbar; nach dem Aktivieren kann ein Angreifer die gebundene IP fälschen. Nur hinter einem eigenen Reverse-Proxy aktivieren.
> `FailClosed` ist standardmäßig deaktiviert (Freigabe bei Speicherfehlern), konsistent mit `httpval.IPBlacklist`. Der Speicherschlüssel ist der SHA-256 des token; ein Speicherleck liefert daher keinen direkt nutzbaren token.

### Signer

Detektorname `data_tamper` (siehe `Signer.Name()`).

```go
type Signer struct {
    Secret  []byte           // gemeinsamer HMAC-Schlüssel, mit crypto/rand erzeugt
    MaxSkew time.Duration    // erlaubte Zeitstempelabweichung, Standard 5m
    Nonces  storage.Backend  // optional: wenn nicht leer, blockiert ein Fensterzähler Signatur-Replays (instanzübergreifend, Redis wiederverwendbar)
}

signer := session.NewSigner(secret, mem)
sig, err := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // "<unix-ts>.<nonce>.<mac>"
res := signer.Verify(params, sig)                                        // Parameter geändert/Schlüssel falsch/abgelaufen/Replay
```

Parameter werden über `url.Values.Encode()` normalisiert (Sortierung + Escaping), die Map-Reihenfolge beeinflusst das Ergebnis nicht. Die Prüfreihenfolge ist Zeitstempel → Signatur → Nonce-Zähler, daher kann eine gefälschte Signatur keine gültige Nonce verbrauchen; ist `Nonces` nil, lässt sich Replay nur über das Zeitstempel-Fenster einschränken.

Werte von `Details["reason"]`: `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High).

## Hilfsfunktionen für Datei-Uploads

Die Upload-Erkennung stellt neben ihrer Registrierung als Detektor zwei direkt aufrufbare Hilfsfunktionen bereit:

```go
// HasMaliciousExt prüft, ob die Dateiendung nicht in der Whitelist (15 Endungen) steht; ohne Endung true
func HasMaliciousExt(filename string) bool

// CheckExtension nutzt dieselbe Quelle, liefert aber ein vollständiges *Result (mit Schweregrad und Beschreibung)
func (d *MaliciousFileUpload) CheckExtension(filename string) *security.Result
```

Damit lässt sich vor dem Schreiben auf die Platte eine schnelle Vorprüfung durchführen, ohne eine `Engine` aufzubauen.

## Projekt-Maskottchen

Das Paket `pet` bettet die SVG des Projekt-Maskottchens Sentinel Gopher (哨兵鼠) über `go:embed` zur Kompilierzeit ein, ohne Fremdabhängigkeit und ohne Dateizugriff zur Laufzeit:

```go
func SVG() []byte         // rohe SVG-Bytes; das Slice wird geteilt und darf vom Aufrufer nicht geändert werden
func Handler() http.Handler // wird als image/svg+xml ausgeliefert, Cache-Control für einen Tag
func Banner() string      // terminalfreundlicher Klartext-Banner mit abschließendem Zeilenumbruch
```

```go
log.Println(pet.Banner())              // beim Start ausgeben
http.Handle("/pet.svg", pet.Handler()) // an eine Debug-Route hängen
```

`Handler` verwendet intern `http.ServeContent` und liefert daher `Content-Length`; `Range` und `HEAD` werden unterstützt. Ein direktes `w.Write` überschreitet den 2-KiB-Sniff-Puffer von `net/http` und degradiert zu einer chunked-Antwort.

### Mood: von Erkennungsergebnissen gesteuert

Das Maskottchen ist kein statisches Bild — Schild, Radar und Lupe wechseln mit dem Scan-Ergebnis die Farbe und taugen damit direkt als Statusanzeige der Bedrohungsstufe:

```go
type Mood int

const (
    Calm     Mood = iota // sauberer Scan
    Watchful             // Treffer, aber keine High / Critical
    Alarmed              // mindestens ein High oder Critical, Handlungsbedarf
)

func MoodOf(results []*security.Result) Mood  // Einstufung nach dem schwersten Treffer
func SVGFor(m Mood) []byte                    // Grafik für diese Haltung; unbekannte Werte fallen auf Calm zurück
func MoodHandler(moodFor func(*http.Request) Mood) http.Handler
```

`MoodOf` zählt nur Ergebnisse mit gesetztem `Detected` — ein Detektor setzt `Severity` auch dann, wenn er nichts findet; die Severity allein darf also keinen Alarm auslösen. Der schwerste Treffer gewinnt, unabhängig von der Reihenfolge der Ergebnisse.

An die Engine angebunden ist es eine lebende Bedrohungsstatus-Grafik:

```go
e := security.NewEngine()
all.RegisterAll(e)

http.Handle("/pet.svg", pet.MoodHandler(func(r *http.Request) pet.Mood {
    return pet.MoodOf(e.DetectRequest(r))
}))
```

`MoodHandler` trägt `Cache-Control: no-store` — anders als der statische `Handler` ändert sich seine Ausgabe mit dem Scan-Ergebnis; eine Tages-Cache würde eine veraltete Haltung zurückliefern.

## Beispiel für benutzerdefinierte Detektoren

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

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

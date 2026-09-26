# Security Go — API Reference

This document summarizes all public APIs of `security-go`: core types, the `Detector` interface, the `Engine` registry, storage backend interfaces, and HTTP validator constructors.

## Core Types

### Result

The detection result struct, returned by every detector:

```go
type Result struct {
    Name     string                 // detector name
    Detected bool                   // whether an attack was detected
    Message  string                 // result description
    Severity Severity               // severity level
    Details  map[string]interface{} // additional details
}
```

### Severity

Severity levels:

```go
type Severity int

const (
    SeverityLow      Severity = iota // low risk
    SeverityMedium                   // medium risk
    SeverityHigh                     // high risk
    SeverityCritical                 // critical
)
```

## Detector Interface

All detectors must implement this interface:

```go
type Detector interface {
    Name() string                // unique detector name
    Detect(input string) *Result // run detection on the input and return the result
}
```

## Engine Registry

`Engine` is the unified entry point that registers and manages detectors by name:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // create an empty Engine
func (e *Engine) Register(d Detector)             // register a detector
func (e *Engine) Detect(name, input string) *Result // detect a single input by name
func (e *Engine) DetectAll(input string) []*Result  // detect everything (only returns Detected=true)
func (e *Engine) DetectRequest(r *http.Request) []*Result // detect a complete HTTP request
```

`DetectRequest` automatically collects the request's URL, Query, Headers, and Cookies as input. Each input is also scanned after URL-decoding, so encoded payloads such as `%3Cscript%3E` cannot bypass detection.

## Registration Entry Point

```go
// the all package registers every zero-config detector (27) in one call
all.RegisterAll(engine)
```

## Helper Function

```go
// FirstMatch returns the first pattern matching input; ("", false) when none match
func FirstMatch(input string, patterns []*regexp.Regexp) (string, bool)
```

Custom detectors can reuse the built-in pre-compiled patterns instead of compiling the regular expressions again.

## Storage Backend Interface

`httpval.IPBlacklist` uses pluggable storage through this interface:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // increment the count inside the window
    Get(key string) (int, error)                          // read the count
    Block(key string, duration time.Duration) error       // block for the given duration
    IsBlocked(key string) (bool, error)                   // whether it is already blocked
    Close() error                                         // close and release resources
}
```

Implementations:

| Backend | Description |
|------|------|
| `storage.NewMemory() *Memory` | In-memory implementation, `sync.Mutex` + map, auto-cleans expired entries every 30s |
| `storage.NewFile(path) (*File, error)` | JSON file persistence, auto-save every 30s + flush on Close |
| `redis.New(addr, password string, db int) *Backend` | Redis submodule, Pipeline Incr + TTL, requires `go-redis/v9` |

## HTTP Validators

```go
// HTTP method whitelist validation
e.Register(&httpval.Method{})

// request body size limit (default 10MB)
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type whitelist (an empty whitelist rejects everything)
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF Origin check (cross-origin requests must have a matching Origin and Host)
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP blacklist (auto-ban after N attacks in the window; default 5/60s → 15-minute ban)
bl := httpval.NewIPBlacklist(mem) // mem is any storage.Backend implementation
e.Register(bl)
blocked, _ := bl.RecordAttack(clientIP)
```

### JSON Nesting Depth & Cookie Attributes

| Constructor | Description |
|--------|------|
| `NewNestedDepth(maxDepth, maxKeys) *NestedDepth` | Streams a JSON body: reports `nested_depth` when nesting depth (default 32) or element count is exceeded. Non-JSON and truncated JSON never match |
| `NewCookieAttrs(requireSecure, requireHttpOnly, requireSameSite) *CookieAttrs` | Validates one `Set-Cookie`: missing attributes, overlong value (`MaxValueLen`), empty value (`RequireNonEmpty`) |

## Session Security

The `session` package detects **client hijacking**, **data tampering**, and **remote login**. It needs the complete `*http.Request` (token, client IP, User-Agent) plus application-provided storage and a secret key, so it is not registered with the `Engine` and is called directly as middleware/functions.

### Store interface

A session binding cannot be expressed with `storage.Backend` (counts and bans only), so `session` ships its own small interface:

```go
type Store interface {
    Save(key string, value []byte, ttl time.Duration) error
    Load(key string) ([]byte, error)   // returns (nil, nil) when absent or expired
    Delete(key string) error
}

session.NewMemoryStore() *MemoryStore // in-memory implementation; cleans expired entries every 30s, Close stops the cleanup
```

### Session

```go
type Session struct {
    IP          string    `json:"ip"`           // client IP at session creation
    UserAgent   string    `json:"ua,omitempty"`
    Fingerprint string    `json:"fp,omitempty"` // device fingerprint (X-Device-Fingerprint header)
    Country     string    `json:"country,omitempty"`
    IssuedAt    time.Time `json:"issued_at"`
    LastSeen    time.Time `json:"last_seen"`    // slide-renewed on every Check
}
```

### Tracker

Detector name `session_guard` (see `Tracker.Name()`).

```go
type Tracker struct {
    Store             Store
    TTL               time.Duration              // session lifetime, default 30m, slide-renewed on every Check
    SubnetBits        int                        // same-location prefix, default 24 (IPv6 automatically +24)
    CountryOf         func(ip string) string     // optional GeoIP hook; country checks are skipped when nil
    KnownNets         int                        // login networks Observe keeps per user, default 8
    KnownNetTTL       time.Duration              // how long a login network is kept, default 90 days
    TokenSource       func(*http.Request) string // default DefaultTokenSource
    TrustProxyHeaders bool                       // default false
    FailClosed        bool                       // default false
    Failures          int                        // failure threshold that locks the token inside the window, default 5
    FailureWindow     time.Duration              // how long failures are counted; older ones are ignored, default 5m
    Lockout           time.Duration              // lock duration on first crossing the threshold, doubles each further crossing, default 15m
    MaxLockout        time.Duration              // cap on the doubling lockout, default 24h
    BackoffWindow     time.Duration              // how long escalation counts are kept, default 24h
    StuffingLimit     int                        // max distinct identities one IP may fail against, default 10
}
```

| Method | Description |
|------|------|
| `NewTracker(store) *Tracker` | Creates a tracker and fills in the defaults |
| `Issue(token, r) error` | Binds the token to the IP subnet / UA / fingerprint after a successful login; an empty token returns an error |
| `Check(r) *Result` | Validates on every request and returns `Detected: true` on a hit; slide-renews on pass |
| `Observe(user, r) *Result` | At login, compares against the user's historical login networks and alerts on a new subnet; no alert on the first login (no baseline) |
| `Guard(http.Handler) http.Handler` | Middleware wrapper; returns 401 as soon as `Check` hits |
| `Revoke(token) error` | Logout; the session becomes invalid immediately |
| `DefaultTokenSource(r) string` | Reads `Authorization: Bearer <token>`, then the `session` cookie |
| `RecordFailure(identity, r) error` | Counts one failed login (identity is the authentication key such as a username; r supplies the client IP). Reaching `Failures` (default 5 in 5 minutes) locks the identity, doubling each episode up to `MaxLockout` (default 24h) |
| `CheckLogin(identity, r) *Result` | Pre-flight for a login attempt: `token_locked` when the identity is locked, `credential_stuffing` when the client IP has already failed against `StuffingLimit` (default 10) distinct identities — both Critical |
| `GuardLogin(next, identity) http.Handler` | Middleware for an authentication endpoint: 429 with `Retry-After` when it fires; a 401 afterwards counts as a failure and a 2xx clears the counter |
| `IsLocked(token) (bool, time.Time)` | Whether the token is locked and until when; a store error reads as unlocked |
| `ClearFailures(token) error` | Resets the failure count on a successful login (a lockout runs its own timer and is not cleared) |

`Details["reason"]` values:

| reason | Trigger | Severity |
|------|------|------|
| `missing_token` | The request carries no token | High |
| `unknown_token` | The token was never issued, has been `Revoke`d, or has expired | High |
| `token_locked` | Failure threshold reached inside the window, token locked out | Critical |
| `credential_stuffing` | One client IP failed against `StuffingLimit` distinct identities inside the window | Critical |
| `client_hijack` | The UA changed, or the device fingerprint changed | Critical |
| `remote_login` | `CountryOf` judges a country change (Critical) / an IP subnet change (High); shared by `Check` and `Observe` | Critical / High |
| `store_error` | The storage read failed and `FailClosed = true` | High |

> `TrustProxyHeaders` is disabled by default: `X-Forwarded-For` / `X-Real-IP` are client-controllable, and enabling it lets a hijacker forge the bound IP. Enable it only behind your own reverse proxy.
> `FailClosed` is disabled by default (requests pass through on storage failure), consistent with `httpval.IPBlacklist`. Storage keys are the SHA-256 of the token, so a storage leak does not directly yield a usable token.

### Signer

Detector name `data_tamper` (see `Signer.Name()`).

```go
type Signer struct {
    Secret  []byte           // shared HMAC secret, generate with crypto/rand
    MaxSkew time.Duration    // allowed timestamp skew, default 5m
    Nonces  storage.Backend  // optional: when non-nil, a window counter blocks signature replay (cross-instance, reuse Redis)
}

signer := session.NewSigner(secret, mem)
sig, err := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // "<unix-ts>.<nonce>.<mac>"
res := signer.Verify(params, sig)                                        // parameters altered / key mismatch / expired / replay
```

Parameters are canonicalized with `url.Values.Encode()` (sorted + escaped), so map ordering does not affect the result. Verification runs in the order timestamp → signature → nonce counter, so a forged signature cannot consume a legitimate nonce; when `Nonces` is nil, only the timestamp window limits replay.

`Details["reason"]` values: `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High).

## File Upload Helpers

Beyond registering as a detector, upload detection also exports two helper functions you can call directly:

```go
// HasMaliciousExt reports whether the file extension falls outside the whitelist (15 entries); a missing extension returns true
func HasMaliciousExt(filename string) bool

// CheckExtension shares the same logic but returns a full *Result (with severity and message)
func (d *MaliciousFileUpload) CheckExtension(filename string) *security.Result
```

Use it for a fast pre-flight check before a file reaches disk, without constructing an `Engine`.

## Project Mascot

The `pet` package embeds the project mascot, the Sentinel Gopher, as SVG at compile time via `go:embed`. It pulls in no third-party dependency and reads no files at runtime:

```go
func SVG() []byte         // raw SVG bytes; the slice is shared, callers must not modify it
func Handler() http.Handler // served as image/svg+xml, Cache-Control for one day
func Banner() string      // terminal-friendly plain-text banner, ends with a newline
```

```go
log.Println(pet.Banner())              // print at startup
http.Handle("/pet.svg", pet.Handler()) // mount on a debug route
```

`Handler` goes through `http.ServeContent` internally, so it carries a `Content-Length` and supports `Range` and `HEAD`; a bare `w.Write` would exceed the 2 KiB sniff buffer in `net/http` and degrade to a chunked response.

### Mood: driven by detection results

The mascot is not a static image — its shield, radar and magnifier recolour to match the scan, so it works directly as a threat-level indicator:

```go
type Mood int

const (
    Calm     Mood = iota // the scan found nothing
    Watchful             // hits, but none High / Critical
    Alarmed              // at least one High or Critical, needs handling
)

func MoodOf(results []*security.Result) Mood  // classified by the most severe hit
func SVGFor(m Mood) []byte                    // artwork for that mood; an unknown value falls back to Calm
func MoodHandler(moodFor func(*http.Request) Mood) http.Handler
```

`MoodOf` counts only results with `Detected` set — a detector stamps `Severity` even when it finds nothing, so severity alone must not raise the alarm. The most severe hit wins, independent of result order.

Wire the engine up and you get a live threat-state image:

```go
e := security.NewEngine()
all.RegisterAll(e)

http.Handle("/pet.svg", pet.MoodHandler(func(r *http.Request) pet.Mood {
    return pet.MoodOf(e.DetectRequest(r))
}))
```

`MoodHandler` carries `Cache-Control: no-store` — unlike the static `Handler`, its output changes with the scan, and caching it a day would serve a stale posture.

## Custom Detector Example

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

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

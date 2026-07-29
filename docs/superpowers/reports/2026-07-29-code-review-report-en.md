# Security-Go Code Review Report

**Date:** 2026-07-29  
**Project:** github.com/bag/security-go  
**Scope:** 42 Go source files, 8 packages (security, all, data, file, httpval, injection, protocol, storage)  

---

## 1. Test Results

```
ok      github.com/bag/security-go       0.004s
?       github.com/bag/security-go/all   [no test files]
ok      github.com/bag/security-go/data  0.005s
ok      github.com/bag/security-go/file  0.006s
ok      github.com/bag/security-go/httpval 0.004s  (32 tests added)
ok      github.com/bag/security-go/injection 0.005s
ok      github.com/bag/security-go/protocol  0.005s
ok      github.com/bag/security-go/storage   0.159s
```

- `go vet ./...` passed, zero warnings
- All tests passing
- **Missing tests:** `all` package only

---

## 2. Bugs Fixed

### Bug #1 [Critical] `storage/file.go` — JSON marshal error silently ignored

**Issue:** `Close()` method used `data, _ := json.Marshal(out)`, discarding marshal errors. On failure, `data` would be nil, `os.WriteFile` writes empty data, causing **complete persistent data loss**.

**Fix:** Check `json.Marshal` error and return before writing empty data.

```go
// Before
data, _ := json.Marshal(out)
return os.WriteFile(f.path, data, 0644)

// After
data, err := json.Marshal(out)
if err != nil {
    return err
}
return os.WriteFile(f.path, data, 0644)
```

### Bug #2 [Critical] `httpval/content_type.go` — Empty AllowList permits all Content-Types

**Issue:** `if len(c.Allowed) == 0 || c.Allowed[mt]` meant an empty AllowList allowed ALL content types. Security defaults should be deny-all.

**Fix:** Removed `len(c.Allowed) == 0` condition — empty AllowList now correctly denies everything.

```go
// Before
if len(c.Allowed) == 0 || c.Allowed[mt] {
    return &security.Result{Name: c.Name(), Detected: false}
}

// After
if c.Allowed[mt] {
    return &security.Result{Name: c.Name(), Detected: false}
}
```

### Bug #3 [Medium] `protocol/xxe.go` — `&[a-z]+;` matches all legitimate HTML/XML entities

**Issue:** `(?i)&[a-z]+;` matched standard entity references (`&amp;`, `&lt;`, `&gt;`), causing false positives on any HTML/XML content.

**Fix:** Narrowed to known malicious protocol prefixes.

```go
// Before
regexp.MustCompile(`(?i)&[a-z]+;`),

// After
regexp.MustCompile(`(?i)&(?:xxe|file|http|ftp|gopher|dict|data|expect);`),
```

---

## 3. Minor Issues (Unfixed)

| # | Issue | Location |
|---|-------|----------|
| 1 | No tests for `all` package | `all/all.go` |
| 2 | Credit card regex too broad (matches any 13-16 digit sequence) | `data/data_leak.go` |
| 3 | `storage/redis/` sub-module missing go.sum and parent dependency | `storage/redis/go.mod` |
| 4 | Inconsistent receiver style (pointer vs value) | `injection` vs `protocol` |
| 5 | `&#x?[0-9a-f]+;?` matches legitimate HTML entities | `injection/xss.go` |

---

## 4. Architecture Assessment

| Dimension | Score | Notes |
|-----------|-------|-------|
| Interface design | ★★★★☆ | Clean `Detector` + `Engine` orchestration pattern |
| Code consistency | ★★★☆☆ | Receiver style not unified |
| Error handling | ★★★☆☆ | Improved after silent error swallowing fix |
| Test coverage | ★★★★☆ | httpval tests added; `all` package still missing |
| Security defaults | ★★★☆☆ | ContentType empty AllowList issue fixed |
| Detection accuracy | ★★★☆☆ | Some regex have false positive risk (xxe partially fixed) |

---

## 5. Priority

| Priority | Item | Status |
|----------|------|--------|
| P0 | Write `httpval` tests | Done (32 tests, 5 detectors) |
| P1 | Write `all` package tests | Pending |
| P1 | Fix `storage/redis/` go.mod | Pending |
| P2 | Unify receiver style | Pending |
| P2 | Evaluate regex false positive rates | Pending |

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

# Security-Go Code Review Report

**Date**: 2026-07-29  
**Project**: github.com/erikwang2013/security-go  
**Review scope**: 42 Go source files, 8 packages (security, all, data, file, httpval, injection, protocol, storage)

---

## 1. Test Results

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

- `go vet ./...` passes, no warnings
- All tests pass
- **Package missing tests**: `all` (the only one)

---

## 2. Fixed Bugs

### Bug #1 [Critical] `storage/file.go:101` — JSON serialization errors silently ignored

**Problem**: `data, _ := json.Marshal(out)` in `Close()` ignored the serialization error. If JSON serialization fails, `data` is nil and `os.WriteFile` writes empty data, **causing all persisted data to be lost**.

**Fix**: Check the error return value of `json.Marshal` and return the error immediately on failure.

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

### Bug #2 [Critical] `httpval/content_type.go:34` — empty AllowList allows all Content-Types

**Problem**: The condition `if len(c.Allowed) == 0 || c.Allowed[mt]` means that when the AllowList is empty, **all Content-Types are allowed**. The secure default should be deny-all.

**Fix**: Remove the `len(c.Allowed) == 0` condition so an empty AllowList falls through to the rejection branch.

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

### Bug #3 [Medium] `protocol/xxe.go:15` — `&[a-z]+;` falsely matches all legitimate HTML/XML entities

**Problem**: The regex `(?i)&[a-z]+;` matches all standard entity references (`&amp;`, `&lt;`, `&gt;`, etc.), causing any request containing legitimate HTML/XML to be falsely flagged as an XXE attack.

**Fix**: Narrow the match to a list of known malicious protocol prefixes.

```go
// 修复前
regexp.MustCompile(`(?i)&[a-z]+;`),

// 修复后
regexp.MustCompile(`(?i)&(?:xxe|file|http|ftp|gopher|dict|data|expect);`),
```

---

## 3. Minor Issues Found (Not Fixed, Need Assessment)

### Issue #1: `all` package has no test coverage

The `RegisterAll()` function in `all/all.go` has no tests. Tests should be added to verify that all registered detectors can be invoked correctly.

### Issue #2: `httpval` package tests added ✅ (resolved)

`httpval/httpval_test.go` has been added (32 test cases) covering `BodySize` (7 tests), `ContentType` (7 tests), `CSRFOrigin` (8 tests), `IPBlacklist` (6 tests), `Method` (3 tests). Includes boundary values, malformed input, and empty-AllowList deny-all verification.

### Issue #3: `data/data_leak.go` credit card regex is too broad

`\b(?:\d[ -]*?){13,16}\b` matches any sequence of 13-16 digits.

### Issue #4: `storage/redis/` submodule is incomplete

- `go.mod` lacks a dependency declaration on the parent module
- `go.sum` file is missing

### Issue #5: Receiver style inconsistency between protocol and injection packages

- The `injection` package uses pointer receivers: `func (d *XSS) Name() string`
- The `protocol` package uses value receivers: `func (d CORS) Name() string`

### Issue #6: `injection/xss.go` — `&#x?[0-9a-f]+;?` matches legitimate HTML numeric character references

---

## 4. Architecture Assessment

| Dimension | Score | Notes |
|------|------|------|
| Interface design | ★★★★☆ | The `Detector` interface + `Engine` orchestration pattern is clear |
| Code consistency | ★★★☆☆ | Receiver style is inconsistent |
| Error handling | ★★★☆☆ | Silent error swallowing existed before the fix; improved after |
| Test coverage | ★★★★☆ | `httpval` tests added; `all` package still missing |
| Secure defaults | ★★★☆☆ | ContentType empty-AllowList issue fixed |
| Detection accuracy | ★★★☆☆ | Some regexes carry false-positive risk (xxe partially fixed) |

---

## 5. Recommended Priorities

| Priority | Item |
|--------|------|
| ~~P0~~ | ~~Add `httpval` package tests~~ ✅ Complete (32 tests, 5 detectors) |
| P1 | Add `all` package tests |
| P1 | Fix `storage/redis/` submodule go.mod |
| P2 | Unify receiver style to pointer receivers |
| P2 | Assess credit card / XSS regex false-positive rates |

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

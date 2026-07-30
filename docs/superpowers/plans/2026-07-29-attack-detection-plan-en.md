# Attack Detection Package — Implementation Plan

**Goal:** Build a pure Go attack detection library with 32 detectors across 5 categories, 3 pluggable storage backends, and a unified Engine registry. **Status: Complete (2026-07-29).**

**Architecture:** Flat interface design — every detector implements `Detector` (Name + Detect). Pre-compiled regex patterns. Engine provides registry, by-name lookup, and `DetectRequest` for full HTTP request scanning. RegisterAll lives in `all/all.go` (separate package).

**Tech Stack:** Go 1.21+, stdlib `regexp` + `net/http`, `go-redis` for Redis backend (optional submodule at `storage/redis/`).

---

### Tasks 1-12: Implementation — All Complete

All 32 detectors implemented across 5 packages plus `all/all.go` for one-shot registration.

### Task 13: Tests — Complete

| Package | Test File | Tests |
|---------|----------|-------|
| security | security_test.go | 5 |
| data | jwt_attack_test.go | 4 |
| file | path_traversal_test.go, data_leak_test.go | ~16 |
| injection | xss_test.go, sql_test.go, jndi_test.go, ssti_test.go | ~24 |
| protocol | ssrf_test.go | 11 |
| storage | memory_test.go | 4 |

---

### Task 14: Post-Implementation Code Review & Fixes (2026-07-29)

- [x] **Full code review** — 42 Go source files, 8 packages
- [x] **Bug fix #1** — `storage/file.go`: JSON marshal error silently ignored → return error on failure
- [x] **Bug fix #2** — `httpval/content_type.go`: Empty AllowList allowed all content types → deny-all default
- [x] **Bug fix #3** — `protocol/xxe.go`: `&[a-z]+;` matched legitimate HTML entities → narrowed to known malicious protocols
- [x] **httpval tests** — 32 test cases covering 5 detectors (BodySize, ContentType, CSRFOrigin, IPBlacklist, Method)
- [x] **Full test suite** — `go test -count=1 ./...` 7/7 packages pass, `go vet` zero warnings

---

## Actual vs Planned Deviations

| Planned | Actual | Reason |
|---------|--------|--------|
| RegisterAll in `security.go` | `all/all.go` separate package | Avoid circular imports |
| Redis in root go.mod | `storage/redis/` sub-module | Isolate optional dependency |
| Unified pointer receivers | protocol uses value receivers | ✅ Fixed in v2 review — all changed to pointer receivers |
| Per-task commits | Single implementation pass | All code implemented at once |

## Test Coverage Summary

| Package | Tests | Status |
|---------|-------|--------|
| security | 5 | OK |
| data | 8 | OK |
| file | 5 | OK |
| httpval | 32 | OK (added post-review) |
| injection | 10 | OK |
| protocol | 9 | OK |
| storage | 4 | OK |
| all | 0 | Pending |

> Full report: `docs/superpowers/reports/2026-07-29-code-review-report-v2.md`

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

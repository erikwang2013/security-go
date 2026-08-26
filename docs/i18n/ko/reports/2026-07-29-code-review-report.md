# Security-Go 코드 리뷰 보고서

**날짜**: 2026-07-29  
**프로젝트**: github.com/erikwang2013/security-go  
**리뷰 범위**: Go 소스 파일 42개, 8개 패키지(security, all, data, file, httpval, injection, protocol, storage)

---

## 1. 테스트 결과

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

- `go vet ./...` 통과, 경고 없음
- 모든 테스트 통과
- **테스트 누락 패키지**: `all`(유일)

---

## 2. 수정된 Bug

### Bug #1 [심각] `storage/file.go:101` — JSON 직렬화 오류가 조용히 무시됨

**문제**: `Close()` 메서드의 `data, _ := json.Marshal(out)`가 직렬화 오류를 무시합니다. JSON 직렬화가 실패하면 `data`가 nil이 되어 `os.WriteFile`이 빈 데이터를 쓰고, **영속화된 데이터가 전부 손실됩니다**.

**수정**: `json.Marshal`의 오류 반환값을 검사하고, 실패 시 즉시 error를 반환합니다.

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

### Bug #2 [심각] `httpval/content_type.go:34` — 빈 AllowList가 모든 Content-Type 허용

**문제**: 조건 `if len(c.Allowed) == 0 || c.Allowed[mt]`는 AllowList가 비어 있을 때 **모든 Content-Type이 허용**됨을 의미합니다. 보안 기본값은 deny-all이어야 합니다.

**수정**: `len(c.Allowed) == 0` 조건을 제거하여, 빈 AllowList는 거부 분기로 진행되게 합니다.

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

### Bug #3 [중간] `protocol/xxe.go:15` — `&[a-z]+;`가 모든 정상 HTML/XML 엔티티 오탐

**문제**: 정규식 `(?i)&[a-z]+;`는 모든 표준 엔티티 참조(`&amp;`, `&lt;`, `&gt;` 등)를 매칭하여, 정상 HTML/XML을 포함한 모든 요청이 XXE 공격으로 오탐됩니다.

**수정**: 매칭 범위를 알려진 악성 프로토콜 접두사로 축소합니다.

```go
// 修复前
regexp.MustCompile(`(?i)&[a-z]+;`),

// 修复后
regexp.MustCompile(`(?i)&(?:xxe|file|http|ftp|gopher|dict|data|expect);`),
```

---

## 3. 발견된 부차적 문제(미수정, 평가 필요)

### 문제 #1: `all` 패키지 테스트 커버리지 없음

`all/all.go`의 `RegisterAll()` 함수에는 테스트가 전혀 없습니다. 등록된 모든 감지기가 정상 호출되는지 검증하는 테스트를 추가해야 합니다.

### 문제 #2: `httpval` 패키지 테스트 추가 완료 ✅(해결됨)

`httpval/httpval_test.go` 추가(테스트 케이스 32개): `BodySize`(7개), `ContentType`(7개), `CSRFOrigin`(8개), `IPBlacklist`(6개), `Method`(3개) 커버. 경계값, 오류 입력, 빈 AllowList deny-all 검증 포함.

### 문제 #3: `data/data_leak.go` 신용카드 번호 정규식이 너무 광범위

`\b(?:\d[ -]*?){13,16}\b`는 13-16자리 숫자 시퀀스를 모두 매칭합니다.

### 문제 #4: `storage/redis/` 서브모듈 불완전

- `go.mod`에 부모 모듈에 대한 의존성 선언 누락
- `go.sum` 파일 누락

### 문제 #5: protocol 패키지와 injection 패키지의 receiver 스타일 불일치

- `injection` 패키지는 포인터 수신자 사용: `func (d *XSS) Name() string`
- `protocol` 패키지는 값 수신자 사용: `func (d CORS) Name() string`

### 문제 #6: `injection/xss.go` — `&#x?[0-9a-f]+;?`가 정상 HTML 숫자 문자 참조를 매칭

---

## 4. 아키텍처 총평

| 항목 | 점수 | 설명 |
|------|------|------|
| 인터페이스 설계 | ★★★★☆ | `Detector` 인터페이스 + `Engine` 오케스트레이션 패턴이 명확 |
| 코드 일관성 | ★★★☆☆ | receiver 스타일이 통일되지 않음 |
| 오류 처리 | ★★★☆☆ | 수정 전 조용한 오류 무시 존재; 수정 후 개선 |
| 테스트 커버리지 | ★★★★☆ | `httpval` 테스트 추가 완료, `all` 패키지 여전히 부족 |
| 보안 기본값 | ★★★☆☆ | ContentType 빈 AllowList 문제 수정됨 |
| 탐지 정확도 | ★★★☆☆ | 일부 정규식에 오탐 위험(xxe 부분 수정됨) |

---

## 5. 권장 우선순위

| 우선순위 | 항목 |
|--------|------|
| ~~P0~~ | ~~`httpval` 패키지 테스트 추가~~ ✅ 완료(테스트 32개, 감지기 5개) |
| P1 | `all` 패키지 테스트 추가 |
| P1 | `storage/redis/` 서브모듈 go.mod 수정 |
| P2 | receiver 스타일을 포인터 수신자로 통일 |
| P2 | 신용카드/XSS 정규식 오탐율 평가 |

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

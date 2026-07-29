# Security-Go 代码审查报告

**日期**：2026-07-29  
**项目**：github.com/bag/security-go  
**审查范围**：42 个 Go 源文件，8 个包（security、all、data、file、httpval、injection、protocol、storage）  

---

## 一、测试结果

```
ok      github.com/bag/security-go       0.012s
?       github.com/bag/security-go/all   [no test files]
ok      github.com/bag/security-go/data  0.015s
ok      github.com/bag/security-go/file  0.013s
?       github.com/bag/security-go/httpval [no test files]
ok      github.com/bag/security-go/injection 0.005s
ok      github.com/bag/security-go/protocol  0.004s
ok      github.com/bag/security-go/storage   0.159s
```

- `go vet ./...` 通过，无警告
- 所有测试通过
- **缺失测试的包**：`all`、`httpval`

---

## 二、已修复的 Bug

### Bug #1 [关键] `storage/file.go:101` — JSON 序列化错误被静默忽略

**问题**：`Close()` 方法中 `data, _ := json.Marshal(out)` 忽略了序列化错误。如果 JSON 序列化失败，`data` 为 nil，`os.WriteFile` 会写入空数据，**导致持久化数据全部丢失**。

**修复**：检查 `json.Marshal` 的错误返回值，失败时立即返回 error。

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

### Bug #2 [关键] `httpval/content_type.go:34` — 空 AllowList 放行所有 Content-Type

**问题**：条件 `if len(c.Allowed) == 0 || c.Allowed[mt]` 意味着当 AllowList 为空时，**所有 Content-Type 都被放行**。安全默认值应为 deny-all。

**修复**：移除 `len(c.Allowed) == 0` 条件，空 AllowList 走到拒绝分支。

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

### Bug #3 [中等] `protocol/xxe.go:15` — `&[a-z]+;` 误匹配所有合法 HTML/XML 实体

**问题**：正则 `(?i)&[a-z]+;` 会匹配所有标准实体引用（`&amp;`、`&lt;`、`&gt;` 等），导致任何包含合法 HTML/XML 的请求都被误报为 XXE 攻击。

**修复**：缩小匹配范围为已知恶意协议前缀。

```go
// 修复前
regexp.MustCompile(`(?i)&[a-z]+;`),

// 修复后
regexp.MustCompile(`(?i)&(?:xxe|file|http|ftp|gopher|dict|data|expect);`),
```

---

## 三、发现的次要问题（未修复，需评估）

### 问题 #1：`all` 包无测试覆盖

`all/all.go` 的 `RegisterAll()` 函数无任何测试。应添加测试验证所有注册的 detector 可正常调用。

### 问题 #2：`httpval` 包完全无测试（零覆盖）

`httpval` 包含 `BodySize`、`ContentType`、`CSRFOrigin`、`IPBlacklist`、`Method` 五个 detector，但没有任何测试文件。关键安全组件缺乏测试覆盖。

### 问题 #3：`data/data_leak.go` 信用卡号正则过于宽泛

`\b(?:\d[ -]*?){13,16}\b` 会匹配任何 13-16 位数字序列。

### 问题 #4：`storage/redis/` 子模块不完整

- `go.mod` 缺少对父模块的依赖声明
- 缺少 `go.sum` 文件

### 问题 #5：protocol 包与 injection 包 receiver 风格不一致

- `injection` 包使用指针接收者：`func (d *XSS) Name() string`
- `protocol` 包使用值接收者：`func (d CORS) Name() string`

### 问题 #6：`injection/xss.go` — `&#x?[0-9a-f]+;?` 会匹配合法 HTML 数字字符引用

---

## 四、架构总评

| 维度 | 评分 | 说明 |
|------|------|------|
| 接口设计 | ★★★★☆ | `Detector` 接口 + `Engine` 编排模式清晰 |
| 代码一致性 | ★★★☆☆ | receiver 风格不统一 |
| 错误处理 | ★★★☆☆ | 修复前存在静默错误吞没；修复后改善 |
| 测试覆盖 | ★★★☆☆ | 核心包覆盖尚可，`httpval`/`all` 无测试 |
| 安全默认值 | ★★★☆☆ | ContentType 空 AllowList 问题已修复 |
| 检测准确性 | ★★★☆☆ | 部分正则有误报风险（xxe 已部分修复） |

---

## 五、建议优先级

| 优先级 | 事项 |
|--------|------|
| P0 | 补写 `httpval` 包测试（当前零覆盖） |
| P1 | 补写 `all` 包测试 |
| P1 | 修复 `storage/redis/` 子模块 go.mod |
| P2 | 统一 receiver 风格为指针接收者 |
| P2 | 评估信用卡/XSS 正则误报率 |

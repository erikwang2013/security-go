# 单元测试报告

- 日期：2026-08-27
- 模块：`github.com/erikwang2013/security-go`（Go 1.24.1）
- 执行方式：`go test ./... -count=1 -race`（主模块）+ `cd storage/redis && go test ./... -count=1 -race`（嵌套模块）

## 覆盖率

| 包 | 语句覆盖率 |
|----|-----------|
| security（根包） | 100.0% |
| all | 100.0% |
| data | 100.0% |
| file | 100.0% |
| httpval | 100.0% |
| injection | 100.0% |
| protocol | 100.0% |
| storage | 85.1% |
| **主模块总计** | **96.2%** |
| storage/redis（嵌套模块） | 94.1% |

storage 包的缺口集中在 `reap` 后台清理协程的 30s ticker 路径（测试不等待 30s），属预期。

详细逐函数覆盖率见 `coverage-summary.txt`，可视化见 `coverage.html`。

## 测试中发现并修复的问题

| # | 文件 | 问题 | 影响 |
|---|------|------|------|
| 1 | injection/xss.go | 全部 20 条 XSS 模式区分大小写 | `<SCRIPT>`、`JavaScript:`、`EVAL(` 等大小写变体可绕过检测 |
| 2 | injection/command.go | 模式 3/6/7 区分大小写 | `| CAT`、`&& WHOAMI`、`; LS` 可绕过（cmd.exe 大小写不敏感，Windows 目标可利用） |
| 3 | injection/ssi.go | 4 条 SSI 模式区分大小写 | `<!--#EXEC cmd=...-->` 大小写变体可绕过 |
| 4 | protocol/request_smuggling.go | `Content-Length:\s*0` 只匹配 CL:0 | 漏掉经典 `Content-Length: 13\r\nTransfer-Encoding: chunked` CL.TE 走私 |
| 5 | file/upload.go | `<?php` 区分大小写 | `<?PHP` 变体可绕过恶意上传检测 |
| 6 | security.go | `DetectRequest(nil)` / nil URL 空指针 panic | 未初始化的 *http.Request 直接崩溃 |
| 7 | storage/file.go | autoSave goroutine 永不停止（Close 后泄漏） | 每个 File 实例泄漏一个常驻 goroutine |
| 8 | httpval/ip_blacklist_test.go | `Block(ip, 3600)` 裸整数被当作 3600 纳秒 | 测试时序依赖，-race 下必挂（测试缺陷，已改为 `time.Hour`） |

## 遗留说明

- `sql.go` 的模式 `(?:--|#|/\*).*$` 会把含 `#` 的普通文本（如 "C#"）误报——安全库"宁误报不漏报"的设计取舍，未改动。
- `nosql.go` 检测不到无引号写法 `{$expr: {...}}`——已知检测盲区，低优先级。
- `dns_rebinding` 的 `Host:\s*\w+$` 会命中任意单词主机、`data_leak` 对 20 位以上连续数字串不命中信用卡号——均为现有行为，测试已固化。

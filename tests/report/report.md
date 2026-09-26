# 单元测试报告

- 日期：2026-09-26
- 模块：`github.com/erikwang2013/security-go`（Go 1.24.1）
- 执行方式：`go test ./... -count=1 -race`（主模块）+ `cd storage/redis && go test ./... -count=1 -race`（嵌套模块）

## 覆盖率

| 包 | 语句覆盖率 |
|----|-----------|
| security（根包） | 100.0% |
| all | 100.0% |
| data | 100.0% |
| file | 100.0% |
| httpval | 99.1% |
| injection | 100.0% |
| pet | 100.0% |
| protocol | 100.0% |
| session | 88.0% |
| storage | 85.6% |
| **主模块总计** | **92.5%** |
| storage/redis（嵌套模块） | 94.1% |

10 个包全部通过，`-race` 无数据竞争。

未覆盖的分支集中在两类，均属预期：

- **后台定时器**——`storage.Memory.reap`、`session.MemoryStore.reap` 的 30s ticker，测试不等待真实时钟。
- **故障回退**——存储返回 error 时的降级路径（`FailOpen` / `FailClosed` 的异常侧），以及各结构体字段「0 值回退默认值」的短分支。

对比上一版（2026-08-27，96.2%）：分母增加了 `pet`（100.0%）与 `session`（88.0%）两个包，`session` 的故障回退分支较多，故总比例下降，不是覆盖退化。

详细逐函数覆盖率见 `coverage-summary.txt`，可视化见 `coverage.html`。

## 本轮（2026-09-26）变更

- 新增 `pet` 包（项目宠物：内嵌 SVG + 启动横幅 + 调试路由），3 个导出函数全部 100%。
- 根包 `security` 自身测试补齐两处此前为 0 与 83.3% 的导出面：`FirstMatch` 的契约测试，以及 `DetectRequest` 的 URL 解码重扫分支。两处此前由各检测器包的测试间接覆盖，但根包自身从未直接调用；`FirstMatch` 现有 36 处调用点，是全部正则类检测器的公共底座。
- 重扫测试第一次写成用 query 参数触发，**证伪时发现是空测试**：`URL.Query().Encode()` 会把 `%61ttack` 还原成明文 `attack`，第一遍就命中，删掉重扫分支测试照样绿。改用 header 作为向量（header 逐字传入不解码）后，删掉重扫分支测试即失败。

## 测试中发现并修复的问题（2026-08-27 轮次）

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

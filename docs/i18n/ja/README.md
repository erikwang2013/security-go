# Security Go — 攻撃検出ライブラリ

[简体中文](../../../README.md) · [English](../../../README-EN.md)

Go 言語で書かれた攻撃検出パッケージ。**32 個の検出器**、**5 大攻撃カテゴリ**、**3 種類のプラグ可能なストレージバックエンド**をカバーします。統一インターフェース + レジストリパターンを採用した純粋な検出ライブラリで、あらゆる Go HTTP フレームワークに適合します。

## 設計思想

### コア原則

- **ゼロ依存検出** — すべての検出器は Go 標準ライブラリの `regexp` のみを使用し、外部依存なし
- **統一インターフェース** — 各検出器は `Detector` インターフェース（`Name()` + `Detect()`）を実装し、`Engine` レジストリで一元管理
- **プリコンパイル済み正規表現** — すべてのパターンは `var` の初期化時にコンパイルされ、実行時オーバーヘッドはゼロ
- **オンデマンド設定** — インジェクション/プロトコル/データ/ファイル検出器はプラグイン方式で即使用可能。HTTP バリデータはアプリ側でのカスタム設定が必要

### 設計アーキテクチャ

```
                         ┌───────────────────────────────┐
                         │        security.Engine         │
                         │  ┌─────────────────────────┐  │
                         │  │    Detector Registry     │  │
                         │  │   map[string]Detector    │  │
                         │  └─────────────────────────┘  │
                         │                               │
                         │  Detect(name, input)          │
                         │  DetectAll(input)             │
                         │  DetectRequest(*http.Request) │
                         └──────────────┬────────────────┘
                                        │
          ┌─────────────────┬───────────┴───────────┬─────────────────┐
          │                 │                       │                 │
   ┌──────▼──────┐   ┌──────▼──────┐   ┌────────────▼────────┐   ┌───▼───────────┐
   │  injection  │   │  protocol   │   │        data         │   │     file      │
   │   (10 个)   │   │   (9 个)    │   │       (5 个)        │   │    (3 个)     │
   │             │   │             │   │                     │   │               │
   │  xss, sql,  │   │  ssrf, xxe, │   │  deser, csv,        │   │  traversal,   │
   │  command,   │   │  header,    │   │  mail, jwt,         │   │  upload,      │
   │  nosql,     │   │  host,      │   │  proto_poll         │   │  data_leak    │
   │  ldap,      │   │  smuggling, │   │                     │   │               │
   │  xpath,     │   │  redirect,  │   │                     │   │               │
   │  jndi, ssi, │   │  cors, ws,  │   │                     │   │               │
   │  graphql,   │   │  dns_rebind │   │                     │   │               │
   │  ssti       │   │             │   │                     │   │               │
   └─────────────┘   └─────────────┘   └─────────────────────┘   └───────────────┘
                                                                          │
          ┌───────────────────────────────────────────────────────────────┤
          │                                                               │
   ┌──────▼──────────┐                                         ┌──────────▼──────────┐
   │     httpval     │                                         │       storage       │
   │     (5 个)      │                                         │  ┌──────────────┐   │
   │                 │                                         │  │   Backend    │   │
   │  method, size,  │                                         │  │   interface  │   │
   │  type, csrf,    │                                         │  └──┬───┬───┬───┘   │
   │  ip_blacklist   │◄────── 使用 storage.Backend ──────────►│  Memory File Redis │
   │  (需配置参数)    │                                         │                    │
   └─────────────────┘                                         └────────────────────┘
```

### データフロー

```
HTTP Request
     │
     ▼
┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│ collectInputs│────▶│  DetectAll()    │────▶│  []*Result   │
│ URL, Query,  │     │  逐个检测器调用   │     │  聚合结果     │
│ Headers,     │     │  Detect(input)  │     │              │
│ Cookies      │     └─────────────────┘     └──────────────┘
└──────────────┘
```

### 深刻度レベル

| レベル | 説明 | 典型的なシナリオ |
|------|------|---------|
| `SeverityLow` | 低リスク | 不正な HTTP メソッド、Content-Type の不一致 |
| `SeverityMedium` | 中リスク | CORS 設定の問題、開放リダイレクト、GraphQL イントロスペクション |
| `SeverityHigh` | 高リスク | XSS、SQL インジェクション、SSRF、パストラバーサル |
| `SeverityCritical` | 重大 | コマンドインジェクション、JNDI、SSTI、XXE、データ漏洩 |

## 実装機能

### インジェクション系攻撃 (10)

| 検出器 | 検出パターン |
|--------|---------|
| **XSS** | `<script>`、`on[a-z]+=` イベントハンドラ、`javascript:` 疑似プロトコル、SVG/CSS インジェクション、`eval()`、`document.cookie` |
| **SQL インジェクション** | `UNION SELECT`（`/**/` バイパス含む）、`sleep/benchmark/pg_sleep`、ブールベース盲注、`information_schema` 列挙、`xp_cmdshell` |
| **コマンドインジェクション** | バッククォート、`$()`、パイプ、`/dev/tcp`、PHP `system/exec/shell_exec`、チェーン実行 `&&` `;` `\|\|` |
| **NoSQL インジェクション** | MongoDB `$ne` `$gt` `$regex` `$where` 演算子、`$func`、JSON キーインジェクション |
| **LDAP インジェクション** | フィルタ演算子 `(\|(&(!`、`objectClass=*`、URL エンコードバイパス |
| **XPATH インジェクション** | ブールバイパス `' or '1'='1`、`string-length()`、`count()` |
| **JNDI/Log4Shell** | `${jndi:ldap://`、`${lower:j}` 難読化、`${env:}` 環境変数、`ldap/rmi/dns` プロトコル |
| **SSI インジェクション** | `<!--#exec cmd=`、`<!--#include file=`、`<!--#echo var=` |
| **GraphQL インジェクション** | `__schema`/`__type` イントロスペクション、深いネスト DoS（5 層以上）、`mutation` 検出 |
| **SSTI** | Jinja2 `{{}}`、FreeMarker `${}`、ERB `<% %>`、Python MRO 探索、`config/self` アクセス |

### プロトコル・リクエスト攻撃 (9)

| 検出器 | 検出パターン |
|--------|---------|
| **SSRF** | 内部 IP（127/10/172.16/192.168）、`169.254.169.254`、IPv6 loopback、`gopher/dict/file/ftp` プロトコル |
| **XXE** | `<!ENTITY SYSTEM/PUBLIC`、パラメータエンティティ `%entity;`、DOCTYPE 宣言 |
| **HTTP ヘッダーインジェクション** | CRLF `%0d%0a` / `\r\n`、Set-Cookie/Location/Content-Length インジェクション |
| **Host ヘッダー攻撃** | CRLF Host インジェクション、`X-Forwarded-Host`、`X-Original-URL` ポイズニング |
| **リクエストスマグリング** | Transfer-Encoding/Content-Length の不一致、二重 TE ヘッダー、`\x0b` 折り返しヘッダー難読化 |
| **開放リダイレクト** | `//evil.com` プロトコル相対 URL、`javascript:/data:` 疑似プロトコル |
| **CORS バイパス** | `Origin: null`、`Access-Control-Allow-*` ヘッダーインジェクション |
| **WebSocket ハイジャック** | Upgrade ヘッダーインジェクション、null Origin バイパス、`ws://` URL |
| **DNS リバインディング** | Host ヘッダー内の内部 IP、localhost、TLD なしの短いホスト名 |

### HTTP プロトコル層バリデーション (5)

| 検出器 | 説明 |
|--------|------|
| **HTTP メソッド** | GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH のみ許可、それ以外は警告 |
| **リクエストボディサイズ** | 上限（デフォルト 10MB）を超えると警告 |
| **Content-Type** | 設定済みの MIME タイプホワイトリストのみ許可 |
| **CSRF Origin** | クロスオリジンリクエストの Origin と Host の一致を検出、追加ホワイトリスト対応 |
| **IP ブラックリスト** | ウィンドウ時間内に N 回攻撃すると自動ブロック（デフォルト 5回/60s → 15分ブロック）、File/Redis/Memory ストレージ対応 |

### データ・シリアライズ攻撃 (5)

| 検出器 | 検出パターン |
|--------|---------|
| **PHP デシリアライゼーション** | `O:数字:` / `C:数字:` シリアライズオブジェクト、`unserialize()`、マジックメソッド（`__wakeup`/`__destruct`） |
| **CSV インジェクション** | `=cmd\|`、`@SUM(`、`+`/`-` 数式プレフィックス、`HYPERLINK`/`DDE` |
| **メールヘッダーインジェクション** | Bcc/Cc/From/To インジェクション、MIME multipart、boundary パラメータ |
| **JWT 攻撃** | `alg: none` バイパス、`kid` パストラバーサル、空シグネチャ検出（構造デコード解析） |
| **プロトタイプ汚染** | `__proto__`/`constructor` キー、`__defineGetter__`/`__defineSetter__` |

### ファイル・機密データ (3)

| 検出器 | 検出パターン |
|--------|---------|
| **パストラバーサル** | `../`、`..\\`、`php://filter`/`php://input`、null バイト、URL エンコードバイパス、`/etc/passwd` |
| **悪意のあるアップロード** | 拡張子ホワイトリスト（15 種）+ PHP タグ `<?php`/`<?=` 内容スキャン |
| **データ漏洩** | クレジットカード番号、AWS Access Key、秘密鍵 `-----BEGIN`、データベース接続文字列、API トークン、JWT シークレット、GitHub PAT |

### ストレージバックエンド (3)

| バックエンド | 説明 |
|------|------|
| **Memory** | `sync.Mutex` + map、30 秒ごとに期限切れエントリを自動クリーンアップ |
| **File** | JSON ファイル永続化、Close 時に flush |
| **Redis** | 独立サブモジュール、Pipeline Incr + TTL、`go-redis/v9` が必要 |

## 使用説明

### インストール

```bash
go get github.com/erikwang2013/security-go
```

### クイックスタート

```go
package main

import (
    "fmt"
    "github.com/erikwang2013/security-go"
    "github.com/erikwang2013/security-go/all"
)

func main() {
    e := security.NewEngine()
    all.RegisterAll(e) // 一键注册 27 个零配置检测器

    // 单个检测
    r := e.Detect("xss", "<script>alert(1)</script>")
    fmt.Printf("检测到: %v, 严重程度: %d\n", r.Detected, r.Severity)

    // 全量检测
    for _, r := range e.DetectAll("' OR '1'='1") {
        fmt.Printf("[%s] %s\n", r.Name, r.Message)
    }
}
```

### HTTP リクエスト検出

```go
func handler(w http.ResponseWriter, r *http.Request) {
    e := security.NewEngine()
    all.RegisterAll(e)

    for _, result := range e.DetectRequest(r) {
        if result.Detected {
            log.Printf("攻击检测: [%s] %s", result.Name, result.Message)
        }
    }
}
```

### HTTP バリデータ設定

```go
// 方法校验
e.Register(&httpval.Method{})

// 请求体大小限制
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type 白名单
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF Origin 检查
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP 黑名单（自动封禁：5次/60s → 封禁15分钟）
mem := storage.NewMemory()
defer mem.Close()
bl := httpval.NewIPBlacklist(mem)
e.Register(bl)

// 攻击发生时记录
blocked, _ := bl.RecordAttack(clientIP)
```

### カスタム検出器

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "检测到恶意内容",
    }
}

e.Register(&MyDetector{})
```

### 関連ドキュメント

- [API インターフェースドキュメント](api.md) — コア型、Detector/Engine インターフェース、ストレージバックエンドインターフェース、HTTP バリデータ
- [設計仕様](specs/2026-07-29-attack-detection-design.md) — パッケージ構造、検出器カタログ
- [実装計画](plans/2026-07-29-attack-detection-plan.md) — 段階的タスク計画と実装の乖離の対照表
- [コードレビュー報告](reports/2026-07-29-code-review-report.md) — バグ修正、テストカバレッジ、アーキテクチャ評価

---

## 多言語ドキュメント

| 言語 | ドキュメント |
|------|------|
| 简体中文 | [README.md](../../../README.md) |
| English | [README-EN.md](../../../README-EN.md) · [docs/i18n/en/README.md](../en/README.md) |
| 한국어 | [docs/i18n/ko/README.md](../ko/README.md) |
| Русский | [docs/i18n/ru/README.md](../ru/README.md) |
| Deutsch | [docs/i18n/de/README.md](../de/README.md) |
| Français | [docs/i18n/fr/README.md](../fr/README.md) |
| Español | [docs/i18n/es/README.md](../es/README.md) |
| Português | [docs/i18n/pt/README.md](../pt/README.md) |
| हिन्दी | [docs/i18n/hi/README.md](../hi/README.md) |
| العربية | [docs/i18n/ar/README.md](../ar/README.md) |
| বাংলা | [docs/i18n/bn/README.md](../bn/README.md) |
| Bahasa Indonesia | [docs/i18n/id/README.md](../id/README.md) |
| 日本語 | [README.md](README.md) |

インデックス: [docs/i18n/README.md](../README.md)

---

## 寄付のお願い

このプロジェクトがお役に立ったなら、ぜひ支援をお願いします:

| 方法 | QR コード |
|------|--------|
| 支付宝 | ![支付宝](images/alipay.png) |
| 微信支付 | ![微信支付](images/weixinpay.png) |

### 海外送金での支援（銀行振込）

**受取人情報**

- 受取人氏名：WANG KEXUN
- 受取口座番号：881015918251

**受取銀行（ZA Bank）**

- SWIFT Code：`AABLHKHHXXX`
- 銀行名：ZA Bank Limited
- 銀行番号：387
- 銀行住所：Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

**越境送金の代理銀行（必要な場合）**

> ご注意：これは越境送金の代理銀行（中継銀行）の情報であり、受取銀行の情報ではありません。ご利用の送金銀行に、代理銀行の情報が必要かどうかをお問い合わせください。

- 香港ドル・人民元・米ドルを送金する場合の代理銀行は Citibank です：
  - 銀行名：Citibank N.A. Hong Kong
  - SWIFT Code：`CITIHKHXXXX`
  - 銀行番号：006
  - 支店名：Hong Kong Branch
  - 支店番号：391
  - 銀行住所：Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong
- その他の通貨を送金する場合の代理銀行は BNY Mellon です：
  - 銀行名：THE BANK OF NEW YORK MELLON
  - SWIFT Code：`IRVTUS3NXXX`
  - 銀行住所：THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## English

完全な英語ドキュメントは [README-EN.md](../../../README-EN.md) を参照してください。

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

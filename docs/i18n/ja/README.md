# Security Go — 攻撃検出ライブラリ

[简体中文](../../../README.md) · [English](../../../README-EN.md) · [API インターフェースドキュメント](api.md)

Go 言語で書かれた攻撃検出パッケージ。**36 個の検出器**、**6 大攻撃カテゴリ**、**3 種類のプラグ可能なストレージバックエンド**をカバーします。統一インターフェース + レジストリパターンを採用した純粋な検出ライブラリで、あらゆる Go HTTP フレームワークに適合します。

<p align="center">
  <img src="../../../pet/pet.svg" width="190" alt="Sentinel Gopher">
  <br>
  <sub>プロジェクトのマスコット Sentinel Gopher（哨兵鼠）— 盾を構えて見張りに立つ Go ゴーファー。盾の 36 は検出器の数、虫めがねはリクエストごとのスキャンを表します。</sub>
</p>

[設計アーキテクチャ](#設計アーキテクチャ) · [機能](#実装機能) · [ライフサイクル](#ライフサイクル) · [プロジェクト構成](#プロジェクト構成) · [マスコット](#マスコット)

## 設計思想

### コア原則

- **ゼロ依存検出** — すべての検出器は Go 標準ライブラリの `regexp` のみを使用し、外部依存なし
- **統一インターフェース** — 各検出器は `Detector` インターフェース（`Name()` + `Detect()`）を実装し、`Engine` レジストリで一元管理
- **プリコンパイル済み正規表現** — すべてのパターンは `var` の初期化時にコンパイルされ、実行時オーバーヘッドはゼロ
- **オンデマンド設定** — インジェクション/プロトコル/データ/ファイル検出器はプラグイン方式で即使用可能。HTTP バリデータとセッションセキュリティ検出はアプリ側でのカスタム設定が必要

### 設計アーキテクチャ

![設計アーキテクチャ](../../../docs/images/architecture.svg)

> `session` パッケージは `Engine` に登録しません：セッション検証は完全な `*http.Request`（token、クライアント IP、User-Agent）を読む必要があり、
> またアプリ側のストレージと鍵を用意する必要があるため、ミドルウェアとして直接呼び出します。以下「セッションセキュリティ設定」を参照してください。

### ライフサイクル

リクエストの全体的な流れ — 受信から検出、そして段階的な処理まで（IP ブロックのサイクルと URL デコード後の再スキャンを含む）。あわせて、セッションがバインドから失効に至るまでの道のり:

![ライフサイクル](../../../docs/images/lifecycle.svg)

### 深刻度レベル

| レベル | 説明 | 典型的なシナリオ |
|------|------|---------|
| `SeverityLow` | 低リスク | 不正な HTTP メソッド、Content-Type の不一致 |
| `SeverityMedium` | 中リスク | 弱いシグナル: CORS 設定の問題、開放リダイレクト、GraphQL イントロスペクション、および各検出器が意図的に分離した文脈なしパターン（`../`、`on…=`、`javascript:`、`sleep(`、`sqlite_master`、バッククォート、`{#…#}`、`__proto__:`、PHP マジックメソッド名）— チュートリアルや通常のコンテンツによく現れます |
| `SeverityHigh` | 高リスク | 強いシグナル: XSS、SQL インジェクション、SSRF、パストラバーサル、セッション異常 |
| `SeverityCritical` | 重大 | 強いシグナル: コマンドインジェクション、JNDI、SSTI、XXE、データ漏洩、デシリアライゼーション（PHP シリアライズオブジェクト / pickle / Java / .NET） |

## 実装機能

### 機能概要

![機能設計](../../../docs/images/features.svg)

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

### HTTP プロトコル層バリデーション (7)
| **JSON ネスト深度** | `json.Decoder` によるストリーム走査。ネスト深度または要素数が上限を超えると JSON ボムとして検出（既定深度 32）。不正・切り詰められた JSON では決して発報しません |
| **Cookie 属性** | `Set-Cookie` に `Secure`/`HttpOnly`/`SameSite` が無い、値が長すぎる、または空の場合を検出。欠落属性は 1 件の結果にまとめます |

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
| **デシリアライゼーション** | `O:数字:` / `C:数字:` シリアライズオブジェクト、`unserialize()`、マジックメソッド（`__wakeup`/`__destruct`）。PHP / pickle / Java / .NET のペイロードに対応 |
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

### セッションセキュリティ (2)

| 検出器 | 検出パターン |
|--------|---------|
| **セッションガード** (`session_guard`) | セッション確立時のクライアントに token をバインドし、リクエストごとに比較：User-Agent またはデバイスフィンガープリントの変化を**クライアントハイジャック**（Critical）と判定。クライアント IP が別サブネットや別国家に落ちた場合を**遠隔地ログイン**（High/Critical）と判定。`Observe()` はログイン時に過去のサブネットと比較し、新しいサブネットが現れれば即座に警告。セッションはスライディングで延長され、`Revoke()` で即座に無効化可能。`RecordFailure()` が失敗回数を数え、ウィンドウ内でしきい値に達するとトークンをロックし、`Check()` が `token_locked` を返し、ログイン成功時に `ClearFailures()` がカウントを戻します。`CheckLogin()` はさらにクレデンシャルスタッフィングを検出し（1 クライアントが多数の異なる識別子に失敗すると `credential_stuffing`）、ロックは繰り返しごとに倍増（上限 24 時間）します |
| **データ改ざん** (`data_tamper`) | リクエストパラメータに HMAC-SHA256 署名（`タイムスタンプ.nonce.署名`）を行い、パラメータの改変、鍵の不一致、タイムスタンプのずれ、署名リプレイ（nonce カウンター）を識別 |

### ストレージバックエンド (3)

| バックエンド | 説明 |
|------|------|
| **Memory** | `sync.Mutex` + map、30 秒ごとに期限切れエントリを自動クリーンアップ |
| **File** | JSON ファイル永続化、Close 時に flush |
| **Redis** | 独立サブモジュール、Pipeline Incr + TTL、`go-redis/v9` が必要 |

## プロジェクト構成

```
security-go/
├── security.go            # コア: Result / Severity / Detector インターフェース / Engine レジストリ
├── injection/             # インジェクション検出器 (10): xss, sql, command, nosql, ldap,
│                          #   xpath, jndi, ssi, graphql, ssti
├── protocol/              # プロトコル・リクエスト検出器 (9): ssrf, xxe, header, host,
│                          #   smuggling, redirect, cors, websocket, dns_rebinding
├── data/                  # データ・シリアライズ検出器 (5): deserialization, csv,
│                          #   mail, jwt, prototype_pollution
├── file/                  # ファイル・機密データ検出器 (3): path_traversal,
│                          #   upload, data_leak
├── httpval/               # HTTP プロトコルバリデータ (7)、いずれもアプリ側の設定が必要
├── session/               # セッションセキュリティ (2): session_guard, data_tamper
│                          #   Engine を経由せずミドルウェアとして直接使用
├── storage/               # ストレージバックエンド
│   ├── storage.go         #   Backend インターフェース: Incr / Get / Block / IsBlocked / Close
│   ├── memory.go          #   Memory: Mutex + map、30 秒ごとにバックグラウンドで削除
│   ├── file.go            #   File: JSON 永続化、Close 時にフラッシュ
│   └── redis/             #   Redis: 独立サブモジュール、独自の go.mod
├── all/                   # 27 個のゼロ設定検出器を 1 回の呼び出しで登録
├── pet/                   # プロジェクトのマスコット: 埋め込み SVG + 起動バナー
├── docs/
│   ├── api.md             # API リファレンス
│   ├── images/            # アーキテクチャ / 機能 / ライフサイクル の SVG
│   ├── i18n/              # 翻訳ドキュメント (12 言語)
│   └── superpowers/       # 設計仕様、実装計画、コードレビューレポート
└── tests/                 # カバレッジレポート
```

各検出器パッケージは `xxx.go` と `xxx_test.go` を対にして持ち、`all` には回帰テストも含まれます。

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
    all.RegisterAll(e) // 27 個のゼロ設定検出器をまとめて登録

    // 単一検出
    r := e.Detect("xss", "<script>alert(1)</script>")
    fmt.Printf("検出: %v, 深刻度: %d\n", r.Detected, r.Severity)

    // 全量検出
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
            log.Printf("攻撃検出: [%s] %s", result.Name, result.Message)
        }
    }
}
```

### HTTP バリデータ設定

```go
// メソッド検証
e.Register(&httpval.Method{})

// リクエストボディサイズ制限
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type ホワイトリスト
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF Origin チェック
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP ブラックリスト（自動ブロック: 5 回/60s → 15 分ブロック）
mem := storage.NewMemory()
defer mem.Close()
bl := httpval.NewIPBlacklist(mem)
e.Register(bl)

// 攻撃発生時に記録
blocked, _ := bl.RecordAttack(clientIP)
```

### セッションセキュリティ設定

`session` パッケージは `Engine` を経由せず、ミドルウェアとして直接使用します。ストレージはアプリ側で用意する必要があります（デフォルトでメモリ実装を提供、Redis などに差し替え可能）：

```go
import "github.com/erikwang2013/security-go/session"

st := session.NewMemoryStore()
defer st.Close()

tr := session.NewTracker(st)
tr.CountryOf = geo.Lookup // 任意: クロスカントリーログインを識別するため GeoIP を接続

// ログイン成功後にセッションをバインド（token はあなたのログインフローで生成）
// 遠隔地ログイン検出: そのユーザーの過去のサブネットと比較し、新しいサブネットが現れれば警告
if res := tr.Observe("user-1", r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
if err := tr.Issue(token, r); err != nil {      // token をバインド → IP サブネット / UA / デバイスフィンガープリント
    http.Error(w, "session error", http.StatusInternalServerError)
    return
}

// 保護ルート: ハイジャックまたは遠隔地ログインに該当したら直接 401 を返す
mux.Handle("/api/", tr.Guard(apiHandler))

// または検出のみ行い、対処は自分で判断する
if res := tr.Check(r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}

// ログアウト
tr.Revoke(token)
```

データ改ざん検出：クライアントとサーバーが共有鍵を持ち、クライアントがパラメータに署名し、サーバーが再計算して検証します：

```go
signer := session.NewSigner(secret, storage.NewMemory()) // 2 番目の引数は署名リプレイを遮断する（nil 可）

sig, _ := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // クライアント: パラメータと一緒に送信

if res := signer.Verify(map[string]string{"amount": "100", "to": "bob"}, sig); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
```

> `TrustProxyHeaders` はデフォルトで無効：`X-Forwarded-For` / `X-Real-IP` はクライアントが制御できるため、自前のリバースプロキシ配下でのみ有効にしてください。
> `FailClosed` はデフォルトで無効（ストレージ障害時は通過、`IPBlacklist` と同様）。セッションに敏感な業務では有効化を推奨します。

### カスタム検出器

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "悪意のあるコンテンツを検出",
    }
}

e.Register(&MyDetector{})
```

### マスコット

`pet` パッケージはコンパイル時に `go:embed` で Sentinel Gopher を SVG として埋め込みます — 実行時のファイル依存も、サードパーティ依存の追加もありません:

```go
import "github.com/erikwang2013/security-go/pet"

log.Println(pet.Banner())              // 起動バナー: ターミナル向けのプレーンテキスト
http.Handle("/pet.svg", pet.Handler()) // デバッグループ: image/svg+xml として配信、1 日キャッシュ
svg := pet.SVG()                       // または生の SVG バイトを取得
```

### 関連ドキュメント

- [API インターフェースドキュメント](api.md) — コア型、Detector/Engine インターフェース、ストレージバックエンドインターフェース、HTTP バリデータ
- [設計仕様](specs/2026-07-29-attack-detection-design.md) — パッケージ構造、検出器カタログ
- [実装計画](plans/2026-07-29-attack-detection-plan.md) — 段階的タスク計画と実装の乖離の対照表
- [コードレビュー報告](reports/2026-07-29-code-review-report.md) — バグ修正、テストカバレッジ、アーキテクチャ評価
- [コードレビュー報告 v2](reports/2026-07-29-code-review-report-v2.md) — 二回目のレビュー: 4 件の問題を修正、テストファイル 18 個を追加

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
| Alipay | ![Alipay](images/alipay.png) |
| WeChat Pay | ![WeChat Pay](images/weixinpay.png) |

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

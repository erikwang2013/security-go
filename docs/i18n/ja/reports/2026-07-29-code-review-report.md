# Security-Go コードレビュー報告

**日付**: 2026-07-29  
**プロジェクト**: github.com/erikwang2013/security-go  
**レビュー範囲**: Go ソースファイル 42 個、8 パッケージ（security、all、data、file、httpval、injection、protocol、storage）

---

## 一、テスト結果

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

- `go vet ./...` 通過、警告なし
- すべてのテストが通過
- **テストが不足しているパッケージ**: `all`（残るはこれのみ）

---

## 二、修正済みのバグ

### Bug #1 [重大] `storage/file.go:101` — JSON シリアライズエラーが黙って無視されていた

**問題**: `Close()` メソッド内の `data, _ := json.Marshal(out)` がシリアライズエラーを無視していました。JSON シリアライズに失敗すると `data` は nil となり、`os.WriteFile` が空のデータを書き込むため、**永続化データがすべて失われます**。

**修正**: `json.Marshal` のエラー戻り値を検査し、失敗時は即座に error を返すようにしました。

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

### Bug #2 [重大] `httpval/content_type.go:34` — 空の AllowList がすべての Content-Type を許可

**問題**: `if len(c.Allowed) == 0 || c.Allowed[mt]` という条件は、AllowList が空の場合に**すべての Content-Type が許可される**ことを意味します。セキュリティ上のデフォルトは deny-all であるべきです。

**修正**: `len(c.Allowed) == 0` の条件を削除し、空の AllowList は拒否ブランチに進むようにしました。

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

### Bug #3 [中程度] `protocol/xxe.go:15` — `&[a-z]+;` がすべての正当な HTML/XML エンティティを誤検出

**問題**: 正規表現 `(?i)&[a-z]+;` はすべての標準エンティティ参照（`&amp;`、`&lt;`、`&gt;` など）にマッチするため、正当な HTML/XML を含むリクエストがすべて XXE 攻撃として誤検出されていました。

**修正**: マッチ範囲を既知の悪意あるプロトコルプレフィックスに絞り込みました。

```go
// 修复前
regexp.MustCompile(`(?i)&[a-z]+;`),

// 修复后
regexp.MustCompile(`(?i)&(?:xxe|file|http|ftp|gopher|dict|data|expect);`),
```

---

## 三、発見された軽微な問題（未修正・要評価）

### 問題 #1: `all` パッケージにテストカバレッジなし

`all/all.go` の `RegisterAll()` 関数にはテストがありません。登録されたすべての検出器が正常に呼び出せることを検証するテストを追加すべきです。

### 問題 #2: `httpval` パッケージのテスト追加 ✅（解決済み）

`httpval/httpval_test.go`（32 テストケース）を追加済み。`BodySize`（7 テスト）、`ContentType`（7 テスト）、`CSRFOrigin`（8 テスト）、`IPBlacklist`（6 テスト）、`Method`（3 テスト）をカバー。境界値、エラー入力、空 AllowList の deny-all 検証を含みます。

### 問題 #3: `data/data_leak.go` のクレジットカード正規表現が広すぎる

`\b(?:\d[ -]*?){13,16}\b` は任意の 13〜16 桁の数字列にマッチします。

### 問題 #4: `storage/redis/` サブモジュールが不完全

- `go.mod` に親モジュールへの依存宣言がない
- `go.sum` ファイルがない

### 問題 #5: protocol パッケージと injection パッケージの receiver スタイルが不統一

- `injection` パッケージはポインタレシーバ: `func (d *XSS) Name() string`
- `protocol` パッケージは値レシーバ: `func (d CORS) Name() string`

### 問題 #6: `injection/xss.go` — `&#x?[0-9a-f]+;?` が正当な HTML 数字文字参照にマッチする

---

## 四、アーキテクチャ総評

| 評価軸 | 評価 | 説明 |
|------|------|------|
| インターフェース設計 | ★★★★☆ | `Detector` インターフェース + `Engine` オーケストレーションパターンが明確 |
| コードの一貫性 | ★★★☆☆ | receiver スタイルが不統一 |
| エラー処理 | ★★★☆☆ | 修正前はエラーが黙って無視されていた。修正後に改善 |
| テストカバレッジ | ★★★★☆ | `httpval` にはテスト追加済み、`all` パッケージは依然不足 |
| セキュリティデフォルト | ★★★☆☆ | ContentType の空 AllowList 問題は修正済み |
| 検出精度 | ★★★☆☆ | 一部の正規表現に誤検出リスク（xxe は部分的に修正済み） |

---

## 五、推奨優先度

| 優先度 | 事項 |
|--------|------|
| ~~P0~~ | ~~`httpval` パッケージのテスト追加~~ ✅ 完了済み（32 テスト、5 検出器） |
| P1 | `all` パッケージのテスト追加 |
| P1 | `storage/redis/` サブモジュールの go.mod 修正 |
| P2 | receiver スタイルをポインタレシーバに統一 |
| P2 | クレジットカード/XSS 正規表現の誤検出率を評価 |

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

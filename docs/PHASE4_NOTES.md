# Phase 4 Implementation Notes

## フェーズ4: TCP コネクション切断 (4ウェイハンドシェイク)

### 実装された機能

1. **FourWayHandshake構造体**
   - TCP接続の切断処理を管理
   - アクティブクローズと受動クローズの両方をサポート

2. **主要メソッド**
   - `Close()`: アクティブクローズを開始（FIN送信）
   - `HandleFin()`: 受信したFINパケットの処理
   - `HandleFinAck()`: FINに対するACKの処理
   - `CloseFromCloseWait()`: CLOSE_WAIT状態からの最終クローズ

3. **サポートする状態遷移**
   - ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT
   - ESTABLISHED → CLOSE_WAIT → LAST_ACK → CLOSED
   - ESTABLISHED → FIN_WAIT_1 → CLOSING → TIME_WAIT (同時クローズ)

### 特徴

- **学習目的に特化**: シンプルで理解しやすい実装
- **RFC準拠**: TCP RFC 793に基づく正統な4ウェイハンドシェイク
- **包括的テスト**: アクティブクローズ、同時クローズ、エラーケースをカバー
- **デモプログラム**: 視覚的に動作を確認可能

### デモの実行

```bash
# 4ウェイハンドシェイクのデモ
go run examples/connection_close_demo.go

# すべてのテストを実行
go test ./... -v
```

### 実装のポイント

1. **シーケンス番号管理**: FINパケットもシーケンス番号を1つ消費
2. **状態管理**: RFC準拠の正確な状態遷移
3. **エラーハンドリング**: 無効な状態からの操作を適切に検出
4. **同時クローズ**: 両方の端点が同時にクローズする場合の処理

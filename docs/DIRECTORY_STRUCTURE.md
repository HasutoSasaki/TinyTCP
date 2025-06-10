# ディレクトリ構造

```
tinytcp/
├── cmd/                    # メインアプリケーション（実行可能ファイル）
│   ├── tinytcp-server/     # テスト用TCPサーバー
│   └── tinytcp-client/     # テスト用TCPクライアント
├── internal/               # プライベートライブラリコード
│   ├── tcp/               # TCP プロトコル実装
│   ├── socket/            # ソケット API
│   └── packet/            # パケット処理（ヘッダ構造など）
├── pkg/                   # 外部ライブラリで使用可能なライブラリコード
│   └── tinytcp/           # 公開 API
├── test/                  # 追加のテストアプリとテストデータ
├── docs/                  # ドキュメント
├── examples/              # サンプルコード
├── go.mod                 # Go モジュール定義
├── go.sum                 # Go モジュール依存関係のチェックサム
├── README.md              # プロジェクト概要
├── DESIGN.md              # 設計文書
├── PLAN.md                # 開発計画
└── Makefile               # ビルド・テスト用タスク（今後作成予定）
```

## 各ディレクトリの役割

### `/cmd`
- アプリケーションのメインパッケージ
- `tinytcp-server`: テスト用のTCPサーバー実装
- `tinytcp-client`: テスト用のTCPクライアント実装

### `/internal`
- プライベートなアプリケーションとライブラリのコード
- 他のアプリケーションやライブラリからインポートされたくないコード
- `/internal/tcp`: TCP プロトコルのコア実装
- `/internal/socket`: ソケット API の実装
- `/internal/packet`: パケット構造とヘッダ処理

### `/pkg`
- 外部アプリケーションで使用されることを意図したライブラリコード
- `/pkg/tinytcp`: 公開 API とインターフェース

### その他
- `/test`: 追加のテストアプリケーションとテストデータ
- `/docs`: 詳細なドキュメント
- `/examples`: 使用例とサンプルコード

この構造は以下の Go プロジェクトレイアウト標準に従っています：
- [Standard Go Project Layout](https://github.com/golang-standards/project-layout)
- Kubernetes, Docker, Prometheus などの大規模 OSS プロジェクトで採用されているパターン

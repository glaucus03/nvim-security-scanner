# nvim-security-scanner

Neovimプラグインのセキュリティリスクを検出・分析するためのツールです。多数のプラグインを利用するNeovimユーザーが、プラグインコード内の潜在的なセキュリティリスクを特定し、安全に管理できるようにすることを目的としています。

## 機能

- **静的解析**: プラグインのLuaコードを解析し、危険なパターンを検出
- **リスク評価**: 検出された各パターンに対してhigh/medium/lowのリスクレベルを評価
- **プラグインマネージャー統合**: lazy.nvim/packer.nvim統合でプラグイン更新前にセキュリティチェック
- **詳細レポート**: 検出されたリスクの詳細を表示

## インストール

### [lazy.nvim](https://github.com/folke/lazy.nvim)

```lua
{
  "glaucus03/nvim-security-scanner",
  config = function()
    require("nvim-security-scanner").setup({
      -- オプション設定
    })
  end,
}
```

### [packer.nvim](https://github.com/wbthomason/packer.nvim)

```lua
use {
  "glaucus03/nvim-security-scanner",
  config = function()
    require("nvim-security-scanner").setup({
      -- オプション設定
    })
  end
}
```

## 設定

```lua
require("nvim-security-scanner").setup({
  -- プラグインを有効化
  enabled = true,
  
  -- リスク閾値 (low, medium, high)
  risk_threshold = "medium",
  
  -- 起動時に自動スキャン
  scan_on_startup = false,
  
  -- プラグイン更新前にスキャン
  scan_before_update = true,
  
  -- リスク検出時に確認を求める
  require_confirmation = true,
  
  -- 無視するパターン (偽陽性対策)
  ignore_patterns = {},
  
  -- スキャンから除外するパス
  exclude_paths = {
    "test/",
    "spec/",
    "tests/"
  },
  
  -- プラグインマネージャー統合
  integrations = {
    lazy = true,
    packer = true
  }
})
```

## 使い方

### コマンド

- `:SecurityScanAll` - 全プラグインをスキャン
- `:SecurityScan <plugin-name>` - 特定のプラグインをスキャン
- `:SecurityReport` - 最新のスキャンレポートを表示

### プラグイン更新時の動作

プラグイン更新前に自動的にセキュリティチェックが実行され、リスクが検出された場合は確認ダイアログが表示されます。

## 検出されるセキュリティリスク

以下のようなカテゴリのセキュリティリスクを検出します：

- **システム実行**: `os.execute`、`vim.fn.system`などによる外部コマンド実行
- **ファイル操作**: `io.open`、`vim.fn.readfile`などによるファイル読み書き
- **コード実行**: `loadstring`、`load`などによる動的コード評価
- **ネットワークアクセス**: `socket.http`などによる外部通信
- **設定変更**: `vim.opt.rtp`などによる重要な設定変更

## ライセンス

MIT

## 貢献

バグ報告や機能要望は[Issues](https://github.com/glaucus03/nvim-security-scanner/issues)に投稿してください。
プルリクエストも歓迎します！

## 開発

### テスト

テストを実行するには以下のコマンドを使用します：

```bash
nvim --headless -u NONE -c "lua dofile('test/run_tests.lua')" -c "q"
```

開発中の場合は、以下のようにNVIM_CONFIG変数を設定して特定の設定を使用せずにプラグインをテストできます：

```bash
NVIM_CONFIG="" nvim --cmd "set rtp+=$(pwd)" -c "lua require('nvim-security-scanner').setup()"
```
local M = {}

-- デフォルトの設定
local default_config = {
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
}

-- ユーザー設定
M.config = {}

-- セットアップ関数
function M.setup(user_config)
  -- デフォルト設定とユーザー設定をマージ
  M.config = vim.tbl_deep_extend("force", default_config, user_config or {})
  
  -- プラグインが無効化されている場合は早期リターン
  if not M.config.enabled then
    return
  end
  
  -- コマンドの登録
  vim.api.nvim_create_user_command("SecurityScanAll", function()
    require("nvim-security-scanner.scanner").scan_all_plugins()
  end, {})
  
  vim.api.nvim_create_user_command("SecurityScan", function(opts)
    if opts.args and opts.args ~= "" then
      require("nvim-security-scanner.scanner").scan_plugin(opts.args)
    else
      vim.notify("プラグイン名を指定してください", vim.log.levels.ERROR)
    end
  end, { nargs = "?" })
  
  vim.api.nvim_create_user_command("SecurityReport", function()
    require("nvim-security-scanner.report").show_last_report()
  end, {})
  
  -- プラグインマネージャー統合の初期化
  if M.config.integrations.lazy then
    require("nvim-security-scanner.integrations.lazy").setup()
  end
  
  if M.config.integrations.packer then
    require("nvim-security-scanner.integrations.packer").setup()
  end
  
  -- 起動時のスキャン
  if M.config.scan_on_startup then
    vim.defer_fn(function()
      require("nvim-security-scanner.scanner").scan_all_plugins()
    end, 1000) -- 起動から1秒後に実行
  end
end

return M
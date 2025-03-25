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
  
  -- GitHubリポジトリクローン後にディレクトリを保持
  keep_cloned_repos = false,
  
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
  
  -- スキャナーモジュールを初期化
  require("nvim-security-scanner.scanner").init(M.config)
  
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
      -- GitHub リポジトリの形式かどうか確認 (user/repo)
      if opts.args:match("^[%w%-%.]+/[%w%-%.]+$") then
        -- GitHub リポジトリスキャン
        require("nvim-security-scanner.scanner").scan_github_repo(opts.args)
      else
        -- 既存のプラグインスキャン
        require("nvim-security-scanner.scanner").scan_plugin(opts.args)
      end
    else
      vim.notify("プラグイン名または 'user/repo' 形式のGitHubリポジトリを指定してください", vim.log.levels.ERROR)
    end
  end, { nargs = "?", 
          complete = function(ArgLead, CmdLine, CursorPos)
            -- 補完候補を提供（インストール済みプラグインと最近スキャンしたGitHubリポジトリ）
            local candidates = {}
            
            -- lazy.nvim プラグイン
            local lazy_path = vim.fn.stdpath("data") .. "/lazy/"
            if vim.fn.isdirectory(lazy_path) == 1 then
              local plugins = vim.fn.readdir(lazy_path)
              for _, plugin in ipairs(plugins) do
                if plugin:lower():match(ArgLead:lower()) then
                  table.insert(candidates, plugin)
                end
              end
            end
            
            -- packer.nvim プラグイン
            local packer_path = vim.fn.stdpath("data") .. "/site/pack/packer/start/"
            if vim.fn.isdirectory(packer_path) == 1 then
              local plugins = vim.fn.readdir(packer_path)
              for _, plugin in ipairs(plugins) do
                if plugin:lower():match(ArgLead:lower()) then
                  table.insert(candidates, plugin)
                end
              end
            end
            
            return candidates
          end
        })
  
  vim.api.nvim_create_user_command("SecurityReport", function()
    local report = require("nvim-security-scanner.report")
    
    -- テスト用レポート生成機能を追加
    if vim.fn.exists("g:security_scanner_debug") == 1 and vim.g.security_scanner_debug == 1 then
      -- デバッグモードの場合、テストレポートを作成するオプションを提供
      if vim.fn.confirm("テスト用レポートを生成しますか？", "&Yes\n&No", 2) == 1 then
        report.create_test_report()
      end
    end
    
    report.show_last_report()
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
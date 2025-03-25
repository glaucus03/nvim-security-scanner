local M = {}
local scanner = require("nvim-security-scanner.scanner")
local report = require("nvim-security-scanner.report")
local config = require("nvim-security-scanner").config

-- lazy.nvimとの統合をセットアップ
function M.setup()
  -- lazy.nvimがインストールされているか確認
  local has_lazy, lazy = pcall(require, "lazy")
  if not has_lazy then
    vim.notify("lazy.nvimが見つからないため、統合をスキップします", vim.log.levels.WARN)
    return
  end
  
  -- 統合方法を試みる
  local integration_success = false
  
  -- 方法1: 古いバージョンのlazy.nvimでのフック追加方法
  if type(lazy.hook) == "table" and lazy.hook.add then
    pcall(function()
      lazy.hook.add("pre-update", function(plugin)
        return M.pre_update_hook(plugin)
      end)
      integration_success = true
      vim.notify("lazy.nvimとの統合が完了しました（hooksAPIを使用）", vim.log.levels.INFO)
    end)
  end
  
  -- 方法2: ハンドラーとして登録
  if not integration_success and type(lazy.config) == "table" and lazy.config.handlers then
    pcall(function()
      -- ハンドラーとして登録
      lazy.config.handlers = lazy.config.handlers or {}
      lazy.config.handlers.pre_update = lazy.config.handlers.pre_update or {}
      table.insert(lazy.config.handlers.pre_update, function(plugin)
        return M.pre_update_hook(plugin)
      end)
      integration_success = true
      vim.notify("lazy.nvimとの統合が完了しました（handlersを使用）", vim.log.levels.INFO)
    end)
  end
  
  -- 方法3: イベントとして登録
  if not integration_success and type(lazy.on_event) == "function" then
    pcall(function()
      lazy.on_event("pre-update", function(plugin)
        return M.pre_update_hook(plugin)
      end)
      integration_success = true
      vim.notify("lazy.nvimとの統合が完了しました（eventsを使用）", vim.log.levels.INFO)
    end)
  end
  
  -- 方法4: Lazyのインストール関数をモンキーパッチ（最終手段）
  if not integration_success and type(lazy.install) == "function" then
    pcall(function()
      local original_update = lazy.install
      lazy.install = function(...)
        -- プラグイン更新前の処理
        local plugins = ...
        if plugins and type(plugins) == "table" then
          for _, plugin in ipairs(plugins) do
            local should_continue = M.pre_update_hook(plugin)
            if not should_continue then
              vim.notify("プラグイン " .. (plugin.name or "unknown") .. " の更新がキャンセルされました", vim.log.levels.INFO)
              return
            end
          end
        end
        
        -- 元の更新関数を呼び出し
        return original_update(...)
      end
      integration_success = true
      vim.notify("lazy.nvimとの統合が完了しました（モンキーパッチを使用）", vim.log.levels.INFO)
    end)
  end
  
  -- 最終的な結果
  if not integration_success then
    vim.notify("lazy.nvimのAPIが非対応のため、統合に失敗しました。手動でセキュリティチェックを実行してください：:SecurityScanAll", vim.log.levels.WARN)
  end
end

-- 更新前のフック処理（共通）
function M.pre_update_hook(plugin)
  -- プラグインが無効化されているかチェック
  if not config or not config.enabled or not config.scan_before_update then
    return true
  end
  
  -- プラグインディレクトリのチェック
  local plugin_dir = plugin.dir
  if not plugin_dir and plugin.path then
    plugin_dir = plugin.path  -- 異なるバージョンでは異なるプロパティ名かもしれない
  end
  
  local plugin_name = plugin.name
  if not plugin_name and plugin_dir then
    plugin_name = vim.fn.fnamemodify(plugin_dir, ":t")
  else
    plugin_name = plugin_name or "unknown"
  end
  
  if not plugin_dir or vim.fn.isdirectory(plugin_dir) ~= 1 then
    vim.notify("プラグイン " .. plugin_name .. " のディレクトリが見つかりません", vim.log.levels.WARN)
    return true
  end
  
  -- プラグインをスキャン
  local findings = scanner.scan_plugin(plugin_dir)
  
  -- リスクが見つかった場合
  if #findings > 0 then
    if config.require_confirmation then
      -- ユーザーに確認を要求
      return report.confirmation_dialog(plugin_name, findings)
    else
      -- 警告を表示するだけで更新は許可
      vim.notify(plugin_name .. " でセキュリティリスクが見つかりました。詳細は :SecurityReport で確認してください", vim.log.levels.WARN)
      return true
    end
  end
  
  -- リスクが見つからなければ更新を許可
  return true
end

return M
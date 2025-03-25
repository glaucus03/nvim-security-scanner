local M = {}
local scanner = require("nvim-security-scanner.scanner")
local report = require("nvim-security-scanner.report")
local config = require("nvim-security-scanner").config

-- packer.nvimとの統合をセットアップ
function M.setup()
  -- packer.nvimがインストールされているか確認
  local has_packer = pcall(require, "packer")
  if not has_packer then
    vim.notify("packer.nvimが見つからないため、統合をスキップします", vim.log.levels.WARN)
    return
  end
  
  -- packer.nvimのフックシステムにアクセス
  local packer = require("packer")
  
  -- pre-updateフックを追加
  packer.set_hook("pre-update", function(plugin_name)
    -- プラグインが無効化されているかチェック
    if not config.enabled or not config.scan_before_update then
      return true
    end
    
    -- プラグインパスを構築
    local plugin_path = vim.fn.stdpath("data") .. "/site/pack/packer/start/" .. plugin_name
    if vim.fn.isdirectory(plugin_path) ~= 1 then
      plugin_path = vim.fn.stdpath("data") .. "/site/pack/packer/opt/" .. plugin_name
      if vim.fn.isdirectory(plugin_path) ~= 1 then
        vim.notify("プラグイン " .. plugin_name .. " のディレクトリが見つかりません", vim.log.levels.WARN)
        return true
      end
    end
    
    -- プラグインをスキャン
    local findings = scanner.scan_plugin(plugin_path)
    
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
  end)
  
  vim.notify("packer.nvimとの統合が完了しました", vim.log.levels.INFO)
end

return M
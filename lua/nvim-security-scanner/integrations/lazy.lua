local M = {}
local scanner = require("nvim-security-scanner.scanner")
local report = require("nvim-security-scanner.report")
local config = require("nvim-security-scanner").config

-- lazy.nvimとの統合をセットアップ
function M.setup()
  -- lazy.nvimがインストールされているか確認
  local has_lazy = pcall(require, "lazy")
  if not has_lazy then
    vim.notify("lazy.nvimが見つからないため、統合をスキップします", vim.log.levels.WARN)
    return
  end
  
  -- lazy.nvimのフックシステムにアクセス
  local lazy = require("lazy")
  
  -- pre-updateフックを追加
  if lazy.hook and lazy.hook.add then
    lazy.hook.add("pre-update", function(plugin)
      -- プラグインが無効化されているかチェック
      if not config.enabled or not config.scan_before_update then
        return true
      end
      
      -- プラグインをスキャン
      local findings = scanner.scan_plugin(plugin.dir)
      
      -- リスクが見つかった場合
      if #findings > 0 then
        if config.require_confirmation then
          -- ユーザーに確認を要求
          return report.confirmation_dialog(plugin.name, findings)
        else
          -- 警告を表示するだけで更新は許可
          vim.notify(plugin.name .. " でセキュリティリスクが見つかりました。詳細は :SecurityReport で確認してください", vim.log.levels.WARN)
          return true
        end
      end
      
      -- リスクが見つからなければ更新を許可
      return true
    end)
    
    vim.notify("lazy.nvimとの統合が完了しました", vim.log.levels.INFO)
  else
    vim.notify("lazy.nvimのフックAPIが見つからないため、統合に失敗しました", vim.log.levels.ERROR)
  end
end

return M
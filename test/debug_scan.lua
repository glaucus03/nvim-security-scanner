-- デバッグ用スクリプト
-- Neovimで以下のコマンドで実行:
-- nvim --headless -u NONE -c "lua dofile('test/debug_scan.lua')" -c "messages" -c "q"

-- ルートへのパスを取得
local root_dir = vim.fn.getcwd()

-- プラグインのruntimepathを追加
vim.opt.runtimepath:append(root_dir)

-- モックアラート
local notifications = {}
local mock_notify = function(msg, level)
  print("[通知] " .. msg)
  table.insert(notifications, { message = msg, level = level })
end
vim.notify = mock_notify

-- プラグインを初期化
local security_scanner = require("nvim-security-scanner")
security_scanner.setup({
  risk_threshold = "low",
  scan_on_startup = false,
  require_confirmation = false
})

-- スキャナーモジュールを取得
local scanner = require("nvim-security-scanner.scanner")
local report = require("nvim-security-scanner.report")

-- サンプルプラグインをスキャン
print("-- リスクプラグインのスキャン")
local risky_path = root_dir .. "/test/sample-plugins/risky-plugin"
local risky_findings = scanner.scan_plugin(risky_path)
print("リスクが検出されたか: " .. (#risky_findings > 0 and "はい" or "いいえ"))
print("検出数: " .. #risky_findings)

-- レポート確認
print("\n-- レポート確認")

-- デバッグ用にレポートを表示する関数を追加
local test_show_report = function()
  -- レポートモジュールから直接アクセスできないので、独自の方法でチェック
  local report_displayed = false
  
  -- オリジナルのshow_last_reportを一時的に上書き
  local original_show = report.show_last_report
  report.show_last_report = function()
    report_displayed = true
    print("レポートの表示テスト")
    original_show()
  end
  
  -- レポート表示試行
  report.show_last_report()
  
  -- 関数を元に戻す
  report.show_last_report = original_show
  
  return report_displayed
end

local report_exists = test_show_report()

-- 安全なプラグインをスキャン
print("\n-- 安全なプラグインのスキャン")
local safe_path = root_dir .. "/test/sample-plugins/safe-plugin"
local safe_findings = scanner.scan_plugin(safe_path)
print("リスクが検出されたか: " .. (#safe_findings > 0 and "はい" or "いいえ"))
print("検出数: " .. #safe_findings)

-- レポート確認（安全なプラグイン後）
print("\n-- 安全プラグイン後のレポート確認")
test_show_report()

-- scan_all_pluginsをシミュレート
print("\n-- scan_all_plugins シミュレーション")
scanner.scan_all_plugins = function()
  local all_findings = {}
  
  -- リスクありプラグインをスキャン
  local risky_findings = scanner.scan_plugin(risky_path)
  for _, finding in ipairs(risky_findings) do
    table.insert(all_findings, finding)
  end
  
  -- 安全なプラグインをスキャン
  local safe_findings = scanner.scan_plugin(safe_path)
  for _, finding in ipairs(safe_findings) do
    table.insert(all_findings, finding)
  end
  
  -- 総合レポートを作成
  require("nvim-security-scanner.report").save_report("AllPlugins", all_findings)
  
  if #all_findings > 0 then
    vim.notify("スキャン完了: 2 プラグイン中 1 プラグインで合計 " .. #all_findings .. 
              " 件のセキュリティリスクが検出されました。:SecurityReport で詳細を確認できます",
              vim.log.levels.WARN)
  else
    vim.notify("スキャン完了: 2 プラグインすべてでセキュリティリスクは検出されませんでした。",
              vim.log.levels.INFO)
  end
end

-- 全プラグインスキャン実行
scanner.scan_all_plugins()

-- 最終レポート確認
print("\n-- 全プラグインスキャン後のレポート確認")
test_show_report()

-- このテストでは既に十分な情報が得られました

-- レポート表示
print("レポート表示の実行:")
report.show_last_report()
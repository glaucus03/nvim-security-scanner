-- GitHub リポジトリスキャン機能のテストスクリプト
-- Neovimで以下のコマンドで実行:
-- nvim --headless -u NONE -c "lua dofile('test/github_scan_test.lua')" -c "messages" -c "q"

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

-- 便利な出力関数
local function print_header(text)
  print("\n" .. string.rep("=", 80))
  print("== " .. text)
  print(string.rep("=", 80) .. "\n")
end

local function print_success(text)
  print("[成功] " .. text)
end

local function print_error(text)
  print("[エラー] " .. text)
end

local function print_info(text)
  print("[情報] " .. text)
end

-- プラグインを初期化
local security_scanner = require("nvim-security-scanner")
security_scanner.setup({
  risk_threshold = "low",
  scan_on_startup = false,
  require_confirmation = false,
  keep_cloned_repos = true -- テスト用に保持
})

-- スキャナーモジュールを取得
local scanner = require("nvim-security-scanner.scanner")
local report = require("nvim-security-scanner.report")

-- GitHubリポジトリをスキャン
print_header("GitHub リポジトリスキャンテスト")

-- テスト用に小さいリポジトリを選択
local test_repo = "neovim/nvim-lspconfig"
print_info("テスト対象リポジトリ: " .. test_repo)

-- リポジトリをスキャン
print_info("リポジトリスキャン開始...")
local time_start = os.time()
local findings = scanner.scan_github_repo(test_repo)
local time_end = os.time()
local elapsed = time_end - time_start

print_info("スキャン完了! 所要時間: " .. elapsed .. "秒")
print_info("検出されたリスク: " .. #findings .. "件")

-- レポートをテスト
print_header("レポート表示テスト")

-- オリジナルの関数を保存
local original_show = report.show_last_report

-- テスト用にモック
report.show_last_report = function()
  print_info("レポート表示呼び出し...")
  
  if not report.M or not report.M.last_report then
    print_error("レポートが存在しません")
    return
  end
  
  print_success("レポートが存在します:")
  print_info("プラグイン名: " .. report.M.last_report.plugin_name)
  print_info("検出数: " .. #report.M.last_report.findings)
  
  -- レポート内容を取得
  local content = report.generate_report_content()
  print_info("レポート内容: " .. #content .. "行")
  
  -- サンプルとして先頭10行を表示
  print_info("レポート内容（一部）:")
  for i = 1, math.min(10, #content) do
    print("  " .. content[i])
  end
end

-- レポート表示
report.show_last_report()

-- テスト後のクリーンアップ
print_header("テスト後のクリーンアップ")

-- テスト用にクローンしたディレクトリを確認
local tmp_dir = vim.fn.stdpath("cache") .. "/security_scanner/" .. test_repo:gsub("/", "_")
if vim.fn.isdirectory(tmp_dir) == 1 then
  print_info("テスト用クローンディレクトリ: " .. tmp_dir)
  print_info("keep_cloned_repos が有効なため、ディレクトリは保持されています")
  
  -- テスト用に手動削除
  if vim.fn.confirm("このディレクトリを削除しますか？", "&Yes\n&No", 2) == 1 then
    vim.fn.delete(tmp_dir, "rf")
    print_success("ディレクトリを削除しました")
  else
    print_info("ディレクトリを保持します")
  end
end

print_header("テスト完了")
print_success("GitHub リポジトリスキャン機能のテストが完了しました")
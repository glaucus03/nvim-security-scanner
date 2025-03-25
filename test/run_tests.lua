-- nvim-security-scanner用のテストスクリプト
-- Neovimで以下のコマンドで実行:
-- nvim --headless -u NONE -c "lua dofile('test/run_tests.lua')" -c "q"

-- ルートへのパスを取得
local root_dir = vim.fn.getcwd()

-- ヘルパー関数
local function print_header(text)
  print("\n\027[1;34m" .. string.rep("=", 80) .. "\027[0m")
  print("\027[1;34m== " .. text .. "\027[0m")
  print("\027[1;34m" .. string.rep("=", 80) .. "\027[0m\n")
end

local function print_success(text)
  print("\027[1;32m✓ " .. text .. "\027[0m")
end

local function print_failure(text)
  print("\027[1;31m✗ " .. text .. "\027[0m")
end

local function print_info(text)
  print("\027[1;33m→ " .. text .. "\027[0m")
end

-- レポート生成結果を保存するテーブル
local last_report = nil

-- モックの作成
local mock_notify = function(msg, level)
  print_info("[通知] " .. msg)
end

-- vim.notifyをモック化
vim.notify = mock_notify

-- テスト用にプラグインのruntimepathを追加
vim.opt.runtimepath:append(root_dir)

-- プラグインのモジュールをロード
local patterns = require("nvim-security-scanner.patterns")
local original_report = require("nvim-security-scanner.report")

-- レポートモジュールをモック化して結果を保存
local report_module = {}
for k, v in pairs(original_report) do
  report_module[k] = v
end

-- モック化したreportモジュールをpackage.loadedに設定
package.loaded["nvim-security-scanner.report"] = report_module

-- scannerモジュールはreportをモック化した後にロード
local scanner = require("nvim-security-scanner.scanner")

-- モック用のグローバル変数
-- 注意: 実際のプラグインコードでは使用しないでください - テスト専用
_G.test_last_report = nil

-- save_reportをオーバーライド
report_module.save_report = function(plugin_name, findings)
  print_info("レポート保存: プラグイン = " .. plugin_name .. ", 検出数 = " .. #findings)
  
  -- グローバル変数と内部変数の両方に保存
  _G.test_last_report = {
    plugin_name = plugin_name,
    findings = findings,
    timestamp = os.time()
  }
  
  last_report = _G.test_last_report
  
  -- オリジナルの関数も呼び出し
  original_report.save_report(plugin_name, findings)
end

-- show_last_reportをオーバーライド
report_module.show_last_report = function()
  -- グローバル変数から最新のレポートを取得
  local report_to_show = _G.test_last_report or last_report
  
  if report_to_show and report_to_show.findings and #report_to_show.findings > 0 then
    print_info("レポート表示: プラグイン = " .. report_to_show.plugin_name .. ", 検出数 = " .. #report_to_show.findings)
    
    -- リスク別のカウント
    local risk_counts = { low = 0, medium = 0, high = 0 }
    for _, finding in ipairs(report_to_show.findings) do
      risk_counts[finding.risk] = (risk_counts[finding.risk] or 0) + 1
    end
    
    print_info("  高リスク: " .. risk_counts.high)
    print_info("  中リスク: " .. risk_counts.medium)
    print_info("  低リスク: " .. risk_counts.low)
    
    for i, finding in ipairs(report_to_show.findings) do
      print_info("  検出 " .. i .. ": [" .. finding.risk .. "] " .. finding.pattern .. " (行 " .. finding.line .. ")")
    end
    
    return true
  else
    print_info("表示可能なレポートがありません")
    return false
  end
end

-- テストケース
local tests = {}

-- パターンテスト
tests.test_patterns = function()
  print_header("パターンテスト")
  
  local all_patterns = patterns.get_all_patterns()
  if #all_patterns > 0 then
    print_success("パターンの合計数: " .. #all_patterns)
  else
    print_failure("パターンが見つかりません")
    return false
  end
  
  local high_patterns = patterns.get_patterns_by_risk("high")
  print_info("高リスクパターン数: " .. #high_patterns)
  
  local medium_patterns = patterns.get_patterns_by_risk("medium")
  print_info("中リスクパターン数: " .. #medium_patterns)
  
  local low_patterns = patterns.get_patterns_by_risk("low")
  print_info("低リスクパターン数: " .. #low_patterns)
  
  return true
end

-- リスクのあるプラグインのスキャンテスト
tests.test_risky_plugin_scan = function()
  print_header("リスクのあるプラグインのスキャンテスト")
  
  -- テスト設定
  local test_config = {
    risk_threshold = "low",
    ignore_patterns = {},
    exclude_paths = {}
  }
  
  -- スキャナーを初期化
  scanner.init(test_config)
  
  -- サンプルプラグインのパス
  local risky_plugin_path = root_dir .. "/test/sample-plugins/risky-plugin"
  
  -- スキャンを実行
  local findings = scanner.scan_plugin(risky_plugin_path)
  
  if #findings > 0 then
    print_success("リスクが検出されました: " .. #findings .. "件")
    
    -- リスクの種類をカウント
    local risk_types = {}
    for _, finding in ipairs(findings) do
      risk_types[finding.risk] = (risk_types[finding.risk] or 0) + 1
    end
    
    for risk, count in pairs(risk_types) do
      print_info(risk .. "リスク: " .. count .. "件")
    end
    
    return true
  else
    print_failure("リスクが検出されませんでした")
    return false
  end
end

-- 安全なプラグインのスキャンテスト
tests.test_safe_plugin_scan = function()
  print_header("安全なプラグインのスキャンテスト")
  
  -- テスト設定
  local test_config = {
    risk_threshold = "low",
    ignore_patterns = {},
    exclude_paths = {}
  }
  
  -- スキャナーを初期化
  scanner.init(test_config)
  
  -- サンプルプラグインのパス
  local safe_plugin_path = root_dir .. "/test/sample-plugins/safe-plugin"
  
  -- スキャンを実行
  local findings = scanner.scan_plugin(safe_plugin_path)
  
  if #findings == 0 then
    print_success("リスクが検出されませんでした（期待通り）")
    return true
  else
    print_failure("リスクが検出されました（期待に反して）: " .. #findings .. "件")
    for _, finding in ipairs(findings) do
      print_info("  検出: " .. finding.pattern .. " (行 " .. finding.line .. ")")
    end
    return false
  end
end

-- レポート生成テスト
tests.test_report_generation = function()
  print_header("レポート生成テスト")
  
  -- リスクのあるプラグインを再度スキャンして確実にレポートを生成
  local risky_plugin_path = root_dir .. "/test/sample-plugins/risky-plugin"
  scanner.init({ risk_threshold = "low" })
  local findings = scanner.scan_plugin(risky_plugin_path)
  
  -- レポートが生成されたか確認
  if findings and #findings > 0 then
    -- レポートの内容をテスト
    local report_content = original_report.generate_report_content()
    if report_content and #report_content > 0 then
      print_info("レポート内容が生成されました（" .. #report_content .. "行）")
      
      -- 一部のコンテンツを表示
      for i = 1, math.min(5, #report_content) do
        print_info("  " .. report_content[i])
      end
      
      print_info("  ...")
      
      -- リスク情報の部分を表示
      for i, line in ipairs(report_content) do
        if line:match("%[HIGH%]") or line:match("%[MEDIUM%]") or line:match("%[LOW%]") then
          print_info("  " .. line)
          -- コードラインも表示
          if i+1 <= #report_content and report_content[i+1]:match("コード:") then
            print_info("  " .. report_content[i+1])
          end
          break
        end
      end
    end
    
    -- レポート表示機能をテスト
    report_module.show_last_report()
    print_success("レポートが正常に生成されました")
    return true
  else
    print_failure("レポートが生成されていないか、リスクが検出されませんでした")
    return false
  end
end

-- 閾値テスト
tests.test_risk_thresholds = function()
  print_header("リスク閾値テスト")
  
  -- サンプルプラグインのパス
  local risky_plugin_path = root_dir .. "/test/sample-plugins/risky-plugin"
  
  -- 高リスクのみ
  scanner.init({ risk_threshold = "high" })
  local high_findings = scanner.scan_plugin(risky_plugin_path)
  print_info("高リスクのみ: " .. #high_findings .. "件")
  
  -- 中リスク以上
  scanner.init({ risk_threshold = "medium" })
  local medium_findings = scanner.scan_plugin(risky_plugin_path)
  print_info("中リスク以上: " .. #medium_findings .. "件")
  
  -- すべてのリスク
  scanner.init({ risk_threshold = "low" })
  local all_findings = scanner.scan_plugin(risky_plugin_path)
  print_info("すべてのリスク: " .. #all_findings .. "件")
  
  if #high_findings <= #medium_findings and #medium_findings <= #all_findings then
    print_success("リスク閾値が期待通り動作しています")
    return true
  else
    print_failure("リスク閾値が期待通り動作していません")
    return false
  end
end

-- 除外パスのテスト
tests.test_exclude_paths = function()
  print_header("除外パステスト")
  
  -- サンプルプラグインのパス
  local risky_plugin_path = root_dir .. "/test/sample-plugins/risky-plugin"
  
  -- 除外なし
  scanner.init({ risk_threshold = "low", exclude_paths = {} })
  local all_findings = scanner.scan_plugin(risky_plugin_path)
  print_info("除外なし: " .. #all_findings .. "件")
  
  -- luaディレクトリを除外（すべてが除外されるはず）
  scanner.init({ risk_threshold = "low", exclude_paths = { "lua" } })
  local excluded_findings = scanner.scan_plugin(risky_plugin_path)
  print_info("luaディレクトリ除外: " .. #excluded_findings .. "件")
  
  if #excluded_findings < #all_findings then
    print_success("除外パスが期待通り動作しています")
    return true
  else
    print_failure("除外パスが期待通り動作していません")
    return false
  end
end

-- テストをすべて実行
local function run_all_tests()
  print_header("nvim-security-scanner テスト実行")
  
  local passed = 0
  local failed = 0
  
  -- テストを特定の順序で実行
  local test_order = {
    "test_patterns",
    "test_risky_plugin_scan",
    "test_report_generation",
    "test_safe_plugin_scan",
    "test_risk_thresholds",
    "test_exclude_paths"
  }
  
  for _, name in ipairs(test_order) do
    local test_func = tests[name]
    if test_func then
      print_info("テスト実行: " .. name)
      local success = test_func()
      if success then
        passed = passed + 1
      else
        failed = failed + 1
      end
    end
  end
  
  print_header("テスト結果")
  print_info("合計テスト数: " .. (passed + failed))
  print_success("成功: " .. passed)
  if failed > 0 then
    print_failure("失敗: " .. failed)
  else
    print_info("失敗: 0")
  end
  
  return failed == 0
end

-- テストを実行
run_all_tests()

-- Neovimのメッセージを表示しておく
vim.cmd("messages")
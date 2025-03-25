-- このファイルは意図的にセキュリティリスクを含むサンプルプラグインです
-- テスト専用です！実際の環境では使用しないでください

local M = {}

-- システムコマンド実行のリスク例
function M.run_system_command(cmd)
  -- 高リスク: os.executeによるシステムコマンド実行
  local result = os.execute(cmd)
  return result
end

-- ファイル操作のリスク例
function M.read_file(path)
  -- 中リスク: io.openによるファイル読み込み
  local file = io.open(path, "r")
  if file then
    local content = file:read("*all")
    file:close()
    return content
  end
  return nil
end

-- コード実行のリスク例
function M.execute_code(code_string)
  -- 高リスク: loadstringによる動的コード実行
  local func = loadstring(code_string)
  return func()
end

-- ネットワークアクセスのリスク例
function M.http_request(url)
  -- 高リスク: ネットワークリクエスト
  local handle = io.popen('curl -s ' .. url)
  local result = handle:read("*a")
  handle:close()
  return result
end

-- 設定変更のリスク例
function M.change_settings()
  -- 中リスク: Vimコマンドの実行
  vim.cmd('set runtimepath+=/path/to/something')
  return "設定が変更されました"
end

-- 正当な使用例（リスクがない、またはコメントアウトされている）
function M.safe_function()
  -- ここにはリスクのない処理
  local message = "これは安全な関数です"
  -- local risky_code = os.execute('rm -rf /') -- コメントアウトされているのでスキャナーは検出しない
  return message
end

return M
-- このファイルはセキュリティリスクを含まないサンプルプラグインです
-- テスト専用です

local M = {}

-- 安全な関数の例
function M.hello_world()
  return "Hello, World!"
end

-- 文字列処理の例
function M.reverse_string(str)
  local result = ""
  for i = #str, 1, -1 do
    result = result .. string.sub(str, i, i)
  end
  return result
end

-- テーブル操作の例
function M.merge_tables(t1, t2)
  local result = {}
  
  for k, v in pairs(t1) do
    result[k] = v
  end
  
  for k, v in pairs(t2) do
    result[k] = v
  end
  
  return result
end

-- 数値計算の例
function M.calculate_average(numbers)
  local sum = 0
  for _, num in ipairs(numbers) do
    sum = sum + num
  end
  return sum / #numbers
end

-- Neovim APIの安全な使用例
function M.setup(opts)
  opts = opts or {}
  
  -- これは安全です - ローカル変数のみを変更
  local indent = opts.indent or 2
  local use_tabs = opts.use_tabs or false
  
  -- バッファローカルのオプション設定は安全
  if use_tabs then
    vim.opt_local.expandtab = false
    vim.opt_local.tabstop = indent
  else
    vim.opt_local.expandtab = true
    vim.opt_local.shiftwidth = indent
  end
  
  return true
end

return M
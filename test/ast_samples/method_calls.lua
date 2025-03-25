-- サンプル3: メソッド呼び出し
local Utils = {}

-- 安全なメソッド
function Utils.safe_method(param)
  return "Processed: " .. param
end

-- 危険なメソッド
function Utils.dangerous_method(cmd)
  -- 危険な関数呼び出し
  local result = io.popen(cmd)
  local output = result:read("*all")
  result:close()
  return output
end

-- テーブルメソッド呼び出し
local function test_method_calls()
  -- 安全なメソッド呼び出し
  local safe_result = Utils.safe_method("test")
  
  -- 危険なメソッド呼び出し
  local dangerous_result = Utils.dangerous_method("ls -la")
  
  return safe_result, dangerous_result
end

return test_method_calls
-- サンプル4: ネストされた呼び出し
local function wrapper(func, arg)
  -- 関数をラップして呼び出す
  return func(arg)
end

local function execute_command(cmd)
  -- 危険な関数呼び出し
  return os.execute(cmd)
end

local function test_nested_calls()
  -- 直接呼び出し
  local direct_result = execute_command("echo 'Direct call'")
  
  -- ラップされた呼び出し (これも検出されるべき)
  local wrapped_result = wrapper(execute_command, "echo 'Wrapped call'")
  
  -- より複雑なネスト
  local complex_result = wrapper(function(x)
    return wrapper(execute_command, x)
  end, "echo 'Complex nested call'")
  
  return direct_result, wrapped_result, complex_result
end

return test_nested_calls
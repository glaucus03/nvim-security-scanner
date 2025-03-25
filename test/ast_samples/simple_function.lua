-- サンプル1: 単純な関数呼び出し
local function test_function()
  -- 安全な関数呼び出し
  print("Hello, World!")
  
  -- 潜在的に危険な関数呼び出し
  os.execute("echo 'This is a test'")
end

return test_function
-- サンプル5: エッジケース
local function edge_cases_test()
  -- 変数名が危険なパターンに似ている場合
  local os_execute = "This is just a variable name"
  
  -- 部分的に一致する場合
  local my_os_function = function() return "Not the real os.execute" end
  
  -- 文字列連結で関数名を構築（高度な解析では検出可能だが現状では難しい）
  local os_obj = "os"
  local execute_method = "." .. "execute"
  local constructed_func = os_obj .. execute_method
  
  -- メタテーブルとカスタムインデックス
  local meta_obj = {}
  setmetatable(meta_obj, {
    __index = function(t, k)
      if k == "execute" then
        return os.execute
      end
      return nil
    end
  })
  
  -- 実際に危険な呼び出し
  -- meta_obj.execute("echo 'MetaTable method call'")  -- コメントアウト状態
  
  return os_execute, my_os_function, constructed_func
end

return edge_cases_test
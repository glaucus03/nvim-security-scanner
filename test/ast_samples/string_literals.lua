-- サンプル2: 文字列リテラル内のパターン
local function string_literals_test()
  -- 通常の文字列リテラル
  local str1 = "This is just a normal string"
  
  -- 危険なパターンを含む文字列リテラル (これは検出されるべきではない)
  local str2 = "Code example: os.execute('rm -rf /')"
  local str3 = 'Another example: io.popen("ls -la")'
  
  -- 実行されるコード (これは検出されるべき)
  local cmd = "ls -la"
  os.execute(cmd)
  
  -- コメント内のパターン (これは検出されるべきではない)
  -- 次の行はos.executeを呼び出す: os.execute("pwd")
  
  return str1, str2, str3
end

return string_literals_test
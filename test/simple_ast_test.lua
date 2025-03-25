-- シンプルなテスト用のASTモジュール
local M = {}

-- ASTノードタイプ定義
M.NODE_TYPES = {
  VARIABLE = "Variable",
  CALL = "Call",
}

-- シンプルなAST解析
function M.parse_code(code)
  local ast = {
    type = "Block",
    body = {
      {
        type = M.NODE_TYPES.CALL,
        func = {
          type = M.NODE_TYPES.VARIABLE,
          name = "print"
        },
        args = {
          {
            type = "Literal",
            value = "Hello, World!"
          }
        }
      }
    }
  }
  
  return ast
end

-- 関数呼び出しノードを特定する関数
function M.find_function_calls(ast, function_name)
  local results = {}
  
  local function traverse(node)
    if not node or type(node) ~= "table" then
      return
    end
    
    if node.type == M.NODE_TYPES.CALL then
      local func = node.func
      
      -- 単純な関数名の場合
      if func.type == M.NODE_TYPES.VARIABLE and func.name == function_name then
        table.insert(results, node)
      end
    end
    
    -- 子ノードの再帰的探索
    for _, child in pairs(node) do
      if type(child) == "table" then
        traverse(child)
      end
    end
  end
  
  traverse(ast)
  return results
end

-- メソッド呼び出しを特定する関数
function M.find_method_calls(ast, table_name, method_name)
  -- シンプルな実装
  return {}
end

-- セキュリティ問題を検出する関数
function M.detect_security_issues(ast, patterns)
  -- シンプルな実装
  return {
    {
      pattern = "os%.execute",
      risk = "high",
      description = "システムコマンドを実行できる危険な関数",
      line = 10
    }
  }
end

-- 動作確認用
function M.test()
  local ast = M.parse_code("")
  local calls = M.find_function_calls(ast, "print")
  print("Found " .. #calls .. " function calls")
  
  local issues = M.detect_security_issues(ast, {})
  print("Found " .. #issues .. " security issues")
  
  return true
end

return M
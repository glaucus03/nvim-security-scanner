--[[
nvim-security-scanner AST parser module

このモジュールはLuaのコードを解析してASTを生成し、セキュリティ分析を行うためのユーティリティを提供します。
]]

local M = {}

-- ASTノードタイプ定義
M.NODE_TYPES = {
  -- 式
  CALL = "Call",           -- 関数呼び出し
  INDEX = "Index",         -- テーブルインデックス
  LITERAL = "Literal",     -- リテラル値
  VARIABLE = "Variable",   -- 変数参照
  TABLE = "Table",         -- テーブル構築
  
  -- 文
  ASSIGNMENT = "Assignment", -- 代入
  LOCAL = "Local",         -- ローカル変数宣言
  FUNCTION = "Function",   -- 関数定義
  IF = "If",               -- if文
  FOR = "For",             -- for文
  WHILE = "While",         -- while文
  REPEAT = "Repeat",       -- repeat文
  RETURN = "Return",       -- return文
  
  -- その他
  BLOCK = "Block",         -- コードブロック
  COMMENT = "Comment",     -- コメント
  STRING = "String",       -- 文字列
  NUMBER = "Number",       -- 数値
}

-- デフォルトのオプション
local default_options = {
  include_comments = true,  -- コメントを含めるかどうか
  track_locations = true,   -- ノードの位置情報を記録するかどうか
}

-- シンプルなLexer（字句解析器）
local function create_lexer(code)
  local tokens = {}
  local pos = 1
  local line = 1
  local col = 1
  local code_len = #code
  
  -- 基本的なトークンパターン
  local patterns = {
    -- 空白とコメント
    {pattern = "^%s+", type = "whitespace"},
    {pattern = "^%-%-[^\n]*", type = "comment"},
    {pattern = "^%-%-%[%[(.-)%]%]", type = "comment", multiline = true},
    
    -- リテラル
    {pattern = "^%d+%.%d+", type = "number"},
    {pattern = "^%d+", type = "number"},
    {pattern = "^\"([^\"]*)\"", type = "string"},
    {pattern = "^'([^']*)'", type = "string"},
    {pattern = "^%[%[(.-)%]%]", type = "string", multiline = true},
    
    -- キーワード
    {pattern = "^function", type = "keyword"},
    {pattern = "^return", type = "keyword"},
    {pattern = "^local", type = "keyword"},
    {pattern = "^if", type = "keyword"},
    {pattern = "^then", type = "keyword"},
    {pattern = "^else", type = "keyword"},
    {pattern = "^elseif", type = "keyword"},
    {pattern = "^end", type = "keyword"},
    {pattern = "^for", type = "keyword"},
    {pattern = "^in", type = "keyword"},
    {pattern = "^do", type = "keyword"},
    {pattern = "^while", type = "keyword"},
    {pattern = "^repeat", type = "keyword"},
    {pattern = "^until", type = "keyword"},
    {pattern = "^break", type = "keyword"},
    {pattern = "^nil", type = "nil"},
    {pattern = "^true", type = "boolean"},
    {pattern = "^false", type = "boolean"},
    {pattern = "^and", type = "operator"},
    {pattern = "^or", type = "operator"},
    {pattern = "^not", type = "operator"},
    
    -- 識別子
    {pattern = "^[%a_][%w_]*", type = "identifier"},
    
    -- 演算子と区切り文字
    {pattern = "^%.", type = "operator"},
    {pattern = "^%.%.", type = "operator"},
    {pattern = "^%.%.%.", type = "operator"},
    {pattern = "^==", type = "operator"},
    {pattern = "^~=", type = "operator"},
    {pattern = "^<=", type = "operator"},
    {pattern = "^>=", type = "operator"},
    {pattern = "^=", type = "operator"},
    {pattern = "^<", type = "operator"},
    {pattern = "^>", type = "operator"},
    {pattern = "^%+", type = "operator"},
    {pattern = "^%-", type = "operator"},
    {pattern = "^%*", type = "operator"},
    {pattern = "^/", type = "operator"},
    {pattern = "^%%", type = "operator"},
    {pattern = "^#", type = "operator"},
    {pattern = "^%^", type = "operator"},
    {pattern = "^:", type = "operator"},
    {pattern = "^;", type = "separator"},
    {pattern = "^,", type = "separator"},
    {pattern = "^%(", type = "paren", value = "("},
    {pattern = "^%)", type = "paren", value = ")"},
    {pattern = "^%{", type = "brace", value = "{"},
    {pattern = "^%}", type = "brace", value = "}"},
    {pattern = "^%[", type = "bracket", value = "["},
    {pattern = "^%]", type = "bracket", value = "]"},
  }
  
  -- 次のトークンを抽出
  local function next_token()
    if pos > code_len then
      return nil
    end
    
    local current_code = code:sub(pos)
    
    for _, pattern_info in ipairs(patterns) do
      local match = current_code:match(pattern_info.pattern)
      
      if match then
        local token_length
        if pattern_info.multiline then
          -- マルチラインの場合は特別処理
          token_length = #match + 4  -- [[ と ]] の分を追加
        else
          -- 通常のパターン
          token_length = #match
        end
        
        local token = {
          type = pattern_info.type,
          value = match,
          pos = pos,
          line = line,
          col = col,
        }
        
        -- パターン固有の値があれば使用
        if pattern_info.value then
          token.value = pattern_info.value
        end
        
        -- 位置情報の更新
        pos = pos + token_length
        
        -- 行と列の位置を更新
        if pattern_info.type == "whitespace" then
          -- 空白文字内の改行をカウント
          local newlines = 0
          for _ in match:gmatch("\n") do
            newlines = newlines + 1
          end
          
          if newlines > 0 then
            line = line + newlines
            col = token_length - match:match(".*\n(.*)")
          else
            col = col + token_length
          end
        else
          -- 空白以外のトークンでも改行があれば対応
          local newlines = 0
          for _ in match:gmatch("\n") do
            newlines = newlines + 1
          end
          
          if newlines > 0 then
            line = line + newlines
            col = token_length - match:match(".*\n(.*)")
          else
            col = col + token_length
          end
          
          -- 空白でないトークンを保存
          if pattern_info.type ~= "whitespace" then
            table.insert(tokens, token)
          end
        end
        
        return token
      end
    end
    
    -- マッチするパターンがない場合
    error("Unexpected character at position " .. pos .. ": " .. code:sub(pos, pos))
  end
  
  -- すべてのトークンを抽出
  while pos <= code_len do
    local token = next_token()
    if not token then break end
  end
  
  return tokens
end

-- シンプルなパーサー（構文解析器）- シンプルな主要構造のみ対応
local function parse_tokens(tokens)
  local current_token_idx = 1
  
  local function peek()
    return tokens[current_token_idx]
  end
  
  local function consume()
    local token = tokens[current_token_idx]
    current_token_idx = current_token_idx + 1
    return token
  end
  
  local function match(type)
    local token = peek()
    if token and token.type == type then
      return consume()
    end
    return nil
  end
  
  local function expect(type)
    local token = match(type)
    if token then
      return token
    end
    error("Expected token of type " .. type .. " but got " .. (peek() and peek().type or "EOF"))
  end
  
  -- 前方宣言
  local parse_expr, parse_stmt, parse_block
  
  -- 式の解析
  parse_expr = function()
    local token = peek()
    
    if not token then
      return nil
    end
    
    -- 基本的な式の解析
    if token.type == "identifier" then
      consume()
      local var_node = {
        type = M.NODE_TYPES.VARIABLE,
        name = token.value,
        pos = {line = token.line, col = token.col}
      }
      
      -- 関数呼び出しかインデックスアクセスのチェック
      local next_token = peek()
      if next_token then
        if next_token.value == "(" then
          -- 関数呼び出し
          consume() -- '('を消費
          local args = {}
          
          -- 引数がない場合
          if peek() and peek().value == ")" then
            consume()
          else
            -- 引数リストの解析
            while true do
              local arg = parse_expr()
              if arg then
                table.insert(args, arg)
              end
              
              if peek() and peek().value == "," then
                consume()
              else
                break
              end
            end
            
            expect("paren") -- ')'を期待
          end
          
          return {
            type = M.NODE_TYPES.CALL,
            func = var_node,
            args = args,
            pos = {line = token.line, col = token.col}
          }
        elseif next_token.value == "." or next_token.value == "[" then
          -- テーブルインデックスアクセス
          local base = var_node
          
          while peek() and (peek().value == "." or peek().value == "[") do
            if peek().value == "." then
              consume() -- '.'を消費
              local key = expect("identifier")
              base = {
                type = M.NODE_TYPES.INDEX,
                table = base,
                key = {
                  type = M.NODE_TYPES.LITERAL,
                  value = key.value,
                  raw = '"' .. key.value .. '"',
                  pos = {line = key.line, col = key.col}
                },
                pos = {line = token.line, col = token.col}
              }
            else -- '['の場合
              consume() -- '['を消費
              local key = parse_expr()
              expect("bracket") -- ']'を期待
              
              base = {
                type = M.NODE_TYPES.INDEX,
                table = base,
                key = key,
                pos = {line = token.line, col = token.col}
              }
            end
            
            -- 関数呼び出しのチェック
            if peek() and peek().value == "(" then
              consume() -- '('を消費
              local args = {}
              
              -- 引数がない場合
              if peek() and peek().value == ")" then
                consume()
              else
                -- 引数リストの解析
                while true do
                  local arg = parse_expr()
                  if arg then
                    table.insert(args, arg)
                  end
                  
                  if peek() and peek().value == "," then
                    consume()
                  else
                    break
                  end
                end
                
                expect("paren") -- ')'を期待
              end
              
              base = {
                type = M.NODE_TYPES.CALL,
                func = base,
                args = args,
                pos = {line = token.line, col = token.col}
              }
            end
          end
          
          return base
        end
      end
      
      return var_node
    elseif token.type == "string" or token.type == "number" or token.type == "boolean" or token.type == "nil" then
      consume()
      return {
        type = M.NODE_TYPES.LITERAL,
        value = token.value,
        raw = token.value,
        pos = {line = token.line, col = token.col}
      }
    elseif token.value == "{" then
      -- テーブル構造
      consume() -- '{'を消費
      local fields = {}
      
      -- 空のテーブル
      if peek() and peek().value == "}" then
        consume()
        return {
          type = M.NODE_TYPES.TABLE,
          fields = fields,
          pos = {line = token.line, col = token.col}
        }
      end
      
      -- テーブルの内容を解析
      while true do
        -- キー = 値 形式
        if peek() and peek().type == "identifier" and peek(2) and peek(2).value == "=" then
          local key = consume()
          consume() -- '='を消費
          local value = parse_expr()
          
          table.insert(fields, {
            key = {
              type = M.NODE_TYPES.LITERAL,
              value = key.value,
              raw = '"' .. key.value .. '"',
              pos = {line = key.line, col = key.col}
            },
            value = value
          })
        -- [式] = 値 形式
        elseif peek() and peek().value == "[" then
          consume() -- '['を消費
          local key = parse_expr()
          expect("bracket") -- ']'を期待
          expect("operator") -- '='を期待
          local value = parse_expr()
          
          table.insert(fields, {
            key = key,
            value = value
          })
        -- 値のみ形式
        else
          local value = parse_expr()
          if value then
            table.insert(fields, {
              value = value
            })
          end
        end
        
        if peek() and (peek().value == "," or peek().value == ";") then
          consume()
        else
          break
        end
      end
      
      expect("brace") -- '}'を期待
      
      return {
        type = M.NODE_TYPES.TABLE,
        fields = fields,
        pos = {line = token.line, col = token.col}
      }
    end
    
    -- その他の式は簡易的に処理（実際のパーサーではより詳細に解析）
    return nil
  end
  
  -- 文の解析
  parse_stmt = function()
    local token = peek()
    
    if not token then
      return nil
    end
    
    -- ローカル変数宣言
    if token.type == "keyword" and token.value == "local" then
      consume() -- 'local'を消費
      
      -- local function の場合
      if peek() and peek().type == "keyword" and peek().value == "function" then
        consume() -- 'function'を消費
        local name = expect("identifier")
        
        -- 関数パラメータの解析
        expect("paren") -- '('を期待
        local params = {}
        
        if peek() and peek().value ~= ")" then
          while true do
            local param = expect("identifier")
            table.insert(params, param.value)
            
            if peek() and peek().value == "," then
              consume()
            else
              break
            end
          end
        end
        
        expect("paren") -- ')'を期待
        
        -- 関数本体の解析
        local body = parse_block()
        expect("keyword") -- 'end'を期待
        
        return {
          type = M.NODE_TYPES.FUNCTION,
          name = name.value,
          params = params,
          body = body,
          local_decl = true,
          pos = {line = token.line, col = token.col}
        }
      else
        -- 通常のローカル変数宣言
        local names = {}
        local values = {}
        
        -- 変数名リストの解析
        while true do
          local name = expect("identifier")
          table.insert(names, name.value)
          
          if peek() and peek().value == "," then
            consume()
          else
            break
          end
        end
        
        -- 初期値があれば解析
        if peek() and peek().value == "=" then
          consume() -- '='を消費
          
          -- 式リストの解析
          while true do
            local value = parse_expr()
            table.insert(values, value)
            
            if peek() and peek().value == "," then
              consume()
            else
              break
            end
          end
        end
        
        return {
          type = M.NODE_TYPES.LOCAL,
          names = names,
          values = values,
          pos = {line = token.line, col = token.col}
        }
      end
    -- 代入文
    elseif token.type == "identifier" then
      local var_expr = parse_expr()
      
      if peek() and peek().value == "=" then
        consume() -- '='を消費
        
        local values = {}
        -- 式リストの解析
        while true do
          local value = parse_expr()
          table.insert(values, value)
          
          if peek() and peek().value == "," then
            consume()
          else
            break
          end
        end
        
        return {
          type = M.NODE_TYPES.ASSIGNMENT,
          targets = {var_expr},
          values = values,
          pos = var_expr.pos
        }
      else
        -- 式文（関数呼び出しなど）
        return var_expr
      end
    -- 関数定義
    elseif token.type == "keyword" and token.value == "function" then
      consume() -- 'function'を消費
      local name_parts = {}
      
      -- 関数名の解析（ドット記法とコロン記法に対応）
      local first_name = expect("identifier")
      table.insert(name_parts, first_name.value)
      
      while peek() and (peek().value == "." or peek().value == ":") then
        local separator = consume().value
        local name_part = expect("identifier")
        table.insert(name_parts, {separator = separator, name = name_part.value})
      end
      
      -- 関数パラメータの解析
      expect("paren") -- '('を期待
      local params = {}
      
      if peek() and peek().value ~= ")" then
        while true do
          local param = expect("identifier")
          table.insert(params, param.value)
          
          if peek() and peek().value == "," then
            consume()
          else
            break
          end
        end
      end
      
      expect("paren") -- ')'を期待
      
      -- 関数本体の解析
      local body = parse_block()
      expect("keyword") -- 'end'を期待
      
      return {
        type = M.NODE_TYPES.FUNCTION,
        name_parts = name_parts,
        params = params,
        body = body,
        local_decl = false,
        pos = {line = token.line, col = token.col}
      }
    -- return文
    elseif token.type == "keyword" and token.value == "return" then
      consume() -- 'return'を消費
      
      local values = {}
      
      -- 空のreturn
      if not peek() or peek().value == "end" or peek().type == "eof" then
        return {
          type = M.NODE_TYPES.RETURN,
          values = values,
          pos = {line = token.line, col = token.col}
        }
      end
      
      -- 式リストの解析
      while true do
        local value = parse_expr()
        if value then
          table.insert(values, value)
        end
        
        if peek() and peek().value == "," then
          consume()
        else
          break
        end
      end
      
      return {
        type = M.NODE_TYPES.RETURN,
        values = values,
        pos = {line = token.line, col = token.col}
      }
    end
    
    -- その他の文は簡易的に処理（実際のパーサーではより詳細に解析）
    return nil
  end
  
  -- ブロックの解析
  parse_block = function()
    local stmts = {}
    
    while peek() and peek().value ~= "end" do
      local stmt = parse_stmt()
      if stmt then
        table.insert(stmts, stmt)
      else
        -- 解析できない文の場合は次のトークンへ
        if current_token_idx <= #tokens then
          consume()
        else
          break
        end
      end
    end
    
    return {
      type = M.NODE_TYPES.BLOCK,
      body = stmts
    }
  }
  
  -- AST生成
  local ast = parse_block()
  
  return ast
end

-- AST内でノードを再帰的に探索する関数
function M.find_nodes(ast, node_type)
  local results = {}
  
  local function traverse(node)
    if not node or type(node) ~= "table" then
      return
    end
    
    if node.type == node_type then
      table.insert(results, node)
    end
    
    -- 子ノードの再帰的探索
    for _, child in pairs(node) do
      if type(child) == "table" then
        if child.type then
          traverse(child)
        elseif #child > 0 then
          -- 配列の場合
          for _, item in ipairs(child) do
            if type(item) == "table" then
              traverse(item)
            end
          end
        end
      end
    end
  end
  
  traverse(ast)
  return results
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
      -- テーブルメソッドの場合
      elseif func.type == M.NODE_TYPES.INDEX then
        -- 最終的なメソッド名を取得
        if func.key and func.key.type == M.NODE_TYPES.LITERAL and func.key.value == function_name then
          table.insert(results, node)
        end
      end
    end
    
    -- 子ノードの再帰的探索
    for _, child in pairs(node) do
      if type(child) == "table" then
        if child.type then
          traverse(child)
        elseif #child > 0 then
          -- 配列の場合
          for _, item in ipairs(child) do
            if type(item) == "table" then
              traverse(item)
            end
          end
        end
      end
    end
  end
  
  traverse(ast)
  return results
end

-- 特定のメソッド呼び出しを探す
function M.find_method_calls(ast, table_name, method_name)
  local results = {}
  
  local function traverse(node)
    if not node or type(node) ~= "table" then
      return
    end
    
    if node.type == M.NODE_TYPES.CALL then
      local func = node.func
      
      -- テーブルメソッドの場合
      if func.type == M.NODE_TYPES.INDEX then
        local base = func.table
        local key = func.key
        
        -- テーブル名とメソッド名を確認
        if base.type == M.NODE_TYPES.VARIABLE and base.name == table_name and
           key.type == M.NODE_TYPES.LITERAL and key.value == method_name then
          table.insert(results, node)
        end
      end
    end
    
    -- 子ノードの再帰的探索
    for _, child in pairs(node) do
      if type(child) == "table" then
        if child.type then
          traverse(child)
        elseif #child > 0 then
          -- 配列の場合
          for _, item in ipairs(child) do
            if type(item) == "table" then
              traverse(item)
            end
          end
        end
      end
    end
  end
  
  traverse(ast)
  return results
end

-- ノードの位置情報を取得する関数
function M.get_node_location(node)
  if node and node.pos then
    return node.pos.line, node.pos.col
  end
  return nil, nil
end

-- AST解析エンジンの主要関数
function M.parse_code(code, options)
  options = vim.tbl_deep_extend("force", default_options, options or {})
  
  -- 実際のASTパーサーライブラリがある場合はそれを使用
  -- 現在はシンプルな実装を使用
  
  -- コードの字句解析
  local tokens = create_lexer(code)
  
  -- 構文解析
  local ast = parse_tokens(tokens)
  
  return ast
end

-- セキュリティ問題を検出する関数
function M.detect_security_issues(ast, patterns)
  local issues = {}
  
  -- 関数呼び出しの検査
  for _, pattern in ipairs(patterns.system_execution or {}) do
    local parts = vim.split(pattern.pattern, "%.", true)
    
    if #parts == 1 then
      -- 単純な関数呼び出し (例: os.execute)
      local calls = M.find_function_calls(ast, parts[1])
      
      for _, call in ipairs(calls) do
        local line, col = M.get_node_location(call)
        
        table.insert(issues, {
          pattern = pattern.pattern,
          risk = pattern.risk,
          description = pattern.description,
          line = line,
          col = col,
          node = call
        })
      end
    elseif #parts == 2 then
      -- テーブルメソッド呼び出し (例: os.execute)
      local calls = M.find_method_calls(ast, parts[1], parts[2])
      
      for _, call in ipairs(calls) do
        local line, col = M.get_node_location(call)
        
        table.insert(issues, {
          pattern = pattern.pattern,
          risk = pattern.risk,
          description = pattern.description,
          line = line,
          col = col,
          node = call
        })
      end
    end
  end
  
  -- 他のパターンカテゴリに対しても同様の処理
  -- ...
  
  return issues
end

-- セキュリティ解析を実行する関数
function M.analyze_code(code, patterns, options)
  options = options or {}
  
  -- コードのパース
  local ast = M.parse_code(code, options)
  
  -- セキュリティ問題の検出
  local issues = M.detect_security_issues(ast, patterns)
  
  return issues, ast
end

-- ASTをJSON形式で出力する関数（デバッグ用）
function M.ast_to_json(ast)
  local json = vim.json.encode(ast)
  return json
end

return M
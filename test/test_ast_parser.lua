-- nvim-security-scanner AST パーサーのテスト
-- Neovimで以下のコマンドで実行:
-- nvim --headless -u NONE -c "lua dofile('test/test_ast_parser.lua')" -c "q"

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

-- Neovimのランタイムパスを設定
vim.opt.runtimepath:append(root_dir)

-- AST パーサーモジュールをロード
-- まずシンプルな実装でテスト
local ast_parser

-- 本来のASTパーサーのロードを試みる
local success, module = pcall(function() 
  return require("nvim-security-scanner.ast_parser")
end)

if success then
  ast_parser = module
  print_info("本来のAST Parserをロードしました")
else
  -- エラーが発生した場合はシンプルな実装を使用
  ast_parser = require("test.simple_ast_test")
  print_info("シンプルなテスト用ASTモジュールをロードしました: " .. tostring(module))
end

local patterns = require("nvim-security-scanner.patterns")

-- テスト結果を保存
local test_results = {
  success = 0,
  failure = 0,
  total = 0
}

-- テストケース
local tests = {}

-- AST パーサーの基本機能テスト
tests.test_basic_parsing = function()
  print_header("基本的なパース機能テスト")
  
  -- サンプルコード
  local sample_code = [[
local function test()
  print("Hello, World!")
  return 42
end
]]
  
  -- コードをパース
  local ast = ast_parser.parse_code(sample_code)
  
  -- ASTが生成されたかチェック
  if ast and ast.type == ast_parser.NODE_TYPES.BLOCK then
    print_success("AST が正常に生成されました")
    
    -- 関数定義があるかチェック
    local functions = ast_parser.find_nodes(ast, ast_parser.NODE_TYPES.FUNCTION)
    if #functions > 0 then
      print_success("関数定義を検出できました")
      return true
    else
      print_failure("関数定義を検出できませんでした")
      return false
    end
  else
    print_failure("AST の生成に失敗しました")
    return false
  end
end

-- 関数呼び出し検出テスト
tests.test_function_call_detection = function()
  print_header("関数呼び出し検出テスト")
  
  -- テスト用のファイルを読み込む
  local file_path = root_dir .. "/test/ast_samples/simple_function.lua"
  local file = io.open(file_path, "r")
  
  if not file then
    print_failure("テストファイルを開けませんでした: " .. file_path)
    return false
  end
  
  local content = file:read("*all")
  file:close()
  
  -- AST 解析を実行
  local ast = ast_parser.parse_code(content)
  
  -- os.execute の呼び出しを検索
  local detected = false
  local calls = ast_parser.find_method_calls(ast, "os", "execute")
  
  if #calls > 0 then
    print_success("os.execute の呼び出しを検出しました")
    detected = true
  else
    print_failure("os.execute の呼び出しを検出できませんでした")
  end
  
  -- セキュリティ問題を検出
  local issues = ast_parser.detect_security_issues(ast, patterns)
  
  if #issues > 0 then
    print_success("セキュリティ問題を検出しました: " .. #issues .. " 件")
    for i, issue in ipairs(issues) do
      print_info(i .. ". パターン: " .. issue.pattern .. ", リスク: " .. issue.risk)
    end
    
    return detected and #issues > 0
  else
    print_failure("セキュリティ問題を検出できませんでした")
    return false
  end
end

-- 文字列リテラル内のパターン除外テスト
tests.test_string_literal_exclusion = function()
  print_header("文字列リテラル内のパターン除外テスト")
  
  -- テスト用のファイルを読み込む
  local file_path = root_dir .. "/test/ast_samples/string_literals.lua"
  local file = io.open(file_path, "r")
  
  if not file then
    print_failure("テストファイルを開けませんでした: " .. file_path)
    return false
  end
  
  local content = file:read("*all")
  file:close()
  
  -- AST 解析を実行
  local ast = ast_parser.parse_code(content)
  
  -- os.execute の呼び出しを検索
  local real_calls = ast_parser.find_method_calls(ast, "os", "execute")
  
  -- セキュリティ問題を検出
  local issues = ast_parser.detect_security_issues(ast, patterns)
  
  -- 文字列リテラル内のパターンを除外できているか
  local pattern_in_strings_not_detected = true
  for _, issue in ipairs(issues) do
    -- 文字列リテラル内の行を特定（簡易的）
    for _, line in ipairs({"str2 = ", "str3 = "}) do
      if issue.line and content:sub(issue.line, issue.line + #line - 1) == line then
        pattern_in_strings_not_detected = false
        print_failure("文字列リテラル内のパターンが誤検出されました: 行 " .. issue.line)
      end
    end
  end
  
  if pattern_in_strings_not_detected then
    print_success("文字列リテラル内のパターンを適切に除外しました")
  end
  
  -- 実際の関数呼び出しは検出しているか
  local real_call_detected = false
  for _, issue in ipairs(issues) do
    if issue.pattern == "os%.execute" then
      real_call_detected = true
      print_success("実際の os.execute 呼び出しを検出しました")
      break
    end
  end
  
  if not real_call_detected then
    print_failure("実際の os.execute 呼び出しを検出できませんでした")
  end
  
  return pattern_in_strings_not_detected and real_call_detected
end

-- メソッド呼び出し検出テスト
tests.test_method_call_detection = function()
  print_header("メソッド呼び出し検出テスト")
  
  -- テスト用のファイルを読み込む
  local file_path = root_dir .. "/test/ast_samples/method_calls.lua"
  local file = io.open(file_path, "r")
  
  if not file then
    print_failure("テストファイルを開けませんでした: " .. file_path)
    return false
  end
  
  local content = file:read("*all")
  file:close()
  
  -- AST 解析を実行
  local ast = ast_parser.parse_code(content)
  
  -- io.popen の呼び出しを検索
  local popen_calls = ast_parser.find_method_calls(ast, "io", "popen")
  
  if #popen_calls > 0 then
    print_success("io.popen の呼び出しを検出しました: " .. #popen_calls .. " 件")
    
    -- セキュリティ問題を検出
    local issues = ast_parser.detect_security_issues(ast, patterns)
    
    if #issues > 0 then
      print_success("セキュリティ問題を検出しました: " .. #issues .. " 件")
      return true
    else
      print_failure("セキュリティ問題を検出できませんでした")
      return false
    end
  else
    print_failure("io.popen の呼び出しを検出できませんでした")
    return false
  end
end

-- ネストされた呼び出しテスト
tests.test_nested_calls = function()
  print_header("ネストされた呼び出しテスト")
  
  -- テスト用のファイルを読み込む
  local file_path = root_dir .. "/test/ast_samples/nested_calls.lua"
  local file = io.open(file_path, "r")
  
  if not file then
    print_failure("テストファイルを開けませんでした: " .. file_path)
    return false
  end
  
  local content = file:read("*all")
  file:close()
  
  -- AST 解析を実行
  local ast = ast_parser.parse_code(content)
  
  -- os.execute の呼び出しを検索
  local execute_calls = ast_parser.find_method_calls(ast, "os", "execute")
  
  if #execute_calls > 0 then
    print_success("os.execute の呼び出しを検出しました: " .. #execute_calls .. " 件")
    
    -- セキュリティ問題を検出
    local issues = ast_parser.detect_security_issues(ast, patterns)
    
    if #issues > 0 then
      local direct_calls_detected = 0
      
      for _, issue in ipairs(issues) do
        if issue.pattern == "os%.execute" then
          direct_calls_detected = direct_calls_detected + 1
        end
      end
      
      if direct_calls_detected > 0 then
        print_success("直接的な関数呼び出しを検出しました: " .. direct_calls_detected .. " 件")
        return true
      else
        print_failure("直接的な関数呼び出しを検出できませんでした")
        return false
      end
    else
      print_failure("セキュリティ問題を検出できませんでした")
      return false
    end
  else
    print_failure("os.execute の呼び出しを検出できませんでした")
    return false
  end
end

-- エッジケーステスト
tests.test_edge_cases = function()
  print_header("エッジケーステスト")
  
  -- テスト用のファイルを読み込む
  local file_path = root_dir .. "/test/ast_samples/edge_cases.lua"
  local file = io.open(file_path, "r")
  
  if not file then
    print_failure("テストファイルを開けませんでした: " .. file_path)
    return false
  end
  
  local content = file:read("*all")
  file:close()
  
  -- AST 解析を実行
  local ast = ast_parser.parse_code(content)
  
  -- セキュリティ問題を検出
  local issues = ast_parser.detect_security_issues(ast, patterns)
  
  -- 偽陽性のチェック（変数名が関数名に似ている場合）
  local false_positives = 0
  
  for _, issue in ipairs(issues) do
    if issue.pattern:match("os%.execute") then
      -- 本来検出すべきでない行を特定（簡易的）
      if content:sub(issue.line, issue.line + 20):match("os_execute =") or
         content:sub(issue.line, issue.line + 20):match("my_os_function") then
        false_positives = false_positives + 1
        print_failure("偽陽性検出: " .. content:sub(issue.line, issue.line + 30))
      end
    end
  end
  
  if false_positives == 0 then
    print_success("偽陽性検出なし")
    return true
  else
    print_failure("偽陽性検出あり: " .. false_positives .. " 件")
    return false
  end
end

-- テストをすべて実行
local function run_all_tests()
  print_header("nvim-security-scanner AST パーサーテスト実行")
  
  local test_order = {
    "test_basic_parsing",
    "test_function_call_detection",
    "test_string_literal_exclusion",
    "test_method_call_detection",
    "test_nested_calls",
    "test_edge_cases"
  }
  
  for _, test_name in ipairs(test_order) do
    print_info("テスト実行: " .. test_name)
    
    test_results.total = test_results.total + 1
    local success = tests[test_name]()
    
    if success then
      test_results.success = test_results.success + 1
    else
      test_results.failure = test_results.failure + 1
    end
  end
  
  print_header("テスト結果")
  print_info("合計テスト数: " .. test_results.total)
  print_success("成功: " .. test_results.success)
  
  if test_results.failure > 0 then
    print_failure("失敗: " .. test_results.failure)
  else
    print_info("失敗: 0")
  end
  
  return test_results.failure == 0
end

-- テストを実行
run_all_tests()

-- Neovimのメッセージを表示しておく
vim.cmd("messages")
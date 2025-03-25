local M = {}
local patterns = require("nvim-security-scanner.patterns")
local config -- 後で初期化する
local ast_parser -- ASTパーサーモジュール（遅延ロード）
local report_module -- レポートモジュール（遅延ロード）

-- ASTパーサーモジュールを遅延ロードする関数
local function load_ast_parser()
  if not ast_parser then
    ast_parser = require("nvim-security-scanner.ast_parser")
  end
  return ast_parser
end

-- レポートモジュールを遅延ロードする関数
local function load_report()
  if not report_module then
    report_module = require("nvim-security-scanner.report")
  end
  return report_module
end

-- プラグインのディレクトリパスを取得
local function get_plugin_dir(plugin_name)
  -- Neovimのランタイムパスから検索
  local rtp = vim.opt.runtimepath:get()
  for _, path in ipairs(rtp) do
    local plugin_path = path .. "/" .. plugin_name
    if vim.fn.isdirectory(plugin_path) == 1 then
      return plugin_path
    end
  end
  
  -- lazy.nvimのディレクトリ構造から検索
  local lazy_path = vim.fn.stdpath("data") .. "/lazy/"
  local lazy_plugin_path = lazy_path .. plugin_name
  if vim.fn.isdirectory(lazy_plugin_path) == 1 then
    return lazy_plugin_path
  end
  
  -- packer.nvimのディレクトリ構造から検索
  local packer_path = vim.fn.stdpath("data") .. "/site/pack/packer/start/"
  local packer_plugin_path = packer_path .. plugin_name
  if vim.fn.isdirectory(packer_plugin_path) == 1 then
    return packer_plugin_path
  end
  
  return nil
end

-- ディレクトリから.luaファイルを再帰的に収集
local function collect_lua_files(dir)
  local files = {}
  local exclude_pattern = ""
  
  -- 除外パスのパターンを構築
  if config and config.exclude_paths and #config.exclude_paths > 0 then
    exclude_pattern = table.concat(config.exclude_paths, "|")
  end
  
  -- ファイルを収集するための再帰関数
  local function collect_files(path)
    local items = vim.fn.readdir(path)
    for _, item in ipairs(items) do
      local full_path = path .. "/" .. item
      
      -- ディレクトリの場合は再帰
      if vim.fn.isdirectory(full_path) == 1 then
        -- 除外パスチェック
        local should_exclude = false
        if exclude_pattern ~= "" and config and config.exclude_paths then
          for _, exclude in ipairs(config.exclude_paths) do
            if full_path:match(exclude) then
              should_exclude = true
              break
            end
          end
        end
        
        if not should_exclude then
          collect_files(full_path)
        end
      else
        -- .luaファイルを追加
        if item:match("%.lua$") then
          table.insert(files, full_path)
        end
      end
    end
  end
  
  collect_files(dir)
  return files
end

-- 初期化機能を追加
function M.init(user_config)
  config = user_config
end

-- ファイルをスキャンして危険なパターンを検出
local function scan_file(file_path)
  local findings = {}
  
  -- ファイルの内容を読み込む
  local content = vim.fn.readfile(file_path)
  if not content or #content == 0 then
    return findings
  end
  
  -- 設定が初期化されていない場合はデフォルト値を使用
  local risk_threshold = config and config.risk_threshold or "medium"
  
  -- 有効なパターンを取得
  local active_patterns = patterns.get_patterns_by_risk(risk_threshold)
  
  -- ファイル内容を文字列に変換
  local content_str = table.concat(content, "\n")
  local ast_issues = {}
  
  -- ASTベースの解析を実行（設定されている場合）
  local use_ast = config and config.advanced_scan and config.advanced_scan.use_ast_parser
  if use_ast then
    local parser = load_ast_parser()
    
    -- ASTパーサーを使用して解析を試みる
    local success, ast_results = pcall(function()
      return parser.analyze_code(content_str, patterns)
    end)
    
    if success and ast_results then
      ast_issues = ast_results
      
      -- 開発者向けの通知
      if config and config.debug_mode then
        vim.notify("AST解析が成功しました: " .. #ast_issues .. " 件のセキュリティリスクを検出", vim.log.levels.DEBUG)
      end
    else
      -- パース失敗時のエラーログ（デバッグ用）
      if config and config.debug_mode then
        vim.notify("AST解析中にエラーが発生しました: " .. (ast_results or "不明なエラー"), vim.log.levels.DEBUG)
      end
      
      -- 実験的機能なので、エラーがあっても通常の解析は継続する
      if not config or not config.debug_mode then
        vim.notify("AST解析機能は現在実験段階です。問題が発生した場合は、詳細ログを確認するためにdebug_modeを有効にしてください。", vim.log.levels.INFO)
      end
    end
  end
  
  -- 既存のパターンマッチング解析
  -- 各行に対してパターンマッチング
  for line_num, line in ipairs(content) do
    for _, pattern_info in ipairs(active_patterns) do
      local ignored = false
      
      -- 無視するパターンチェック
      if config and config.ignore_patterns and #config.ignore_patterns > 0 then
        for _, ignore_pattern in ipairs(config.ignore_patterns) do
          if pattern_info.pattern == ignore_pattern then
            ignored = true
            break
          end
        end
      end
      
      if not ignored and line:match(pattern_info.pattern) then
        -- コメント行の場合はスキップ（単純なヒューリスティック）
        if not line:match("^%s*%-%-") then
          local should_record = true
          
          -- コンテキスト認識機能が有効な場合
          if config and config.advanced_scan and config.advanced_scan.context_awareness then
            -- 文字列リテラル内かをチェック
            local in_string = false
            local prev_chars = ""
            
            -- 文字列リテラルチェックが有効な場合のみ実行
            if not config.advanced_scan.check_string_literals then
              -- 行の先頭から現在位置までを調べて文字列リテラル内かを判定
              for i = 1, #line do
                local char = line:sub(i, i)
                if char == '"' or char == "'" then
                  -- エスケープされていない引用符ならトグル
                  if prev_chars:sub(-1) ~= "\\" then
                    in_string = not in_string
                  end
                end
                
                prev_chars = prev_chars .. char
                
                -- パターンのマッチ位置まで到達したらチェック終了
                if i == string.find(line, pattern_info.pattern) then
                  break
                end
              end
              
              -- 文字列リテラル内の場合はスキップ
              if in_string then
                should_record = false
              end
            end
          end
          
          -- 記録条件を満たす場合に記録
          if should_record then
            -- 見つかった情報を記録
            table.insert(findings, {
              file = file_path,
              line = line_num,
              line_content = line,
              pattern = pattern_info.pattern,
              category = pattern_info.category,
              risk = pattern_info.risk,
              description = pattern_info.description,
              legitimate_uses = pattern_info.legitimate_uses,
              detection_type = "pattern"
            })
          end
        end
      end
    end
  end
  
  -- ASTベースの解析結果を追加
  for _, issue in ipairs(ast_issues) do
    if issue.line then
      -- 行番号が取得できている場合
      local line_content = ""
      if issue.line <= #content then
        line_content = content[issue.line]
      end
      
      -- 重複チェック
      local is_duplicate = false
      for _, finding in ipairs(findings) do
        if finding.line == issue.line and finding.pattern == issue.pattern then
          is_duplicate = true
          break
        end
      end
      
      if not is_duplicate then
        table.insert(findings, {
          file = file_path,
          line = issue.line,
          line_content = line_content,
          pattern = issue.pattern,
          category = issue.category,
          risk = issue.risk,
          description = issue.description,
          legitimate_uses = issue.legitimate_uses or "不明",
          detection_type = "ast"
        })
      end
    end
  end
  
  -- 行番号順にソート
  table.sort(findings, function(a, b)
    return a.line < b.line
  end)
  
  return findings
end

-- 特定のプラグインをスキャン
function M.scan_plugin(plugin_name_or_dir)
  local plugin_dir
  
  -- 入力がディレクトリパスかプラグイン名かを判断
  if vim.fn.isdirectory(plugin_name_or_dir) == 1 then
    plugin_dir = plugin_name_or_dir
  else
    plugin_dir = get_plugin_dir(plugin_name_or_dir)
  end
  
  if not plugin_dir then
    vim.notify("プラグイン " .. plugin_name_or_dir .. " が見つかりませんでした", vim.log.levels.ERROR)
    return {}
  end
  
  -- プラグインのLuaファイルを収集
  local files = collect_lua_files(plugin_dir)
  local all_findings = {}
  
  -- 各ファイルをスキャン
  for _, file in ipairs(files) do
    local findings = scan_file(file)
    for _, finding in ipairs(findings) do
      table.insert(all_findings, finding)
    end
  end
  
  -- スキャン結果を保存
  local plugin_name = vim.fn.fnamemodify(plugin_dir, ":t")
  local report = load_report()
  report.save_report(plugin_name, all_findings)
  
  -- 結果を表示
  if #all_findings > 0 then
    vim.notify("プラグイン " .. plugin_name .. " で " .. #all_findings .. 
              " 件のセキュリティリスクが検出されました。詳細は :SecurityReport で確認してください", 
              vim.log.levels.WARN)
  else
    vim.notify("プラグイン " .. plugin_name .. " でセキュリティリスクは検出されませんでした", 
              vim.log.levels.INFO)
  end
  
  return all_findings
end

-- すべてのプラグインをスキャン
function M.scan_all_plugins()
  local plugins = {}
  
  -- lazy.nvimのプラグインを検索
  local lazy_path = vim.fn.stdpath("data") .. "/lazy/"
  if vim.fn.isdirectory(lazy_path) == 1 then
    local lazy_plugins = vim.fn.readdir(lazy_path)
    for _, plugin in ipairs(lazy_plugins) do
      table.insert(plugins, lazy_path .. plugin)
    end
  end
  
  -- packer.nvimのプラグインを検索
  local packer_path = vim.fn.stdpath("data") .. "/site/pack/packer/start/"
  if vim.fn.isdirectory(packer_path) == 1 then
    local packer_plugins = vim.fn.readdir(packer_path)
    for _, plugin in ipairs(packer_plugins) do
      table.insert(plugins, packer_path .. plugin)
    end
  end
  
  -- すべてのプラグインをスキャン
  local total_findings = 0
  local risky_plugins = {}
  
  for _, plugin_dir in ipairs(plugins) do
    local findings = M.scan_plugin(plugin_dir)
    if #findings > 0 then
      total_findings = total_findings + #findings
      table.insert(risky_plugins, vim.fn.fnamemodify(plugin_dir, ":t"))
    end
  end
  
  -- 結果のサマリーを表示
  if total_findings > 0 then
    vim.notify("スキャン完了: " .. #plugins .. " プラグイン中 " .. #risky_plugins .. 
              " プラグインで合計 " .. total_findings .. " 件のセキュリティリスクが検出されました。",
              vim.log.levels.WARN)
  else
    vim.notify("スキャン完了: " .. #plugins .. " プラグインすべてでセキュリティリスクは検出されませんでした。",
              vim.log.levels.INFO)
  end
end

return M
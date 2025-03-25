local M = {}
local patterns = require("nvim-security-scanner.patterns")
local config = require("nvim-security-scanner").config
local report = require("nvim-security-scanner.report")

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
  if config.exclude_paths and #config.exclude_paths > 0 then
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
        if exclude_pattern ~= "" then
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

-- ファイルをスキャンして危険なパターンを検出
local function scan_file(file_path)
  local findings = {}
  
  -- ファイルの内容を読み込む
  local content = vim.fn.readfile(file_path)
  if not content or #content == 0 then
    return findings
  end
  
  -- 有効なパターンを取得
  local active_patterns = patterns.get_patterns_by_risk(config.risk_threshold)
  
  -- 各行に対してパターンマッチング
  for line_num, line in ipairs(content) do
    for _, pattern_info in ipairs(active_patterns) do
      local ignored = false
      
      -- 無視するパターンチェック
      if config.ignore_patterns and #config.ignore_patterns > 0 then
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
          -- 見つかった情報を記録
          table.insert(findings, {
            file = file_path,
            line = line_num,
            line_content = line,
            pattern = pattern_info.pattern,
            category = pattern_info.category,
            risk = pattern_info.risk,
            description = pattern_info.description,
            legitimate_uses = pattern_info.legitimate_uses
          })
        end
      end
    end
  end
  
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
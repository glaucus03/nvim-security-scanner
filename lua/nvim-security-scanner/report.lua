local M = {}

-- 最新のレポートデータ
local last_report = {
  plugin_name = "",
  findings = {},
  timestamp = 0
}

-- リスクレベルに応じたハイライトグループ
local risk_highlights = {
  low = "DiagnosticInfo",
  medium = "DiagnosticWarn",
  high = "DiagnosticError"
}

-- 結果を保存
function M.save_report(plugin_name, findings)
  last_report = {
    plugin_name = plugin_name,
    findings = findings,
    timestamp = os.time()
  }
end

-- 最新のレポートを表示
function M.show_last_report()
  if not last_report.plugin_name or #last_report.findings == 0 then
    vim.notify("利用可能なレポートがありません", vim.log.levels.INFO)
    return
  end
  
  -- 新しいバッファを作成
  local bufnr = vim.api.nvim_create_buf(false, true)
  vim.api.nvim_buf_set_option(bufnr, "buftype", "nofile")
  vim.api.nvim_buf_set_option(bufnr, "bufhidden", "wipe")
  vim.api.nvim_buf_set_option(bufnr, "modifiable", true)
  
  -- バッファの名前を設定
  local buf_name = "SecurityReport_" .. last_report.plugin_name
  vim.api.nvim_buf_set_name(bufnr, buf_name)
  
  -- レポートの内容を生成
  local lines = M.generate_report_content()
  
  -- バッファに内容を設定
  vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, lines)
  
  -- バッファを表示
  vim.cmd("vsplit")
  local win = vim.api.nvim_get_current_win()
  vim.api.nvim_win_set_buf(win, bufnr)
  
  -- シンタックスハイライトとフォールディングを設定
  M.setup_buffer_highlights(bufnr)
  M.setup_buffer_folding(bufnr)
  
  -- バッファを読み取り専用に設定
  vim.api.nvim_buf_set_option(bufnr, "modifiable", false)
  
  -- キーマッピングを設定
  M.setup_buffer_mappings(bufnr)
end

-- レポート内容を生成
function M.generate_report_content()
  local lines = {}
  local findings = last_report.findings
  
  -- タイトルとサマリー
  table.insert(lines, "# セキュリティスキャンレポート: " .. last_report.plugin_name)
  table.insert(lines, "")
  
  -- タイムスタンプ
  local date_str = os.date("%Y-%m-%d %H:%M:%S", last_report.timestamp)
  table.insert(lines, "スキャン日時: " .. date_str)
  table.insert(lines, "")
  
  -- リスクサマリー
  local risk_counts = { low = 0, medium = 0, high = 0 }
  local detection_counts = { pattern = 0, ast = 0 }
  
  for _, finding in ipairs(findings) do
    risk_counts[finding.risk] = (risk_counts[finding.risk] or 0) + 1
    detection_counts[finding.detection_type or "pattern"] = (detection_counts[finding.detection_type or "pattern"] or 0) + 1
  end
  
  table.insert(lines, "## サマリー")
  table.insert(lines, "")
  table.insert(lines, "検出されたリスク: " .. #findings .. "件")
  table.insert(lines, "- 高リスク (High): " .. risk_counts.high .. "件")
  table.insert(lines, "- 中リスク (Medium): " .. risk_counts.medium .. "件")
  table.insert(lines, "- 低リスク (Low): " .. risk_counts.low .. "件")
  table.insert(lines, "")
  
  -- 検出方法ごとのサマリー
  table.insert(lines, "### 検出方法")
  table.insert(lines, "")
  table.insert(lines, "- パターンマッチング: " .. (detection_counts.pattern or 0) .. "件")
  table.insert(lines, "- AST解析: " .. (detection_counts.ast or 0) .. "件")
  table.insert(lines, "")
  
  -- カテゴリ別サマリー
  local category_counts = {}
  for _, finding in ipairs(findings) do
    local category = finding.category or "その他"
    category_counts[category] = (category_counts[category] or 0) + 1
  end
  
  table.insert(lines, "### カテゴリ別")
  table.insert(lines, "")
  for category, count in pairs(category_counts) do
    table.insert(lines, "- " .. category .. ": " .. count .. "件")
  end
  table.insert(lines, "")
  
  -- 詳細セクション
  table.insert(lines, "## 詳細")
  table.insert(lines, "")
  
  -- ファイル別にグループ化
  local files = {}
  for _, finding in ipairs(findings) do
    local file = finding.file
    if not files[file] then
      files[file] = {}
    end
    table.insert(files[file], finding)
  end
  
  -- 各ファイルについての詳細を表示
  for file, file_findings in pairs(files) do
    local rel_path = vim.fn.fnamemodify(file, ":~:.")
    table.insert(lines, "### ファイル: " .. rel_path)
    table.insert(lines, "")
    
    for i, finding in ipairs(file_findings) do
      local risk_str = "["..string.upper(finding.risk).."]"
      local detection_type = finding.detection_type or "pattern"
      local detection_icon = ""
      
      if detection_type == "ast" then
        detection_icon = "[AST] "
      end
      
      table.insert(lines, i .. ". " .. detection_icon .. risk_str .. " 行 " .. finding.line .. ": " .. finding.pattern)
      table.insert(lines, "   コード: `" .. finding.line_content:gsub("^%s+", "") .. "`")
      table.insert(lines, "   説明: " .. finding.description)
      table.insert(lines, "   正当な使用例: " .. finding.legitimate_uses)
      
      -- AST検出の場合は追加情報
      if detection_type == "ast" then
        table.insert(lines, "   検出方法: AST解析（高精度）")
      end
      
      table.insert(lines, "")
    end
  end
  
  -- フッター
  table.insert(lines, "---")
  table.insert(lines, "レポート生成: nvim-security-scanner")
  
  return lines
end

-- バッファのハイライトを設定
function M.setup_buffer_highlights(bufnr)
  -- 基本的なマークダウンのシンタックスハイライト
  vim.cmd("syntax match SecurityReportHeading /^#.*/")
  vim.cmd("syntax match SecurityReportSubHeading /^##.*/")
  vim.cmd("syntax match SecurityReportSubSubHeading /^###.*/")
  vim.cmd("syntax match SecurityReportListItem /^\\s*-\\s.*/")
  vim.cmd("syntax match SecurityReportCode /`.*`/")
  
  -- リスクレベルのハイライト
  vim.cmd("syntax match SecurityReportRiskHigh /\\[HIGH\\]/")
  vim.cmd("syntax match SecurityReportRiskMedium /\\[MEDIUM\\]/")
  vim.cmd("syntax match SecurityReportRiskLow /\\[LOW\\]/")
  
  -- ハイライトグループのリンク
  vim.cmd("highlight link SecurityReportHeading Title")
  vim.cmd("highlight link SecurityReportSubHeading Statement")
  vim.cmd("highlight link SecurityReportSubSubHeading Identifier")
  vim.cmd("highlight link SecurityReportListItem Normal")
  vim.cmd("highlight link SecurityReportCode String")
  
  vim.cmd("highlight link SecurityReportRiskHigh DiagnosticError")
  vim.cmd("highlight link SecurityReportRiskMedium DiagnosticWarn")
  vim.cmd("highlight link SecurityReportRiskLow DiagnosticInfo")
end

-- バッファのフォールディングを設定
function M.setup_buffer_folding(bufnr)
  -- フォールディングを有効化
  vim.api.nvim_buf_set_option(bufnr, "foldmethod", "marker")
  vim.api.nvim_buf_set_option(bufnr, "foldmarker", "###,##")
  
  -- フォールディングの初期状態を設定
  vim.cmd("normal! zR")
end

-- バッファのキーマッピングを設定
function M.setup_buffer_mappings(bufnr)
  local opts = { noremap = true, silent = true }
  
  -- Neovim 0.7.0以降
  if vim.keymap and vim.keymap.set then
    -- 'q'でバッファを閉じる
    vim.keymap.set('n', 'q', ':close<CR>', { noremap = true, silent = true, buffer = bufnr })
    
    -- エンターキーでファイルを開く
    vim.keymap.set('n', '<CR>', ':lua require("nvim-security-scanner.report").open_file_at_line()<CR>', 
                   { noremap = true, silent = true, buffer = bufnr })
  else
    -- 旧バージョン用
    -- 'q'でバッファを閉じる
    vim.api.nvim_buf_set_keymap(bufnr, 'n', 'q', ':close<CR>', opts)
    
    -- エンターキーでファイルを開く
    vim.api.nvim_buf_set_keymap(bufnr, 'n', '<CR>', 
                               ':lua require("nvim-security-scanner.report").open_file_at_line()<CR>', opts)
  end
end

-- カーソル位置のファイルを開く
function M.open_file_at_line()
  local line = vim.api.nvim_get_current_line()
  
  -- ファイルパスと行番号を抽出
  local file_match = line:match("### ファイル: (.*)")
  if file_match then
    vim.cmd("normal! j")
    return
  end
  
  local line_match = line:match("%[.-%] 行 (%d+)")
  if line_match then
    -- 親の行を取得してファイル名を抽出
    local lnum = vim.api.nvim_win_get_cursor(0)[1]
    local i = lnum
    while i > 0 do
      local l = vim.api.nvim_buf_get_lines(0, i-1, i, false)[1]
      local file_path = l:match("### ファイル: (.*)")
      if file_path then
        vim.cmd("edit " .. file_path)
        vim.cmd(":" .. line_match)
        vim.cmd("normal! zz")
        return
      end
      i = i - 1
    end
  end
end

-- プラグイン更新時の確認ダイアログ
function M.confirmation_dialog(plugin_name, findings)
  if not findings or #findings == 0 then
    return true
  end
  
  -- 高リスクと中リスクの数を数える
  local high_risks = 0
  local medium_risks = 0
  
  for _, finding in ipairs(findings) do
    if finding.risk == "high" then
      high_risks = high_risks + 1
    elseif finding.risk == "medium" then
      medium_risks = medium_risks + 1
    end
  end
  
  -- メッセージを構築
  local msg = "セキュリティリスクが検出されました:\n\n"
  msg = msg .. "プラグイン: " .. plugin_name .. "\n"
  msg = msg .. "高リスク: " .. high_risks .. "件\n"
  msg = msg .. "中リスク: " .. medium_risks .. "件\n"
  msg = msg .. "合計: " .. #findings .. "件\n\n"
  msg = msg .. "詳細は :SecurityReport で確認できます。\n\n"
  msg = msg .. "このプラグインの更新を続行しますか？"
  
  -- 確認ダイアログを表示
  local choice = vim.fn.confirm(msg, "&Yes\n&No", 2)
  return choice == 1 -- 1=Yes, 2=No
end

return M
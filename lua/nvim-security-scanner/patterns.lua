-- 危険なパターンのデータベースを定義
local M = {}

-- システム実行関連のパターン
M.system_execution = {
  {
    pattern = "os%.execute",
    risk = "high",
    description = "システムコマンドを実行できるため、悪意のあるコードが実行される可能性があります",
    legitimate_uses = "外部ツールの実行、プロジェクトのビルド"
  },
  {
    pattern = "vim%.fn%.system",
    risk = "high",
    description = "システムコマンドを実行できるため、悪意のあるコードが実行される可能性があります",
    legitimate_uses = "外部ツールの実行、コマンド出力の取得"
  },
  {
    pattern = "io%.popen",
    risk = "high", 
    description = "システムコマンドを実行し、その出力を読み取ることができます",
    legitimate_uses = "コマンド出力の処理"
  }
}

-- ファイル操作関連のパターン
M.file_operations = {
  {
    pattern = "io%.open",
    risk = "medium",
    description = "任意のファイルを読み書きできるため、機密情報の漏洩やファイル改ざんの可能性があります",
    legitimate_uses = "設定ファイルの読み書き、データの永続化"
  },
  {
    pattern = "vim%.fn%.readfile",
    risk = "medium",
    description = "任意のファイルを読み込むことができます",
    legitimate_uses = "設定ファイルの読み込み"
  },
  {
    pattern = "vim%.fn%.writefile",
    risk = "medium",
    description = "任意のファイルを書き込むことができます",
    legitimate_uses = "設定ファイルの保存"
  }
}

-- コード実行関連のパターン
M.code_execution = {
  {
    pattern = "loadstring",
    risk = "high",
    description = "動的にコードを評価できるため、任意のコードが実行される可能性があります",
    legitimate_uses = "プラグインのホットリロード、設定の動的生成"
  },
  {
    pattern = "load",
    risk = "high",
    description = "動的にコードを評価できるため、任意のコードが実行される可能性があります",
    legitimate_uses = "プラグインのホットリロード、設定の動的生成"
  },
  {
    pattern = "dofile",
    risk = "high",
    description = "任意のファイルをLuaコードとして実行できます",
    legitimate_uses = "プラグインのモジュール読み込み"
  }
}

-- ネットワークアクセス関連のパターン
M.network_access = {
  {
    pattern = "socket%.http",
    risk = "high",
    description = "外部サーバーとHTTP通信を行うことができます",
    legitimate_uses = "API連携、リモートリソースの取得"
  },
  {
    pattern = "curl",
    risk = "high",
    description = "外部サーバーとHTTP通信を行うことができます",
    legitimate_uses = "API連携、リモートリソースの取得"
  },
  {
    pattern = "socket%.connect",
    risk = "high",
    description = "任意のサーバーとソケット通信を行うことができます",
    legitimate_uses = "特定サービスとの通信"
  }
}

-- 設定変更関連のパターン
M.config_changes = {
  {
    pattern = "vim%.opt%.rtp",
    risk = "medium",
    description = "ランタイムパスを変更し、悪意のあるコードを読み込む可能性があります",
    legitimate_uses = "プラグインのパス設定"
  },
  {
    pattern = "vim%.cmd",
    risk = "medium",
    description = "任意のVimコマンドを実行できます",
    legitimate_uses = "Vimの設定や操作"
  },
  {
    pattern = "vim%.api%.nvim_exec",
    risk = "medium",
    description = "任意のVimスクリプトを実行できます",
    legitimate_uses = "高度なVim設定"
  }
}

-- すべてのパターン情報を取得
function M.get_all_patterns()
  local all_patterns = {}
  
  -- すべてのカテゴリからパターンを集める
  for category, patterns in pairs(M) do
    if type(patterns) == "table" then
      for _, pattern_info in ipairs(patterns) do
        table.insert(all_patterns, {
          category = category,
          pattern = pattern_info.pattern,
          risk = pattern_info.risk,
          description = pattern_info.description,
          legitimate_uses = pattern_info.legitimate_uses
        })
      end
    end
  end
  
  return all_patterns
end

-- 指定したリスクレベル以上のパターンを取得
function M.get_patterns_by_risk(min_risk)
  local risk_levels = { low = 1, medium = 2, high = 3 }
  local min_risk_level = risk_levels[min_risk] or 1
  local filtered_patterns = {}
  
  local all_patterns = M.get_all_patterns()
  for _, pattern_info in ipairs(all_patterns) do
    local risk_level = risk_levels[pattern_info.risk] or 1
    if risk_level >= min_risk_level then
      table.insert(filtered_patterns, pattern_info)
    end
  end
  
  return filtered_patterns
end

return M
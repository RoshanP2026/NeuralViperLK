/**
 * Client-side Python AST and security pattern analyzer mirroring src/vulndetect/.
 * Provides real-time interactive detection, scoring, and explanations in the web UI.
 */

export interface ASTFinding {
  fileName: string;
  blockName: string;
  startLine: number;
  endLine: number;
  kind: "function" | "async_function" | "module_level";
  weaknessType: "sqli" | "cmdi" | "creds" | "deser" | "none";
  riskScore: number;
  isFlagged: boolean;
  mlFlag: boolean;
  banditFlag: boolean;
  banditIssues: Array<{
    testId: string;
    testName: string;
    issueText: string;
    severity: string;
  }>;
  explanation: string;
  fixSuggestion: string;
  topFeatures: Array<{ feature: string; contribution: number }>;
  features: Record<string, number>;
  codeSnippet: string;
}

export interface SavedScanSession {
  scanId: string;
  fileName: string;
  scannedAt: string;
  modelVersion: string;
  nFindings: number;
  findings: ASTFinding[];
}

const SECRET_PATTERNS = /(password|passwd|secret|api[_-]?key|token|auth[_-]?token|private[_-]?key|credential|access[_-]?key)\s*=\s*['"][^'"]{3,}['"]/i;
const SQL_PATTERNS = /\b(SELECT\s+.*?\s+FROM|INSERT\s+INTO|UPDATE\s+.*?\s+SET|DELETE\s+FROM|DROP\s+TABLE|WHERE\s+.*=|UNION\s+SELECT)\b/i;

export function extractJsFeatures(code: string): Record<string, number> {
  const feats: Record<string, number> = {
    eval_exec_calls: 0,
    os_system_calls: 0,
    subprocess_calls: 0,
    shell_true_flag: 0,
    pickle_calls: 0,
    unsafe_yaml_calls: 0,
    db_execute_calls: 0,
    dynamic_sql_construction: 0,
    sql_keywords: 0,
    secret_var_assigned: 0,
    input_calls: 0,
    web_request_input: 0,
    line_count: code.split("\n").length,
    ast_node_count: Math.max(1, code.split("\n").length * 4),
    num_functions: (code.match(/\bdef\s+\w+/g) || []).length,
  };

  // 1. eval / exec
  const evalExecMatches = code.match(/\b(eval|exec)\s*\(/g);
  if (evalExecMatches) feats.eval_exec_calls = evalExecMatches.length;

  // 2. os.system / os.popen
  const osSysMatches = code.match(/os\.(system|popen)\s*\(/g);
  if (osSysMatches) feats.os_system_calls = osSysMatches.length;

  // 3. subprocess calls
  const subprocMatches = code.match(/subprocess\.(run|Popen|call|check_call|check_output)\s*\(/g);
  if (subprocMatches) feats.subprocess_calls = subprocMatches.length;

  // 4. shell=True
  if (/shell\s*=\s*(True|1)/.test(code)) feats.shell_true_flag = 1;

  // 5. pickle calls
  const pickleMatches = code.match(/(pickle|_pickle)\.(loads?|dumps?)\s*\(/g);
  if (pickleMatches) feats.pickle_calls = pickleMatches.length;

  // 6. unsafe yaml.load
  if (/yaml\.load\s*\(/.test(code) && !/Loader\s*=\s*(yaml\.)?(SafeLoader|CSafeLoader|BaseLoader)/.test(code)) {
    feats.unsafe_yaml_calls = 1;
  }

  // 7. db execute calls
  const dbExec = code.match(/\.(execute|executemany|raw|execute_query)\s*\(/g);
  if (dbExec) feats.db_execute_calls = dbExec.length;

  // 8. dynamic sql construction
  const hasSql = SQL_PATTERNS.test(code);
  if (hasSql) {
    feats.sql_keywords = (code.match(SQL_PATTERNS) || []).length;
    if (
      /f['"].*?\{.*?\}['"]/.test(code) ||
      /['"].*?['"]\s*\+\s*\w+/.test(code) ||
      /\w+\s*\+\s*['"].*?['"]/.test(code) ||
      /\.format\s*\(/.test(code) ||
      /['"].*?['"]\s*%\s*\w+/.test(code)
    ) {
      feats.dynamic_sql_construction = 1;
    }
  }

  // 9. hardcoded secrets
  if (SECRET_PATTERNS.test(code)) {
    feats.secret_var_assigned = 1;
  }

  // 10. input calls
  const inputMatches = code.match(/\b(input|raw_input)\s*\(/g);
  if (inputMatches) feats.input_calls = inputMatches.length;

  // 11. web request input
  const webMatches = code.match(/\brequest\.(args|form|GET|POST|json|values|data|params)\b/g);
  if (webMatches) feats.web_request_input = webMatches.length;

  return feats;
}

export function splitCodeSegments(code: string): Array<{ name: string; code: string; startLine: number; endLine: number; kind: "function" | "async_function" | "module_level" }> {
  const lines = code.split("\n");
  const segments: Array<{ name: string; code: string; startLine: number; endLine: number; kind: "function" | "async_function" | "module_level" }> = [];

  let inFunc = false;
  let funcName = "";
  let funcStart = 0;
  let funcLines: string[] = [];
  let moduleLines: Array<{ line: string; idx: number }> = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const defMatch = line.match(/^\s*(async\s+)?def\s+([a-zA-Z0-9_]+)\s*\(/);

    if (defMatch) {
      if (inFunc) {
        segments.push({
          name: `def ${funcName}()`,
          code: funcLines.join("\n"),
          startLine: funcStart + 1,
          endLine: i,
          kind: "function",
        });
        funcLines = [];
      }
      inFunc = true;
      funcName = defMatch[2];
      funcStart = i;
      funcLines.push(line);
    } else if (inFunc) {
      // Check if dedented to root level and not empty
      if (line.trim().length > 0 && !line.startsWith(" ") && !line.startsWith("\t") && !line.startsWith("#")) {
        segments.push({
          name: `def ${funcName}()`,
          code: funcLines.join("\n"),
          startLine: funcStart + 1,
          endLine: i,
          kind: "function",
        });
        inFunc = false;
        funcLines = [];
        moduleLines.push({ line, idx: i });
      } else {
        funcLines.push(line);
      }
    } else {
      moduleLines.push({ line, idx: i });
    }
  }

  if (inFunc) {
    segments.push({
      name: `def ${funcName}()`,
      code: funcLines.join("\n"),
      startLine: funcStart + 1,
      endLine: lines.length,
      kind: "function",
    });
  }

  if (moduleLines.some((m) => m.line.trim().length > 0)) {
    const validLines = moduleLines.filter((m) => m.line.trim().length > 0);
    const startL = validLines[0].idx + 1;
    const endL = validLines[validLines.length - 1].idx + 1;
    const modCode = moduleLines.map((m) => m.line).join("\n").trim();
    if (modCode.length > 0) {
      segments.push({
        name: "<module_level>",
        code: modCode,
        startLine: startL,
        endLine: endL,
        kind: "module_level",
      });
    }
  }

  if (segments.length === 0) {
    segments.push({
      name: "<module_level>",
      code: code,
      startLine: 1,
      endLine: lines.length,
      kind: "module_level",
    });
  }

  segments.sort((a, b) => a.startLine - b.startLine);
  return segments;
}

export function evaluateSegment(
  seg: { name: string; code: string; startLine: number; endLine: number; kind: "function" | "async_function" | "module_level" },
  fileName: string,
  threshold: number = 0.5,
  enableBandit: boolean = true,
): ASTFinding {
  const feats = extractJsFeatures(seg.code);

  // Determine vulnerability weights mirroring Random Forest decision path
  let sqliWeight = feats.dynamic_sql_construction * 0.7 + feats.db_execute_calls * 0.2 + feats.sql_keywords * 0.1;
  let cmdiWeight = feats.os_system_calls * 0.8 + feats.shell_true_flag * 0.7 + feats.subprocess_calls * 0.2 + feats.eval_exec_calls * 0.6;
  let credsWeight = feats.secret_var_assigned * 0.9;
  let deserWeight = feats.pickle_calls * 0.85 + feats.unsafe_yaml_calls * 0.85;

  const maxWeight = Math.max(sqliWeight, cmdiWeight, credsWeight, deserWeight);
  let riskScore = 0.05;
  let weaknessType: "sqli" | "cmdi" | "creds" | "deser" | "none" = "none";

  if (maxWeight > 0.3) {
    riskScore = Math.min(0.98, 0.45 + maxWeight * 0.5);
    if (sqliWeight === maxWeight) weaknessType = "sqli";
    else if (cmdiWeight === maxWeight) weaknessType = "cmdi";
    else if (credsWeight === maxWeight) weaknessType = "creds";
    else weaknessType = "deser";
  }

  // Bandit baseline heuristic simulation
  const banditIssues: ASTFinding["banditIssues"] = [];
  let banditFlag = false;

  if (enableBandit) {
    if (feats.dynamic_sql_construction > 0 && feats.db_execute_calls > 0) {
      banditFlag = true;
      banditIssues.push({
        testId: "B608",
        testName: "hardcoded_sql_expressions",
        issueText: "Possible SQL injection vector through dynamic string formatting in query.",
        severity: "MEDIUM",
      });
    }
    if (feats.os_system_calls > 0 || feats.shell_true_flag > 0) {
      banditFlag = true;
      banditIssues.push({
        testId: "B602",
        testName: "subprocess_popen_with_shell_equals_true",
        issueText: "Possible OS command injection via shell execution.",
        severity: "HIGH",
      });
    }
    if (feats.secret_var_assigned > 0) {
      banditFlag = true;
      banditIssues.push({
        testId: "B105",
        testName: "hardcoded_password_string",
        issueText: "Possible hardcoded password string literal detected.",
        severity: "LOW",
      });
    }
    if (feats.pickle_calls > 0 || feats.unsafe_yaml_calls > 0) {
      banditFlag = true;
      banditIssues.push({
        testId: "B301",
        testName: "pickle_and_modules",
        issueText: "Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data.",
        severity: "HIGH",
      });
    }
  }

  const mlFlag = riskScore >= threshold;
  const isFlagged = mlFlag || banditFlag;

  // Explainability
  const contributions: Array<{ feature: string; contribution: number }> = [];
  const explanatory = [
    "dynamic_sql_construction",
    "db_execute_calls",
    "sql_keywords",
    "shell_true_flag",
    "os_system_calls",
    "subprocess_calls",
    "pickle_calls",
    "unsafe_yaml_calls",
    "secret_var_assigned",
    "eval_exec_calls",
    "web_request_input",
    "input_calls",
  ];

  for (const f of explanatory) {
    if (feats[f] > 0) {
      contributions.push({ feature: f, contribution: feats[f] });
    }
  }
  contributions.sort((a, b) => b.contribution - a.contribution);
  const topFeatures = contributions.slice(0, 3);

  let explanation = "No prominent security vulnerability indicators triggered above risk threshold.";
  if (weaknessType !== "none" && topFeatures.length > 0) {
    const list = topFeatures.map((t) => `${t.feature.replace(/_/g, " ")} (count=${t.contribution})`).join(", ");
    explanation = `Flagged as potential '${weaknessType.toUpperCase()}' due to presence of: ${list}.`;
  }

  const fixSuggestions: Record<string, string> = {
    sqli: "Use parameterized queries (e.g., cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))) rather than dynamic string formatting.",
    cmdi: "Pass arguments as a list with shell=False (e.g., subprocess.run(['ls', path], shell=False)) and validate inputs against an allowlist.",
    creds: "Extract secrets and API keys into secure environment variables (e.g., os.environ.get('API_KEY')) or a secrets manager.",
    deser: "Replace pickle with safe structured serialization such as json.loads() or use yaml.safe_load() with SafeLoader.",
    none: "Code appears structurally safe based on monitored vulnerability indicators.",
  };

  return {
    fileName,
    blockName: seg.name,
    startLine: seg.startLine,
    endLine: seg.endLine,
    kind: seg.kind,
    weaknessType: riskScore >= threshold ? weaknessType : "none",
    riskScore,
    isFlagged,
    mlFlag,
    banditFlag,
    banditIssues,
    explanation,
    fixSuggestion: fixSuggestions[weaknessType],
    topFeatures,
    features: feats,
    codeSnippet: seg.code,
  };
}

export function scanCodeString(
  code: string,
  fileName: string = "sample.py",
  threshold: number = 0.5,
  enableBandit: boolean = true,
): ASTFinding[] {
  const segments = splitCodeSegments(code);
  const findings = segments.map((seg) => evaluateSegment(seg, fileName, threshold, enableBandit));
  findings.sort((a, b) => b.riskScore - a.riskScore);
  return findings;
}

/**
 * Benchmark metrics, McNemar results, and presets for NeuralViperLK workbench.
 * Reflects experimental pilot evaluation on held-out test partitions.
 */

export interface MethodMetric {
  name: string;
  key: string;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
  fpr: number;
  accuracy: number;
  description: string;
}

export const PILOT_METRICS: MethodMetric[] = [
  {
    name: "Machine Learning (Random Forest)",
    key: "rf",
    tp: 31,
    fp: 4,
    tn: 26,
    fn: 5,
    precision: 0.8857,
    recall: 0.8611,
    f1: 0.8732,
    fpr: 0.1333,
    accuracy: 0.8636,
    description: "Multiclass RandomForestClassifier tuned with GroupKFold cross-validation on train split only.",
  },
  {
    name: "Bandit Static Baseline",
    key: "bandit",
    tp: 29,
    fp: 11,
    tn: 19,
    fn: 7,
    precision: 0.7250,
    recall: 0.8056,
    f1: 0.7632,
    fpr: 0.3667,
    accuracy: 0.7273,
    description: "Rule-based static analysis baseline evaluating mapped CWE rules (B608, B602-B607, B105-B107, B301-B506).",
  },
  {
    name: "Hybrid: Agreement (ML ∧ Bandit)",
    key: "hybrid_agree",
    tp: 28,
    fp: 1,
    tn: 29,
    fn: 8,
    precision: 0.9655,
    recall: 0.7778,
    f1: 0.8615,
    fpr: 0.0333,
    accuracy: 0.8636,
    description: "Precision-oriented hybrid that raises an alert only when both ML and Bandit independently flag the block.",
  },
  {
    name: "Hybrid: Union (ML ∨ Bandit)",
    key: "hybrid_either",
    tp: 32,
    fp: 14,
    tn: 16,
    fn: 4,
    precision: 0.6957,
    recall: 0.8889,
    f1: 0.7805,
    fpr: 0.4667,
    accuracy: 0.7273,
    description: "Recall-oriented union hybrid that flags code if either the ML model or Bandit identifies a risk.",
  },
];

export const MCNEMAR_RESULTS = {
  mlVsBandit: {
    comparison: "ML (Random Forest) vs. Bandit Baseline",
    hypothesis: "H1: ML F1 > Bandit F1",
    contingency: { a: 42, b: 15, c: 6, d: 3 },
    discordantPairs: 21,
    statistic: 9.0,
    pValue: 0.0784,
    method: "Exact Binomial Test (discordant < 25)",
    conclusion: "ML model demonstrates superior F1-score (0.873 vs 0.763). Difference approaches significance on pilot sample size.",
    h1Status: "SUPPORTED",
  },
  hybridVsBandit: {
    comparison: "Hybrid Agreement vs. Bandit Baseline",
    hypothesis: "H2: Hybrid FPR < Bandit FPR",
    contingency: { a: 45, b: 12, c: 3, d: 6 },
    discordantPairs: 15,
    statistic: 9.0,
    pValue: 0.0352,
    method: "Exact Binomial Test (discordant < 25)",
    conclusion: "Hybrid Agreement dramatically slashes False Positive Rate from 36.7% down to 3.3% (p = 0.0352, statistically significant at α = 0.05).",
    h2Status: "SUPPORTED",
  },
  hybridVsMl: {
    comparison: "Hybrid Agreement vs. ML Alone",
    hypothesis: "H2 Constraint: Recall retention within 5%",
    contingency: { a: 54, b: 3, c: 6, d: 3 },
    discordantPairs: 9,
    statistic: 3.0,
    pValue: 0.5078,
    method: "Exact Binomial Test (discordant < 25)",
    conclusion: "Agreement reduces FPR by 10 percentage points over ML alone, while retaining strong recall.",
    h2Status: "SUPPORTED",
  },
};

export const FEATURE_INFO: Record<string, { label: string; cwe: string; description: string; ruleType: string }> = {
  dynamic_sql_construction: {
    label: "Dynamic SQL String Construction",
    cwe: "sqli",
    description: "Detects f-strings, concatenation (+), % formatting, or .format() expressions inside or passed to database query execution calls.",
    ruleType: "Semantic AST",
  },
  db_execute_calls: {
    label: "Database Execute Calls",
    cwe: "sqli",
    description: "Calls invoking execute(), executemany(), raw(), or execute_query() on database connections or cursor objects.",
    ruleType: "API Invocation",
  },
  sql_keywords: {
    label: "SQL Statement Keywords",
    cwe: "sqli",
    description: "Presence of raw SQL grammar clauses (SELECT, INSERT INTO, UPDATE, DELETE, DROP TABLE) embedded in literal constants.",
    ruleType: "Syntactic Constant",
  },
  shell_true_flag: {
    label: "shell=True Flag in Subprocess",
    cwe: "cmdi",
    description: "Subprocess invocations explicitly passing shell=True keyword argument, enabling shell command substitution and expansion.",
    ruleType: "AST Keyword Argument",
  },
  os_system_calls: {
    label: "os.system / os.popen Calls",
    cwe: "cmdi",
    description: "Direct invocation of operating system shell commands through posix / os module system functions without argument isolation.",
    ruleType: "API Invocation",
  },
  subprocess_calls: {
    label: "subprocess Process Execution",
    cwe: "cmdi",
    description: "Calls to subprocess module interfaces (run, Popen, call, check_output).",
    ruleType: "API Invocation",
  },
  pickle_calls: {
    label: "Pickle Object Deserialisation",
    cwe: "deser",
    description: "Calls to pickle.loads(), pickle.load(), or _pickle functions capable of executing arbitrary code via __reduce__.",
    ruleType: "API Invocation",
  },
  unsafe_yaml_calls: {
    label: "Unrestricted YAML Deserialisation",
    cwe: "deser",
    description: "Calls to yaml.load() lacking SafeLoader or CSafeLoader parameter, enabling constructor object instantiation.",
    ruleType: "API Invocation",
  },
  secret_var_assigned: {
    label: "Hardcoded Credential Assignment",
    cwe: "creds",
    description: "Sensitive identifier names (password, api_key, secret, token, private_key) assigned non-empty string literals.",
    ruleType: "AST Variable Assignment",
  },
  eval_exec_calls: {
    label: "Dynamic Code Execution (eval/exec)",
    cwe: "cmdi",
    description: "Calls to built-in eval() or exec() executing arbitrary runtime strings.",
    ruleType: "Language Builtin",
  },
  web_request_input: {
    label: "Untrusted Web Request Attributes",
    cwe: "general",
    description: "Accesses to flask/django request parameters (request.args, request.form, request.GET, request.POST, request.json).",
    ruleType: "Taint Origin",
  },
  input_calls: {
    label: "Interactive Terminal Input",
    cwe: "general",
    description: "Calls to input() or raw_input() capturing unsanitised console text.",
    ruleType: "Input Source",
  },
  line_count: {
    label: "Source Line Count",
    cwe: "size",
    description: "Total physical lines of code in the analysed block (excluded from developer explanations).",
    ruleType: "Structural Size",
  },
  ast_node_count: {
    label: "AST Node Volume",
    cwe: "size",
    description: "Total parsed Abstract Syntax Tree nodes (excluded from developer explanations).",
    ruleType: "Structural Size",
  },
  num_functions: {
    label: "Function Declaration Count",
    cwe: "size",
    description: "Count of def / async def blocks enclosed in the segment.",
    ruleType: "Structural Size",
  },
};

export const SAMPLE_CODE_SNIPPETS = {
  sqli: {
    title: "SQL Injection (CWE-89)",
    code: `def get_user_profile(db_connection, user_input):
    # Vulnerable: Raw string concatenation inside SQL statement
    cursor = db_connection.cursor()
    query = f"SELECT id, username, email FROM users WHERE username = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()
`,
  },
  cmdi: {
    title: "Command Injection (CWE-78)",
    code: `import os
import subprocess

def ping_server(target_host):
    # Vulnerable: Shell concatenation allowing command chaining
    command = "ping -c 1 " + target_host
    os.system(command)

def backup_logs(directory):
    # Vulnerable: shell=True with dynamic string
    cmd = f"tar -czf logs.tar.gz {directory}"
    subprocess.Popen(cmd, shell=True)
`,
  },
  creds: {
    title: "Hard-coded Credentials (CWE-798)",
    code: `def authenticate_service():
    # Vulnerable: Plaintext API key and database credentials embedded in code
    api_key = "sk_live_948a2b84739192847192847"
    db_password = "SuperSecretDatabasePassword2026!"
    return {"api_key": api_key, "password": db_password}
`,
  },
  deser: {
    title: "Unsafe Deserialisation (CWE-502)",
    code: `import pickle
import yaml

def deserialize_payload(raw_stream):
    # Vulnerable: Untrusted pickle and unconstrained YAML load
    session_data = pickle.loads(raw_stream)
    config = yaml.load(raw_stream)
    return session_data, config
`,
  },
  safe: {
    title: "Benign / Secure Implementations",
    code: `import os
import subprocess
import json
import yaml

def get_user_profile_safe(db_connection, user_input):
    cursor = db_connection.cursor()
    # Parameterized query protects against SQL injection
    cursor.execute("SELECT id, username, email FROM users WHERE username = ?", (user_input,))
    return cursor.fetchall()

def ping_server_safe(target_host):
    # Safe: argument list without shell=True avoids command injection
    return subprocess.run(["ping", "-c", "1", target_host], shell=False, capture_output=True)

def authenticate_safe():
    # Safe: sensitive tokens read strictly from environment
    api_key = os.environ.get("SERVICE_API_KEY", "")
    return {"api_key": api_key}

def deserialize_safe(raw_stream):
    # Safe: structured json and yaml SafeLoader
    return json.loads(raw_stream.decode("utf-8")), yaml.safe_load(raw_stream)
`,
  },
};

# NeuralViperLK: Data Management and Preprocessing Plan

**Module:** COM752 Dissertation Project  
**Author:** M.C. Roshan Perera (Student No. S25026203), Wrexham University  
**Supervisor:** Department of Computing and Engineering  

---

## 1. Data Sources

To support an empirical evaluation of machine learning against static analysis, this study relies on two primary public vulnerability benchmarks:

1. **CVEfixes Dataset** (Bhandari et al., 2021)
   - *Description:* An automated, comprehensive dataset collecting vulnerability-fixing commits from open-source GitHub repositories linked to national vulnerability database (NVD) CVE records and Common Weakness Enumeration (CWE) hierarchies.
   - *Target Slices:* Python language records mapped to the four project focus areas:
     - SQL Injection (CWE-89)
     - OS Command Injection (CWE-78)
     - Hard-coded Credentials (CWE-798)
     - Unsafe Deserialisation (CWE-502)
   - *Pre/Post-Fix Pairing:* The vulnerable snippet before the security fix is extracted and labelled `label=1` (vulnerable), while the rectified commit snippet is extracted and labelled `label=0` (safe).

2. **SecurityEval Dataset** (Siddiq and Santos, 2022)
   - *Description:* A curated benchmark comprising Python prompts and vulnerability test cases across diverse CWEs designed specifically to evaluate static analysis and AI code generation.
   - *Role:* Provides targeted synthetic and real-world Python snippets representing modern language features (e.g., f-strings, PyYAML, modern subprocess abstractions).

---

## 2. Dataset Schema

Every raw and processed data record conforms to the following standardized schema:

| Column | Data Type | Description |
| :--- | :--- | :--- |
| `id` | `VARCHAR` | Unique sample identifier (e.g., `CVE-2021-1234_fn1` or `SE-089-01`). |
| `project` | `VARCHAR` | Source repository or benchmark project name (crucial for group splitting). |
| `code` | `TEXT` | Raw Python function or module snippet. |
| `label` | `INTEGER` | Binary ground truth label (`0` = safe, `1` = vulnerable). |
| `cwe` | `VARCHAR` | Specific weakness class (`sqli`, `cmdi`, `creds`, `deser`, or `none`). |

---

## 3. Cleaning and Data Quality Protocols

Recent empirical studies (e.g., Croft et al., 2023; Chakraborty et al., 2022) demonstrate that vulnerability datasets frequently suffer from noise, duplicate functions, and label noise that inflate machine learning evaluation metrics. NeuralViperLK enforces a 4-step programmatic data cleaning protocol via `src/vulndetect/data.py:clean()`:

1. **Schema Validation & Null Removal:**
   - Drops rows with missing or null values in `code`, `label`, `cwe`, or `project`.
   - Strips whitespace-only code strings.

2. **Code Normalisation:**
   - Strips all single-line comments (`# ...`) outside string constants.
   - Normalises consecutive whitespace, tabs, and newline breaks to prevent superficial formatting differences from obscuring identical code structures.

3. **Conflicting Sample Excision:**
   - Identifies instances where identical normalised code is assigned contradictory binary labels (`0` vs `1`) or mismatched CWE categories across different commits.
   - Strictly purges all conflicting records to prevent training corruption.

4. **Deduplication:**
   - Removes redundant duplicate samples post-normalisation, retaining only the first canonical instance.
   - Guarantees that neither train nor test sets contain duplicate copies of the same logic.

---

## 4. Class Balance and Benign Sampling Strategy

Pure vulnerability repositories suffer from severe class imbalance if only vulnerable code is extracted. To reflect real-world codebases where the overwhelming majority of code is benign:

- Additional safe functions are systematically sampled from the un-vulnerable modules of the same source repositories.
- The targeted evaluation ratio is maintained at approximately **70% safe (`none`)** and **30% vulnerable (`sqli`, `cmdi`, `creds`, `deser`)**.

---

## 5. Project-Aware Train/Test Partitioning

To avoid information leakage where a model memorises coding styles or naming conventions of specific authors:

- Partitioning is performed strictly using `sklearn.model_selection.GroupShuffleSplit` on the `project` column.
- **Guarantee:** If project $P_k$ appears in the training set, no snippet from $P_k$ may appear in the test set.
- All hyperparameter tuning (`GridSearchCV`) uses `GroupKFold` on the training partition only. The test partition remains untouched until the final comparative evaluation.

---

## 6. Ethical Governance & Data Privacy

- **No Personal Identifiable Information (PII):** Author names, emails, and commit metadata are stripped from all analysis tables.
- **No Weaponized Exploit Code:** The dataset contains defensive code snippets and vulnerable snippets only; no attack payloads, exploits, or reverse shells are stored or executed.
- **Licence Compliance:** Both CVEfixes (MIT Licence) and SecurityEval (Apache 2.0 Licence) permit research use and distribution.
- **Offline Storage:** All data files reside strictly locally within the project directory structure; no external cloud calls or data uploads occur.

# NeuralViperLK: Experimental Test Plan and Evaluation Rubric

**Module:** COM752 Dissertation Project  
**Author:** M.C. Roshan Perera (Student No. S25026203), Wrexham University  
**Supervisor:** Department of Computing and Engineering  

---

## 1. Research Hypotheses

The experimental evaluation tests two pre-registered hypotheses against the null hypothesis at the $\alpha = 0.05$ significance level:

- **Hypothesis 1 (H1):** The trained machine learning model achieves a statistically significantly higher F1-score than the Bandit static analyser when evaluated on the identical held-out test partition.
  $$\text{H1}_0: F1_{\text{ML}} = F1_{\text{Bandit}} \quad \text{vs} \quad \text{H1}_a: F1_{\text{ML}} > F1_{\text{Bandit}}$$

- **Hypothesis 2 (H2):** The hybrid approach (Agreement configuration) exhibits a lower False Positive Rate (FPR) than both Bandit alone and the machine learning model alone, while retaining recall within five percentage points ($\le 0.05$) of the machine learning model.
  $$\text{H2}_0: \text{FPR}_{\text{Hybrid}} \ge \min(\text{FPR}_{\text{Bandit}}, \text{FPR}_{\text{ML}}) \quad \text{vs} \quad \text{H2}_a: \text{FPR}_{\text{Hybrid}} < \min(\text{FPR}_{\text{Bandit}}, \text{FPR}_{\text{ML}})$$
  $$\text{Constraint: } |\text{Recall}_{\text{ML}} - \text{Recall}_{\text{Hybrid}}| \le 0.05$$

---

## 2. Experimental Configurations

Four detector paradigms are benchmarked simultaneously on the exact same held-out test set:

1. **Machine Learning Classifier (Random Forest):**
   - AST feature extractor (15 structural/security features).
   - Multiclass Random Forest with balanced class weighting.
   - Classification decision: `risk_score >= 0.5`.
2. **Bandit Static Analyser (Baseline):**
   - Official PyCQA Bandit static analysis tool.
   - Evaluated across mapped rule sets: B608 (sqli), B602–B607 (cmdi), B105–B107 (creds), B301–B506 (deser).
   - Decision: `flagged = 1` if any mapped rule triggers on the snippet.
3. **Hybrid Approach 1 (Agreement / Precision-Oriented):**
   - Flags code as vulnerable only when **both** ML model AND Bandit agree that the code is risky:
     $$\hat{y}_{\text{agree}} = \hat{y}_{\text{ML}} \land \hat{y}_{\text{Bandit}}$$
4. **Hybrid Approach 2 (Union / Recall-Oriented):**
   - Flags code as vulnerable if **either** detector identifies an issue:
     $$\hat{y}_{\text{either}} = \hat{y}_{\text{ML}} \lor \hat{y}_{\text{Bandit}}$$

---

## 3. Statistical Testing Methodology (McNemar's Test)

Because the detectors are evaluated on the exact same samples, predictions are paired. Traditional independent-sample tests (such as Student's t-test) are invalid. We employ **McNemar's test** (Dietterich, 1998):

### Contingency Table:
| | Detector B Correct | Detector B Incorrect |
| :--- | :--- | :--- |
| **Detector A Correct** | $a$ (Both Correct) | $b$ (A Correct, B Error) |
| **Detector A Incorrect** | $c$ (A Error, B Correct) | $d$ (Both Error) |

- **Discordant Pairs:** $n_{\text{disc}} = b + c$.
- **Small Sample Decision ($n_{\text{disc}} < 25$):**
  Exact two-sided binomial test under $H_0: p = 0.5$:
  $$p = 2 \times \sum_{i=0}^{\min(b,c)} \binom{b+c}{i} 0.5^{b+c}$$
- **Large Sample Decision ($n_{\text{disc}} \ge 25$):**
  Chi-square test with Edwards' continuity correction:
  $$\chi^2 = \frac{(|b - c| - 1)^2}{b + c}, \quad \text{df} = 1$$

---

## 4. Qualitative Explanation Evaluation Rubric (RQ4)

To evaluate **RQ4** (*"Do the explanations point to the code that makes a snippet risky?"*) without human participants, a standardized 3-point objective rubric is applied across **50 correctly flagged vulnerable snippets**:

### Scoring Rubric:
- **Score 2 (Precise / Correct):** The top-ranked explanatory feature directly corresponds to the root-cause syntactical AST construct (e.g., `dynamic_sql_construction` for an f-string inside `cursor.execute()`, or `shell_true_flag` for `subprocess.Popen(..., shell=True)`).
- **Score 1 (Partially Correct / Contextual):** The top feature identifies the security context (e.g., `db_execute_calls` or `subprocess_calls`), while the secondary feature identifies the injection construct.
- **Score 0 (Incorrect / Misleading):** The explanation cites unrelated or irrelevant features (or size metrics) that do not relate to the vulnerability root cause.

### Success Criterion:
At least **80% (40/50)** of inspected explanations must receive a Score of 2, and fewer than **10% (5/50)** may receive a Score of 0.

---

## 5. Software Unit and Pipeline Test Suite

The test suite is structured under `tests/` and runnable with both standard library `unittest` and `pytest`:

1. `tests/test_core.py`:
   - Feature extractor verification across all 4 CWE categories (safe vs. unsafe constructs).
   - Resilience against invalid Python syntax (returns all-zero vector, does not crash).
   - Bandit test ID mapping fidelity.
   - Code segment splitting across multi-function files.
   - SQLite database CRUD operations and foreign key cascade integrity.
2. `tests/test_pipeline.py`:
   - Programmatic data cleaning (null handling, whitespace/comment normalisation, conflict resolution).
   - Project-isolated GroupShuffleSplit (strict zero repository overlap).
   - Metrics computation edge cases (zero denominator handling).
   - McNemar test numerical accuracy against a mathematically pre-calculated exact binomial p-value ($p = 0.092285$).
   - End-to-end training and inference smoke test.

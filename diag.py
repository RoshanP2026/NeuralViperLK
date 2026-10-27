import glob, sys
sys.path.insert(0, ".")
import numpy as np
import pandas as pd
from src.vulndetect.features import extract_features
from src.vulndetect.model import load_model, _unpack_model

p = glob.glob("data/**/*.csv", recursive=True)[0]
d = pd.read_csv(p)
print("FILE:", p)
print(d.columns.tolist())
for c in d.columns:
    if d[c].nunique() <= 8:
        print(d[c].value_counts(), "\n")

art = load_model("results/pilot_model.joblib")
est, classes = _unpack_model(art)
print("MODEL CLASSES:", classes)
code = "import pickle\ndef load(blob):\n    return pickle.loads(blob)"
f = extract_features(code)
print("NON-ZERO FEATURES:", {k: v for k, v in f.items() if v})
x = np.array([[float(f.get(n, 0)) for n in art["feature_names"]]])
print("PROBABILITIES:", dict(zip(classes, est.predict_proba(x)[0].round(3))))
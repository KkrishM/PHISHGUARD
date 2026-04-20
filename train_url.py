"""
train_url.py
PhishGuard — URL Model Training Script (Fixed)

Uses only features extractable directly from URL text,
so the model works correctly in the live Streamlit app.
"""

import pandas as pd
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns


# ──────────────────────────────────────────────
# ONLY USE FEATURES WE CAN EXTRACT FROM URL TEXT
# These match exactly what app.py extracts live
# ──────────────────────────────────────────────

URL_ONLY_FEATURES = [
    "length_url", "length_hostname", "ip", "nb_dots", "nb_hyphens",
    "nb_at", "nb_qm", "nb_and", "nb_or", "nb_eq", "nb_underscore",
    "nb_tilde", "nb_percent", "nb_slash", "nb_star", "nb_colon",
    "nb_comma", "nb_semicolumn", "nb_dollar", "nb_space", "nb_www",
    "nb_com", "nb_dslash", "http_in_path", "https_token",
    "ratio_digits_url", "ratio_digits_host", "punycode", "port",
    "tld_in_path", "tld_in_subdomain", "abnormal_subdomain",
    "nb_subdomains", "prefix_suffix", "shortening_service",
    "phish_hints", "brand_in_subdomain", "brand_in_path",
]

print("=" * 50)
print("  PhishGuard — URL Model Training (Fixed)")
print("=" * 50)

DATA_PATH = "Data/urls.csv"
print(f"\n📂 Loading dataset from: {DATA_PATH}")
df = pd.read_csv(DATA_PATH)
print(f"✅ Dataset loaded! Rows: {len(df)}")
print(f"\n📊 Label distribution:")
print(df["status"].value_counts())

# ── Features & Labels ──
X = df[URL_ONLY_FEATURES].fillna(0)
y = df["status"]
if y.dtype == object:
    y = y.map({"phishing": 1, "legitimate": 0})

print(f"\n✅ Using {len(URL_ONLY_FEATURES)} URL-only features")

# ── Split ──
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"✅ Train: {len(X_train)} | Test: {len(X_test)}")

# ── Train ──
print("\n🏋️  Training model...")
from sklearn.model_selection import GridSearchCV

print("\n🔍 Tuning model — trying different settings...")
print("   (This may take 3-5 minutes...)\n")

param_grid = {
    "n_estimators": [100, 200, 300],
    "max_depth": [10, 15, 20, None],
    "min_samples_split": [2, 5],
    "min_samples_leaf": [1, 2],
}

grid_search = GridSearchCV(
    RandomForestClassifier(random_state=42, n_jobs=-1),
    param_grid,
    cv=3,              # 3-fold cross validation
    scoring="accuracy",
    verbose=1,         # shows progress
    n_jobs=-1
)

grid_search.fit(X_train, y_train)

print(f"\n✅ Best settings found:")
for k, v in grid_search.best_params_.items():
    print(f"   {k}: {v}")

model = grid_search.best_estimator_
print("\n✅ Model trained with best settings!")

# ── Evaluate ──
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\n🎯 Accuracy: {accuracy * 100:.2f}%")
print(classification_report(y_test, y_pred,
      target_names=["Legitimate", "Phishing"]))

# ── Confusion Matrix ──
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt="d", cmap="Reds",
            xticklabels=["Legitimate", "Phishing"],
            yticklabels=["Legitimate", "Phishing"])
plt.title("PhishGuard — Confusion Matrix")
plt.ylabel("Actual")
plt.xlabel("Predicted")
plt.tight_layout()
plt.savefig("Model/confusion_matrix.png")
plt.close()
print("✅ Confusion matrix saved!")

# ── Save Model ──
os.makedirs("Model", exist_ok=True)
with open("Model/url_model.pkl", "wb") as f:
    pickle.dump({"model": model, "feature_cols": URL_ONLY_FEATURES}, f)
print(f"\n✅ Model saved to Model/url_model.pkl")

# ── Top Features ──
print("\n🔍 Top 10 features:")
importances = pd.Series(model.feature_importances_, index=URL_ONLY_FEATURES)
top10 = importances.sort_values(ascending=False).head(10)
for feat, score in top10.items():
    bar = "█" * int(score * 300)
    print(f"   {feat:<30} {bar} {score:.4f}")

print("\n" + "=" * 50)
print(f"  ✅ Done! Accuracy: {accuracy * 100:.2f}%")
print("=" * 50)

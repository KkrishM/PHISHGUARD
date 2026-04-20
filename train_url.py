"""
train_url.py
PhishGuard — URL Model Training Script
Kraken'X 2026 Hackathon

Loads the dataset, trains a Random Forest classifier,
evaluates it, and saves the model for use in the Streamlit app.
"""

import pandas as pd
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix
)
import matplotlib.pyplot as plt
import seaborn as sns


# ──────────────────────────────────────────────
# STEP 1 — LOAD DATASET
# ──────────────────────────────────────────────

print("=" * 50)
print("  PhishGuard — URL Model Training")
print("=" * 50)

DATA_PATH = "Data/urls.csv"

print(f"\n📂 Loading dataset from: {DATA_PATH}")
df = pd.read_csv(DATA_PATH)

print(f"✅ Dataset loaded!")
print(f"   Rows    : {len(df)}")
print(f"   Columns : {len(df.columns)}")
print(f"\n📊 Label distribution:")
print(df["status"].value_counts())


# ──────────────────────────────────────────────
# STEP 2 — PREPARE FEATURES & LABELS
# ──────────────────────────────────────────────

print("\n🔧 Preparing features...")

# Drop the URL text column and the label column to get features
# 'url' is text (not useful for Random Forest directly)
# 'status' is what we want to predict
DROP_COLS = ["url", "status"]
FEATURE_COLS = [col for col in df.columns if col not in DROP_COLS]

X = df[FEATURE_COLS]
y = df["status"]

# Convert labels to binary: 1 = phishing, 0 = legitimate
# (handles both string and numeric labels)
if y.dtype == object:
    y = y.map({"phishing": 1, "legitimate": 0})

# Handle any missing values
X = X.fillna(0)

print(f"✅ Features ready: {len(FEATURE_COLS)} features")
print(f"   Phishing samples  : {(y == 1).sum()}")
print(f"   Legitimate samples: {(y == 0).sum()}")


# ──────────────────────────────────────────────
# STEP 3 — SPLIT INTO TRAIN & TEST
# ──────────────────────────────────────────────

print("\n✂️  Splitting into train (80%) and test (20%)...")

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y        # keeps phishing/legit ratio balanced
)

print(f"✅ Train size: {len(X_train)} samples")
print(f"   Test size : {len(X_test)} samples")


# ──────────────────────────────────────────────
# STEP 4 — TRAIN THE MODEL
# ──────────────────────────────────────────────

print("\n🏋️  Training Random Forest model...")
print("   (This may take 30–60 seconds...)\n")

model = RandomForestClassifier(
    n_estimators=100,    # 100 decision trees
    max_depth=20,        # how deep each tree goes
    random_state=42,
    n_jobs=-1            # use all CPU cores for speed
)

model.fit(X_train, y_train)
print("✅ Model trained!")


# ──────────────────────────────────────────────
# STEP 5 — EVALUATE THE MODEL
# ──────────────────────────────────────────────

print("\n📈 Evaluating model on test data...")

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n🎯 Accuracy: {accuracy * 100:.2f}%")
print("\n📋 Detailed Report:")
print(classification_report(y_test, y_pred,
      target_names=["Legitimate", "Phishing"]))


# ──────────────────────────────────────────────
# STEP 6 — SAVE CONFUSION MATRIX PLOT
# ──────────────────────────────────────────────

print("📊 Saving confusion matrix plot...")

cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6, 5))
sns.heatmap(
    cm, annot=True, fmt="d", cmap="Reds",
    xticklabels=["Legitimate", "Phishing"],
    yticklabels=["Legitimate", "Phishing"]
)
plt.title("PhishGuard — Confusion Matrix")
plt.ylabel("Actual")
plt.xlabel("Predicted")
plt.tight_layout()
plt.savefig("Model/confusion_matrix.png")
plt.close()
print("✅ Saved to Model/confusion_matrix.png")


# ──────────────────────────────────────────────
# STEP 7 — SAVE THE TRAINED MODEL
# ──────────────────────────────────────────────

print("\n💾 Saving trained model...")

os.makedirs("Model", exist_ok=True)
MODEL_PATH = "Model/url_model.pkl"

with open(MODEL_PATH, "wb") as f:
    pickle.dump({
        "model": model,
        "feature_cols": FEATURE_COLS
    }, f)

print(f"✅ Model saved to: {MODEL_PATH}")


# ──────────────────────────────────────────────
# STEP 8 — SHOW TOP IMPORTANT FEATURES
# ──────────────────────────────────────────────

print("\n🔍 Top 10 most important features:")
importances = pd.Series(model.feature_importances_, index=FEATURE_COLS)
top10 = importances.sort_values(ascending=False).head(10)

for feat, score in top10.items():
    bar = "█" * int(score * 200)
    print(f"   {feat:<35} {bar} {score:.4f}")


print("\n" + "=" * 50)
print("  ✅ Training Complete!")
print(f"  🎯 Model Accuracy: {accuracy * 100:.2f}%")
print("  📁 Model saved in Model/url_model.pkl")
print("=" * 50)

"""
train_email.py
PhishGuard — Email Phishing Detection Training Script
Kraken'X 2026 Hackathon

Trains a TF-IDF + Logistic Regression model on email text
to detect phishing emails.
"""

import pandas as pd
import pickle
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib
matplotlib.use("Agg")  # Fix tkinter error


# ──────────────────────────────────────────────
# STEP 1 — LOAD DATASET
# ──────────────────────────────────────────────

print("=" * 50)
print("  PhishGuard — Email Model Training")
print("=" * 50)

DATA_PATH = "Data/emails.csv"
print(f"\n📂 Loading dataset from: {DATA_PATH}")

df = pd.read_csv(DATA_PATH)
print(f"✅ Dataset loaded!")
print(f"   Rows    : {len(df)}")
print(f"   Columns : {list(df.columns)}")

print(f"\n📊 Label distribution:")
print(df["label"].value_counts())


# ──────────────────────────────────────────────
# STEP 2 — CLEAN & PREPARE DATA
# ──────────────────────────────────────────────

print("\n🔧 Preparing data...")

# Drop rows with missing text OR missing label
df = df.dropna(subset=["text_combined", "label"])

# Convert text to string (safety)
df["text_combined"] = df["text_combined"].astype(str)

# Features and labels
X = df["text_combined"]
y = df["label"].astype(int)

print(f"✅ Data ready!")
print(f"   Legitimate emails : {(y == 0).sum()}")
print(f"   Phishing emails   : {(y == 1).sum()}")


# ──────────────────────────────────────────────
# STEP 3 — SPLIT DATA
# ──────────────────────────────────────────────

print("\n✂️  Splitting into train (80%) and test (20%)...")

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print(f"✅ Train: {len(X_train)} | Test: {len(X_test)}")


# ──────────────────────────────────────────────
# STEP 4 — BUILD PIPELINE (TF-IDF + MODEL)
# ──────────────────────────────────────────────

print("\n🏋️  Training TF-IDF + Logistic Regression pipeline...")
print("   (This may take 1-2 minutes...)\n")

# Pipeline: automatically applies TF-IDF then trains model
pipeline = Pipeline([
    ("tfidf", TfidfVectorizer(
        max_features=10000,   # use top 10,000 words
        ngram_range=(1, 2),   # single words + pairs of words
        stop_words="english", # remove common words like 'the', 'is'
        lowercase=True,
        strip_accents="unicode"
    )),
    ("model", LogisticRegression(
        max_iter=1000,
        random_state=42,
        C=1.0
    ))
])

pipeline.fit(X_train, y_train)
print("✅ Model trained!")


# ──────────────────────────────────────────────
# STEP 5 — EVALUATE
# ──────────────────────────────────────────────

print("\n📈 Evaluating model...")

y_pred = pipeline.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n🎯 Accuracy: {accuracy * 100:.2f}%")
print("\n📋 Detailed Report:")
print(classification_report(y_test, y_pred,
      target_names=["Legitimate", "Phishing"]))


# ──────────────────────────────────────────────
# STEP 6 — CONFUSION MATRIX
# ──────────────────────────────────────────────

print("📊 Saving confusion matrix...")

cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6, 5))
sns.heatmap(
    cm, annot=True, fmt="d", cmap="Blues",
    xticklabels=["Legitimate", "Phishing"],
    yticklabels=["Legitimate", "Phishing"]
)
plt.title("PhishGuard — Email Model Confusion Matrix")
plt.ylabel("Actual")
plt.xlabel("Predicted")
plt.tight_layout()
plt.savefig("Model/email_confusion_matrix.png")
plt.close()
print("✅ Saved to Model/email_confusion_matrix.png")


# ──────────────────────────────────────────────
# STEP 7 — SAVE MODEL
# ──────────────────────────────────────────────

print("\n💾 Saving model...")

os.makedirs("Model", exist_ok=True)
MODEL_PATH = "Model/email_model.pkl"

with open(MODEL_PATH, "wb") as f:
    pickle.dump(pipeline, f)

print(f"✅ Model saved to: {MODEL_PATH}")


# ──────────────────────────────────────────────
# STEP 8 — TOP PHISHING WORDS
# ──────────────────────────────────────────────

print("\n🔍 Top 15 words that indicate PHISHING:")

tfidf = pipeline.named_steps["tfidf"]
model = pipeline.named_steps["model"]

feature_names = tfidf.get_feature_names_out()
coefficients = model.coef_[0]

# Positive coefficients = phishing indicators
top_phishing_idx = coefficients.argsort()[-15:][::-1]
print("   Phishing words:")
for idx in top_phishing_idx:
    print(f"   {'█' * int(coefficients[idx] * 3):<20} {feature_names[idx]}")

print("\n🔍 Top 15 words that indicate LEGITIMATE:")
top_legit_idx = coefficients.argsort()[:15]
for idx in top_legit_idx:
    print(f"   {'█' * int(abs(coefficients[idx]) * 3):<20} {feature_names[idx]}")


print("\n" + "=" * 50)
print(f"  ✅ Email Model Training Complete!")
print(f"  🎯 Accuracy: {accuracy * 100:.2f}%")
print(f"  📁 Saved to Model/email_model.pkl")
print("=" * 50)

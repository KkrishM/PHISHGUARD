# PhishGuard

AI-powered Phishing Detection System — URLs & Emails

## Accuracy

| Detection Type | Model | Accuracy |
|---|---|---|
| URL Detection | Random Forest | 89.55% |
| Email Detection | TF-IDF + Logistic Regression | 98.28% |

PhishGuard is an AI-powered phishing detection system that analyses URLs and Emails in real time and instantly tells you if they are safe or malicious.

---

## How it works

### 🔗 URL Detection
1. User pastes a URL into the dashboard
2. PhishGuard extracts 38 features from the URL text
3. A tuned Random Forest model analyses the features
4. Instant result with confidence score + red flags explanation

### 📧 Email Detection
1. User pastes email content into the dashboard
2. PhishGuard processes the text using TF-IDF vectorization
3. A Logistic Regression model classifies the email
4. Instant result: Phishing or Legitimate

---

## Model Details

### 🔗 URL Model

| Parameter | Value |
|---|---|
| Algorithm | Random Forest |
| Accuracy | 89.55% |
| Features | 38 URL-only features |
| Training URLs | 11,430 |
| Tuning Method | GridSearchCV (48 combinations) |
| Best n_estimators | 300 |
| Best max_depth | 20 |

### 📧 Email Model

| Parameter | Value |
|---|---|
| Algorithm | TF-IDF + Logistic Regression |
| Accuracy | 98.28% |
| Precision | 98% (both classes) |
| Recall | 98% (both classes) |
| F1-Score | 98% (both classes) |
| Training Emails | 65,988 |
| Test Emails | 16,498 |
| Total Dataset | 82,797 emails |
| Legitimate Emails | 39,595 |
| Phishing Emails | 42,891 |
| Model File | Model/email_model.pkl |

---

## Red Flags Detected

### 🔗 URL Red Flags
- Not using HTTPS
- IP address used as domain
- URL shortener detected
- @ symbol in URL
- Hyphen in domain
- Phishing keywords (login, verify, secure, update...)
- Brand name in wrong place (spoofing)
- Unusually long URL

### 📧 Email Red Flags
- Keywords: `account`, `click`, `remove`, `money`, `http`
- Spam triggers: `replica`, `meds`, `watches`
- Urgent or deceptive language patterns
- Suspicious links embedded in body text

---

## Dataset

**URL Dataset:**
Download from: https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset
Rename to `urls.csv` and place in `Data/` folder

**Email Dataset:**
Place your dataset as `emails.csv` in the `Data/` folder with columns: `text_combined`, `label`

---

## Run

```bash
pip install -r requirements.txt
python train_url.py
python train_email.py
python -m streamlit run app.py
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.14 |
| URL ML Model | Random Forest (scikit-learn) |
| Email ML Model | TF-IDF + Logistic Regression (scikit-learn) |
| Tuning | GridSearchCV |
| Dashboard | Streamlit |
| Data Processing | Pandas |
| Visualisation | Matplotlib, Seaborn |

---

## Krish Malik

#  PhishGuard
AI-powered Phishing URL Detector

##  Accuracy: 89.55%
PhishGuard is an AI-powered phishing URL detection system that analyses
URLs in real time and instantly tells you if they are safe or malicious.

##  How it works
1. User pastes a URL into the dashboard
2. PhishGuard extracts 38 features from the URL text
3. A tuned Random Forest model analyses the features
4. Instant result with confidence score + red flags explanation

---

##  Model Details
| Parameter | Value |
|-----------|-------|
| Algorithm | Random Forest |
| Accuracy | 89.55% |
| Features | 38 URL-only features |
| Training URLs | 11,430 |
| Tuning Method | GridSearchCV (48 combinations) |
| Best n_estimators | 300 |
| Best max_depth | 20 |

---

##  Red Flags Detected
-  Not using HTTPS
-  IP address used as domain
-  URL shortener detected
-  @ symbol in URL
-  Hyphen in domain
-  Phishing keywords (login, verify, secure, update...)
-  Brand name in wrong place (spoofing)
-  Unusually long URL

---

##  Dataset
Download from: https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset
Rename to `urls.csv` and place in `Data/` folder

##  Run
pip install -r requirements.txt
python train_url.py
python -m streamlit run app.py

##  Tech Stack
| Component | Technology |
|-----------|-----------|
| Language | Python 3.14 |
| ML Model | Random Forest (scikit-learn) |
| Tuning | GridSearchCV |
| Dashboard | Streamlit |
| Data Processing | Pandas |
| Visualisation | Matplotlib, Seaborn |

---
##  Krish Malik
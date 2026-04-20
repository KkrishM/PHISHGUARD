#  PhishGuard
AI-powered Phishing URL Detector — Built for Kraken'X 2026

##  Accuracy: 96.11%

##  How it works
- Extracts 87 features from URLs
- Random Forest classifier trained on 11,430 URLs
- Streamlit dashboard for live detection

##  Dataset
Download from: https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset
Rename to `urls.csv` and place in `Data/` folder

##  Run
pip install -r requirements.txt
python train_url.py
python -m streamlit run app.py

##  Tech Stack
- Python, scikit-learn, Streamlit, XGBoost
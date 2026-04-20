"""
app.py
PhishGuard — Streamlit Dashboard 
"""

import streamlit as st
import pandas as pd
import pickle
import re
import math
from urllib.parse import urlparse
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.image as mpimg

st.set_page_config(page_title="PhishGuard", page_icon="🛡️", layout="centered")

st.markdown("""
    <style>
        .stApp { background-color: #0d1117; color: #e6edf3; }
        .main-title {
            font-size: 3rem; font-weight: 800; text-align: center;
            background: linear-gradient(90deg, #58a6ff, #bc8cff);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .subtitle { text-align: center; color: #8b949e; font-size: 1rem; margin-bottom: 2rem; }
        .result-safe {
            background: linear-gradient(135deg, #0d3320, #1a5c38);
            border: 2px solid #2ea043; border-radius: 16px;
            padding: 2rem; text-align: center; margin: 1rem 0;
        }
        .result-danger {
            background: linear-gradient(135deg, #3d0d0d, #6b1f1f);
            border: 2px solid #f85149; border-radius: 16px;
            padding: 2rem; text-align: center; margin: 1rem 0;
        }
        .result-title { font-size: 2rem; font-weight: 800; margin-bottom: 0.5rem; }
        .result-subtitle { font-size: 1rem; opacity: 0.8; }
        .feature-card {
            background: #161b22; border: 1px solid #30363d;
            border-radius: 12px; padding: 1rem 1.5rem; margin: 0.5rem 0;
        }
        .stat-box {
            background: #161b22; border: 1px solid #30363d;
            border-radius: 12px; padding: 1rem; text-align: center;
        }
        .stTextInput input {
            background-color: #161b22 !important; color: #e6edf3 !important;
            border: 1px solid #30363d !important; border-radius: 8px !important;
        }
        .stTextArea textarea {
            background-color: #161b22 !important; color: #e6edf3 !important;
            border: 1px solid #30363d !important; border-radius: 8px !important;
        }
        .stButton > button {
            background: linear-gradient(90deg, #58a6ff, #bc8cff);
            color: white; font-weight: 700; border: none;
            border-radius: 8px; padding: 0.6rem 2rem; font-size: 1rem; width: 100%;
        }
        .stButton > button:hover { opacity: 0.85; }
        .footer {
            text-align: center; color: #8b949e; font-size: 0.8rem;
            margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #30363d;
        }
        hr { border-color: #30363d; }
    </style>
""", unsafe_allow_html=True)

# ── Load Models ──
@st.cache_resource
def load_url_model():
    with open("Model/url_model.pkl", "rb") as f:
        data = pickle.load(f)
    return data["model"], data["feature_cols"]

@st.cache_resource
def load_email_model():
    with open("Model/email_model.pkl", "rb") as f:
        return pickle.load(f)

try:
    url_model, feature_cols = load_url_model()
    url_model_loaded = True
except:
    url_model_loaded = False

try:
    email_pipeline = load_email_model()
    email_model_loaded = True
except:
    email_model_loaded = False

# ── URL Helpers ──
PHISHING_KEYWORDS = ["login","verify","secure","update","confirm","account",
    "banking","paypal","password","credential","signin","wallet",
    "alert","suspend","unlock","validate","authorize"]
SHORTENERS = {"bit.ly","tinyurl.com","goo.gl","ow.ly","t.co",
    "buff.ly","is.gd","rebrand.ly","short.io","cutt.ly"}
BRANDS = ["paypal","google","facebook","amazon","apple",
    "microsoft","netflix","instagram","twitter","bank"]

def extract_features_from_url(url):
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        full = url.lower()
    except:
        return pd.DataFrame([{col: 0 for col in feature_cols}])
    parts = hostname.split(".")
    tld = parts[-1] if parts else ""
    subdomain_parts = parts[:-2] if len(parts) > 2 else []
    f = {col: 0 for col in feature_cols}
    f["length_url"] = len(url)
    f["length_hostname"] = len(hostname)
    f["ip"] = int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname)))
    f["nb_dots"] = url.count(".")
    f["nb_hyphens"] = url.count("-")
    f["nb_at"] = url.count("@")
    f["nb_qm"] = url.count("?")
    f["nb_and"] = url.count("&")
    f["nb_or"] = url.count("|")
    f["nb_eq"] = url.count("=")
    f["nb_underscore"] = url.count("_")
    f["nb_tilde"] = url.count("~")
    f["nb_percent"] = url.count("%")
    f["nb_slash"] = url.count("/")
    f["nb_star"] = url.count("*")
    f["nb_colon"] = url.count(":")
    f["nb_comma"] = url.count(",")
    f["nb_semicolumn"] = url.count(";")
    f["nb_dollar"] = url.count("$")
    f["nb_space"] = url.count(" ")
    f["nb_www"] = full.count("www")
    f["nb_com"] = full.count(".com")
    f["nb_dslash"] = full.count("//")
    f["http_in_path"] = int("http" in path.lower())
    f["https_token"] = int(parsed.scheme == "https")
    f["ratio_digits_url"] = sum(c.isdigit() for c in url) / max(len(url), 1)
    f["ratio_digits_host"] = sum(c.isdigit() for c in hostname) / max(len(hostname), 1)
    f["punycode"] = int("xn--" in hostname)
    f["port"] = int(parsed.port is not None)
    f["tld_in_path"] = int(tld in path)
    f["tld_in_subdomain"] = int(any(tld in s for s in subdomain_parts))
    f["abnormal_subdomain"] = int(len(subdomain_parts) > 2)
    f["nb_subdomains"] = max(0, len(parts) - 2)
    f["prefix_suffix"] = int("-" in hostname)
    f["shortening_service"] = int(hostname in SHORTENERS)
    f["phish_hints"] = sum(kw in full for kw in PHISHING_KEYWORDS)
    f["brand_in_subdomain"] = int(any(b in " ".join(subdomain_parts) for b in BRANDS))
    f["brand_in_path"] = int(any(b in path.lower() for b in BRANDS))
    row = pd.DataFrame([f])
    for col in feature_cols:
        if col not in row.columns:
            row[col] = 0
    return row[feature_cols]

def get_url_flags(url):
    flags = []
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        full = url.lower()
        if parsed.scheme != "https":
            flags.append(("🔓", "Not using HTTPS", "Secure sites use HTTPS"))
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
            flags.append(("🔢", "IP address used as domain", "Legitimate sites use domain names"))
        if hostname in SHORTENERS:
            flags.append(("🔗", "URL shortener detected", "Hides the real destination"))
        if url.count("@") > 0:
            flags.append(("⚠️", "@ symbol in URL", "Used to redirect to malicious sites"))
        if "-" in hostname:
            flags.append(("➖", "Hyphen in domain", "Common in fake domains"))
        kws = [kw for kw in PHISHING_KEYWORDS if kw in full]
        if kws:
            flags.append(("🎣", f"Phishing keywords: {', '.join(kws[:3])}", "Common in phishing URLs"))
        if len(url) > 75:
            flags.append(("📏", f"Very long URL ({len(url)} chars)", "Long URLs often hide malicious paths"))
        if url.count(".") > 4:
            flags.append(("🔴", "Too many dots in URL", "Multiple subdomains are suspicious"))
    except:
        pass
    return flags

# ── Email Helpers ──
URGENCY_WORDS = ["urgent","immediately","act now","limited time","expires",
    "suspended","verify now","confirm now","within 24 hours",
    "your account","click here","click below","click the link"]
MONEY_WORDS = ["winner","won","prize","lottery","cash","reward",
    "million","billion","transfer","inheritance","investment"]
THREAT_WORDS = ["suspended","terminated","blocked","locked","unauthorized",
    "suspicious activity","security alert","breach","hacked"]

def get_email_flags(text):
    flags = []
    text_lower = text.lower()
    urgency = [w for w in URGENCY_WORDS if w in text_lower]
    if urgency:
        flags.append(("⏰", f"Urgency language: {', '.join(urgency[:2])}", "Phishing emails create false urgency"))
    money = [w for w in MONEY_WORDS if w in text_lower]
    if money:
        flags.append(("💰", f"Money keywords: {', '.join(money[:2])}", "Common in scam emails"))
    threats = [w for w in THREAT_WORDS if w in text_lower]
    if threats:
        flags.append(("🚨", f"Threat language: {', '.join(threats[:2])}", "Used to scare recipients into clicking"))
    url_count = len(re.findall(r'http[s]?://', text))
    if url_count > 3:
        flags.append(("🔗", f"{url_count} links found in email", "Excessive links are suspicious"))
    if re.search(r'\b[A-Z]{4,}\b', text):
        flags.append(("📢", "Excessive CAPS detected", "Common attention-grabbing tactic"))
    if len(text) < 100:
        flags.append(("📄", "Very short email", "Phishing emails are often brief with a single call to action"))
    return flags

# ── Header ──
st.markdown('<div class="main-title">🛡️ PhishGuard</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">AI-Powered Phishing Detector </div>', unsafe_allow_html=True)
st.markdown("---")

tab1, tab2, tab3, tab4 = st.tabs(["🔍 Check URL", "📧 Check Email", "📊 Model Stats", "ℹ️ About"])

# ══ TAB 1 — URL ══
with tab1:
    st.markdown("### Enter a URL to analyse")
    url_input = st.text_input("", placeholder="e.g. http://paypal-secure-login.verify-account.com/update",
        label_visibility="collapsed", key="url_input")
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        analyse_url_btn = st.button("🔍 Analyse URL", use_container_width=True, key="url_btn")

    if analyse_url_btn:
        if not url_input.strip():
            st.warning("⚠️ Please enter a URL first.")
        elif not url_model_loaded:
            st.error("URL Model not loaded. Run train_url.py first.")
        else:
            with st.spinner("Analysing URL..."):
                features_df = extract_features_from_url(url_input.strip())
                prediction = url_model.predict(features_df)[0]
                confidence = url_model.predict_proba(features_df)[0]
                confidence_pct = int(max(confidence) * 100)
                flags = get_url_flags(url_input.strip())

                if prediction == 1:
                    st.markdown(f'<div class="result-danger"><div class="result-title">⚠️ PHISHING DETECTED</div><div class="result-subtitle">Do not visit this URL!</div><br><div style="font-size:2rem;font-weight:800;color:#f85149;">{confidence_pct}% Confidence</div></div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="result-safe"><div class="result-title">✅ LOOKS SAFE</div><div class="result-subtitle">This URL appears to be legitimate.</div><br><div style="font-size:2rem;font-weight:800;color:#2ea043;">{confidence_pct}% Confidence</div></div>', unsafe_allow_html=True)

                st.markdown("#### Confidence Score")
                col_l, col_r = st.columns(2)
                with col_l: st.metric("✅ Legitimate", f"{int(confidence[0]*100)}%")
                with col_r: st.metric("⚠️ Phishing", f"{int(confidence[1]*100)}%")
                st.progress(int(confidence[1] * 100))

                if flags:
                    st.markdown("#### 🚩 Red Flags Detected")
                    for icon, flag, reason in flags:
                        st.markdown(f'<div class="feature-card"><b>{icon} {flag}</b><br><span style="color:#8b949e;font-size:0.9rem;">{reason}</span></div>', unsafe_allow_html=True)
                else:
                    st.success("No obvious red flags found in this URL structure.")

                st.markdown("#### 🔬 URL Breakdown")
                try:
                    parsed = urlparse(url_input if url_input.startswith("http") else "http://" + url_input)
                    st.dataframe(pd.DataFrame({
                        "Component": ["Scheme","Hostname","Path","Query","URL Length"],
                        "Value": [parsed.scheme, parsed.hostname or "N/A", parsed.path or "/",
                                  parsed.query or "None", f"{len(url_input)} characters"]
                    }), hide_index=True, use_container_width=True)
                except: pass

# ══ TAB 2 — EMAIL ══
with tab2:
    st.markdown("### Paste an Email to analyse")
    st.markdown("Copy and paste the full email text below.")
    email_input = st.text_area("", height=200,
        placeholder="Paste email text here...\n\nExample:\nDear user, your account has been suspended. Click here immediately to verify your identity...",
        label_visibility="collapsed", key="email_input")
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        analyse_email_btn = st.button("📧 Analyse Email", use_container_width=True, key="email_btn")

    if analyse_email_btn:
        if not email_input.strip():
            st.warning("⚠️ Please paste some email text first.")
        elif not email_model_loaded:
            st.error("Email model not loaded. Run train_email.py first.")
        else:
            with st.spinner("Analysing email..."):
                prediction = email_pipeline.predict([email_input.strip()])[0]
                confidence = email_pipeline.predict_proba([email_input.strip()])[0]
                confidence_pct = int(max(confidence) * 100)
                flags = get_email_flags(email_input.strip())

                if prediction == 1:
                    st.markdown(f'<div class="result-danger"><div class="result-title">⚠️ PHISHING EMAIL DETECTED</div><div class="result-subtitle">Do not click any links in this email!</div><br><div style="font-size:2rem;font-weight:800;color:#f85149;">{confidence_pct}% Confidence</div></div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="result-safe"><div class="result-title">✅ EMAIL LOOKS SAFE</div><div class="result-subtitle">This email appears to be legitimate.</div><br><div style="font-size:2rem;font-weight:800;color:#2ea043;">{confidence_pct}% Confidence</div></div>', unsafe_allow_html=True)

                st.markdown("#### Confidence Score")
                col_l, col_r = st.columns(2)
                with col_l: st.metric("✅ Legitimate", f"{int(confidence[0]*100)}%")
                with col_r: st.metric("⚠️ Phishing", f"{int(confidence[1]*100)}%")
                st.progress(int(confidence[1] * 100))

                if flags:
                    st.markdown("#### 🚩 Red Flags Detected")
                    for icon, flag, reason in flags:
                        st.markdown(f'<div class="feature-card"><b>{icon} {flag}</b><br><span style="color:#8b949e;font-size:0.9rem;">{reason}</span></div>', unsafe_allow_html=True)
                else:
                    st.success("No obvious red flags found in this email.")

                st.markdown("#### 📊 Email Stats")
                st.dataframe(pd.DataFrame({
                    "Metric": ["Word Count","Links Found","CAPS Words","Characters"],
                    "Value": [len(email_input.split()),
                              len(re.findall(r'http[s]?://', email_input)),
                              len(re.findall(r'\b[A-Z]{4,}\b', email_input)),
                              len(email_input)]
                }), hide_index=True, use_container_width=True)

# ══ TAB 3 — STATS ══
with tab3:
    st.markdown("### 📊 Model Performance")
    st.markdown("#### 🔍 URL Detection Model")
    col1, col2, col3 = st.columns(3)
    with col1: st.markdown('<div class="stat-box"><div style="font-size:2rem;">🎯</div><div style="font-size:1.8rem;font-weight:800;color:#58a6ff;">89.55%</div><div style="color:#8b949e;">Accuracy</div></div>', unsafe_allow_html=True)
    with col2: st.markdown('<div class="stat-box"><div style="font-size:2rem;">📦</div><div style="font-size:1.8rem;font-weight:800;color:#bc8cff;">11,430</div><div style="color:#8b949e;">URLs Trained On</div></div>', unsafe_allow_html=True)
    with col3: st.markdown('<div class="stat-box"><div style="font-size:2rem;">🧠</div><div style="font-size:1.8rem;font-weight:800;color:#2ea043;">38</div><div style="color:#8b949e;">Features Used</div></div>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### 📧 Email Detection Model")
    col1, col2, col3 = st.columns(3)
    with col1: st.markdown('<div class="stat-box"><div style="font-size:2rem;">🎯</div><div style="font-size:1.8rem;font-weight:800;color:#58a6ff;">98.28%</div><div style="color:#8b949e;">Accuracy</div></div>', unsafe_allow_html=True)
    with col2: st.markdown('<div class="stat-box"><div style="font-size:2rem;">📦</div><div style="font-size:1.8rem;font-weight:800;color:#bc8cff;">82,486</div><div style="color:#8b949e;">Emails Trained On</div></div>', unsafe_allow_html=True)
    with col3: st.markdown('<div class="stat-box"><div style="font-size:2rem;">🧠</div><div style="font-size:1.8rem;font-weight:800;color:#2ea043;">10,000</div><div style="color:#8b949e;">TF-IDF Features</div></div>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 🗂️ Confusion Matrices")
    col1, col2 = st.columns(2)
    with col1:
        try: st.image("Model/confusion_matrix.png", caption="URL Model", use_container_width=True)
        except: st.info("Run train_url.py to generate")
    with col2:
        try: st.image("Model/email_confusion_matrix.png", caption="Email Model", use_container_width=True)
        except: st.info("Run train_email.py to generate")

# ══ TAB 4 — ABOUT ══
with tab4:
    st.markdown("### 🛡️ About PhishGuard")
    st.markdown("""
    **PhishGuard** is an AI-powered phishing detection system built by **Krish Malik**.
    It detects phishing in both **URLs and Emails** using Machine Learning.

    ---
    ### 🔬 How it works
    1. Paste a URL or Email into the dashboard
    2. PhishGuard extracts features automatically
    3. Trained ML models analyse the features instantly
    4. You get a result with confidence score and red flags

    ---
    ### 📊 Model Performance
    | Model | Algorithm | Accuracy | Training Data |
    |-------|-----------|----------|--------------|
    | URL Detector | Random Forest | 89.55% | 11,430 URLs |
    | Email Detector | TF-IDF + Logistic Regression | 98.28% | 82,486 Emails |

    ---
    ### ⚙️ Model Tuning
    URL model tuned using **GridSearchCV** across 48 combinations:
    - Trees: 300 | Max Depth: 20

    ---
    ### By
    **Krish Malik**
    """)

st.markdown('<div class="footer">🛡️ PhishGuard • Krish Malik • URL: 89.55% • Email: 98.28%</div>', unsafe_allow_html=True)

"""
app.py
PhishGuard — Streamlit Dashboard
Kraken'X 2026 Hackathon

Main application file. Run with:
    python -m streamlit run app.py
"""

import streamlit as st
import pandas as pd
import pickle
import re
import math
from urllib.parse import urlparse
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib.image as mpimg


# ──────────────────────────────────────────────
# PAGE CONFIG
# ──────────────────────────────────────────────

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="centered"
)


# ──────────────────────────────────────────────
# CUSTOM CSS STYLING
# ──────────────────────────────────────────────

st.markdown("""
    <style>
        /* Main background */
        .stApp {
            background-color: #0d1117;
            color: #e6edf3;
        }

        /* Title styling */
        .main-title {
            font-size: 3rem;
            font-weight: 800;
            text-align: center;
            background: linear-gradient(90deg, #58a6ff, #bc8cff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0rem;
        }

        .subtitle {
            text-align: center;
            color: #8b949e;
            font-size: 1rem;
            margin-bottom: 2rem;
        }

        /* Result boxes */
        .result-safe {
            background: linear-gradient(135deg, #0d3320, #1a5c38);
            border: 2px solid #2ea043;
            border-radius: 16px;
            padding: 2rem;
            text-align: center;
            margin: 1rem 0;
        }

        .result-danger {
            background: linear-gradient(135deg, #3d0d0d, #6b1f1f);
            border: 2px solid #f85149;
            border-radius: 16px;
            padding: 2rem;
            text-align: center;
            margin: 1rem 0;
        }

        .result-title {
            font-size: 2rem;
            font-weight: 800;
            margin-bottom: 0.5rem;
        }

        .result-subtitle {
            font-size: 1rem;
            opacity: 0.8;
        }

        /* Feature card */
        .feature-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 1rem 1.5rem;
            margin: 0.5rem 0;
        }

        /* Stats */
        .stat-box {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 1rem;
            text-align: center;
        }

        /* Divider */
        hr {
            border-color: #30363d;
        }

        /* Input box */
        .stTextInput input {
            background-color: #161b22 !important;
            color: #e6edf3 !important;
            border: 1px solid #30363d !important;
            border-radius: 8px !important;
            font-size: 1rem !important;
        }

        /* Button */
        .stButton > button {
            background: linear-gradient(90deg, #58a6ff, #bc8cff);
            color: white;
            font-weight: 700;
            border: none;
            border-radius: 8px;
            padding: 0.6rem 2rem;
            font-size: 1rem;
            width: 100%;
        }

        .stButton > button:hover {
            opacity: 0.85;
        }

        /* Tab styling */
        .stTabs [data-baseweb="tab"] {
            color: #8b949e;
        }

        .stTabs [aria-selected="true"] {
            color: #58a6ff !important;
        }

        /* Footer */
        .footer {
            text-align: center;
            color: #8b949e;
            font-size: 0.8rem;
            margin-top: 3rem;
            padding-top: 1rem;
            border-top: 1px solid #30363d;
        }
    </style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────
# LOAD MODEL
# ──────────────────────────────────────────────

@st.cache_resource
def load_model():
    with open("Model/url_model.pkl", "rb") as f:
        data = pickle.load(f)
    return data["model"], data["feature_cols"]

try:
    model, feature_cols = load_model()
    model_loaded = True
except Exception as e:
    model_loaded = False
    st.error(f"⚠️ Could not load model: {e}. Please run train_url.py first.")


# ──────────────────────────────────────────────
# FEATURE EXTRACTION (mirrors dataset features)
# ──────────────────────────────────────────────

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "update", "confirm", "account",
    "banking", "paypal", "password", "credential", "signin", "wallet",
    "alert", "suspend", "unlock", "validate", "authorize"
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "buff.ly", "is.gd", "rebrand.ly", "short.io", "cutt.ly"
}

BRANDS = ["paypal", "google", "facebook", "amazon", "apple",
          "microsoft", "netflix", "instagram", "twitter", "bank"]


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def extract_features_from_url(url: str) -> pd.DataFrame:
    """Extract features matching the training dataset columns."""
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        full = url.lower()
    except Exception:
        return pd.DataFrame([{col: 0 for col in feature_cols}])

    def count(char): return url.count(char)

    parts = hostname.split(".")
    tld = parts[-1] if parts else ""
    subdomain_parts = parts[:-2] if len(parts) > 2 else []

    f = {col: 0 for col in feature_cols}  # start with zeros

    # Fill what we can extract directly
    f["length_url"] = len(url)
    f["length_hostname"] = len(hostname)
    f["ip"] = int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname)))
    f["nb_dots"] = count(".")
    f["nb_hyphens"] = count("-")
    f["nb_at"] = count("@")
    f["nb_qm"] = count("?")
    f["nb_and"] = count("&")
    f["nb_or"] = count("|")
    f["nb_eq"] = count("=")
    f["nb_underscore"] = count("_")
    f["nb_tilde"] = count("~")
    f["nb_percent"] = count("%")
    f["nb_slash"] = count("/")
    f["nb_star"] = count("*")
    f["nb_colon"] = count(":")
    f["nb_comma"] = count(",")
    f["nb_semicolumn"] = count(";")
    f["nb_dollar"] = count("$")
    f["nb_space"] = count(" ")
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
    # Ensure column order matches training
    for col in feature_cols:
        if col not in row.columns:
            row[col] = 0
    return row[feature_cols]


def get_url_flags(url: str) -> list:
    """Return list of human-readable red flags found in the URL."""
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
        if any(b in hostname.replace(".".join(hostname.split(".")[-2:]), "") for b in BRANDS):
            flags.append(("🏷️", "Brand name in subdomain", "Classic brand spoofing technique"))
        if len(url) > 75:
            flags.append(("📏", f"Very long URL ({len(url)} chars)", "Long URLs often hide malicious paths"))
        if url.count(".") > 4:
            flags.append(("🔴", "Too many dots in URL", "Multiple subdomains are suspicious"))
    except Exception:
        pass
    return flags


# ──────────────────────────────────────────────
# HEADER
# ──────────────────────────────────────────────

st.markdown('<div class="main-title">🛡️ PhishGuard</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">AI-Powered Phishing URL Detector • Kraken\'X 2026</div>', unsafe_allow_html=True)

st.markdown("---")


# ──────────────────────────────────────────────
# TABS
# ──────────────────────────────────────────────

tab1, tab2, tab3 = st.tabs(["🔍 Check URL", "📊 Model Stats", "ℹ️ About"])


# ══════════════════════════════════════════════
# TAB 1 — CHECK URL
# ══════════════════════════════════════════════

with tab1:
    st.markdown("### Enter a URL to analyse")
    st.markdown("Paste any URL below and PhishGuard will instantly tell you if it's safe or a phishing attempt.")

    url_input = st.text_input(
        "",
        placeholder="e.g. http://paypal-secure-login.verify-account.com/update",
        label_visibility="collapsed"
    )

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        analyse_btn = st.button("🔍 Analyse URL", use_container_width=True)

    if analyse_btn:
        if not url_input.strip():
            st.warning("⚠️ Please enter a URL first.")
        elif not model_loaded:
            st.error("Model not loaded. Please run train_url.py first.")
        else:
            with st.spinner("Analysing URL..."):

                # Extract features & predict
                features_df = extract_features_from_url(url_input.strip())
                prediction = model.predict(features_df)[0]
                confidence = model.predict_proba(features_df)[0]
                confidence_pct = int(max(confidence) * 100)

                # Get red flags
                flags = get_url_flags(url_input.strip())

                # ── Result Box ──
                if prediction == 1:
                    st.markdown(f"""
                        <div class="result-danger">
                            <div class="result-title">⚠️ PHISHING DETECTED</div>
                            <div class="result-subtitle">This URL appears to be malicious — do not visit it!</div>
                            <br>
                            <div style="font-size:2rem; font-weight:800; color:#f85149;">{confidence_pct}% Confidence</div>
                        </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                        <div class="result-safe">
                            <div class="result-title">✅ LOOKS SAFE</div>
                            <div class="result-subtitle">This URL appears to be legitimate.</div>
                            <br>
                            <div style="font-size:2rem; font-weight:800; color:#2ea043;">{confidence_pct}% Confidence</div>
                        </div>
                    """, unsafe_allow_html=True)

                # ── Confidence Bar ──
                st.markdown("#### Confidence Score")
                col_l, col_r = st.columns(2)
                with col_l:
                    st.metric("✅ Legitimate", f"{int(confidence[0]*100)}%")
                with col_r:
                    st.metric("⚠️ Phishing", f"{int(confidence[1]*100)}%")

                st.progress(int(confidence[1] * 100))

                # ── Red Flags ──
                if flags:
                    st.markdown("#### 🚩 Red Flags Detected")
                    for icon, flag, reason in flags:
                        st.markdown(f"""
                            <div class="feature-card">
                                <b>{icon} {flag}</b><br>
                                <span style="color:#8b949e; font-size:0.9rem;">{reason}</span>
                            </div>
                        """, unsafe_allow_html=True)
                else:
                    st.markdown("#### 🚩 Red Flags")
                    st.success("No obvious red flags found in this URL structure.")

                # ── URL Breakdown ──
                st.markdown("#### 🔬 URL Breakdown")
                try:
                    parsed = urlparse(url_input if url_input.startswith("http") else "http://" + url_input)
                    breakdown_df = pd.DataFrame({
                        "Component": ["Scheme", "Hostname", "Path", "Query", "URL Length"],
                        "Value": [
                            parsed.scheme,
                            parsed.hostname or "N/A",
                            parsed.path or "/",
                            parsed.query or "None",
                            f"{len(url_input)} characters"
                        ]
                    })
                    st.dataframe(breakdown_df, hide_index=True, use_container_width=True)
                except Exception:
                    pass


# ══════════════════════════════════════════════
# TAB 2 — MODEL STATS
# ══════════════════════════════════════════════

with tab2:
    st.markdown("### 📊 Model Performance")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
            <div class="stat-box">
                <div style="font-size:2rem;">🎯</div>
                <div style="font-size:1.8rem; font-weight:800; color:#58a6ff;">96.11%</div>
                <div style="color:#8b949e;">Accuracy</div>
            </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown("""
            <div class="stat-box">
                <div style="font-size:2rem;">📦</div>
                <div style="font-size:1.8rem; font-weight:800; color:#bc8cff;">11,430</div>
                <div style="color:#8b949e;">URLs Trained On</div>
            </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown("""
            <div class="stat-box">
                <div style="font-size:2rem;">🧠</div>
                <div style="font-size:1.8rem; font-weight:800; color:#2ea043;">87</div>
                <div style="color:#8b949e;">Features Used</div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 🗂️ Confusion Matrix")
    st.markdown("Shows how many URLs were correctly vs incorrectly classified.")

    try:
        img = mpimg.imread("Model/confusion_matrix.png")
        st.image(img, caption="Confusion Matrix — PhishGuard URL Model", use_container_width=True)
    except Exception:
        st.info("Run train_url.py to generate the confusion matrix.")

    st.markdown("---")
    st.markdown("### 🔍 Top Features the Model Uses")
    features_importance = {
        "google_index": 18.36,
        "page_rank": 10.29,
        "nb_hyperlinks": 8.63,
        "web_traffic": 7.56,
        "nb_www": 4.03,
        "domain_age": 3.20,
        "phish_hints": 3.00,
        "ratio_extHyperlinks": 2.74,
        "ratio_intHyperlinks": 2.68,
        "safe_anchor": 2.45,
    }
    feat_df = pd.DataFrame(
        list(features_importance.items()),
        columns=["Feature", "Importance (%)"]
    ).sort_values("Importance (%)", ascending=True)

    fig, ax = plt.subplots(figsize=(8, 5))
    fig.patch.set_facecolor("#0d1117")
    ax.set_facecolor("#161b22")
    bars = ax.barh(feat_df["Feature"], feat_df["Importance (%)"],
                   color="#58a6ff", edgecolor="none")
    ax.set_xlabel("Importance (%)", color="#8b949e")
    ax.tick_params(colors="#e6edf3")
    ax.spines[:].set_color("#30363d")
    ax.set_title("Top 10 Most Important Features", color="#e6edf3", fontsize=13)
    st.pyplot(fig)


# ══════════════════════════════════════════════
# TAB 3 — ABOUT
# ══════════════════════════════════════════════

with tab3:
    st.markdown("###  About PhishGuard")
    st.markdown("""
    **PhishGuard** is an AI-powered phishing URL detection system built for **Kraken'X 2026** hackathon.

    It uses a **Random Forest classifier** trained on 11,430 real-world URLs to detect phishing attempts
    with **96.11% accuracy**.

    ---

    ### 🔬 How it works
    1. You paste a URL into the input box
    2. PhishGuard extracts 87 features from the URL (length, symbols, keywords, domain structure, etc.)
    3. The trained ML model analyses these features
    4. You get an instant result with a confidence score and red flags

    ---

    ### 🧰 Tech Stack
    | Component | Technology |
    |-----------|-----------|
    | ML Model | Random Forest (scikit-learn) |
    | Dataset | Kaggle Phishing Dataset (11,430 URLs) |
    | Dashboard | Streamlit |
    | Language | Python 3.14 |

    ---

    ### 👥 Team
    Built with ❤️ at **Kraken'X 2026**
    *AI/ML Club × AI-Tronics Hub*
    """)


# ──────────────────────────────────────────────
# FOOTER
# ──────────────────────────────────────────────

st.markdown("""
    <div class="footer">
         PhishGuard • Built for Kraken'X 2026 •
        Made by Krish Malik
    </div>
""", unsafe_allow_html=True)

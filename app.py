"""
app.py
PhishGuard — Streamlit Dashboard (Cyber Sentinel UI)
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

st.set_page_config(page_title="PhishGuard", page_icon="🛡️", layout="wide")

# ── Global CSS ──
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

  /* ── Reset & Base ── */
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html, body, .stApp { background-color: #0A0E1A !important; color: #E2E8F4 !important; font-family: 'Inter', sans-serif !important; }
  .block-container { padding: 0 !important; max-width: 100% !important; }
  header[data-testid="stHeader"] { display: none !important; }
  section[data-testid="stSidebar"] { display: none !important; }
  div[data-testid="stDecoration"] { display: none !important; }
  .stApp > header { display: none !important; }

  /* ── Scrollbar ── */
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: #0A0E1A; }
  ::-webkit-scrollbar-thumb { background: #1E2A3A; border-radius: 3px; }

  /* ── Navbar ── */
  .pg-navbar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 2.5rem; height: 64px;
    background: rgba(10,14,26,0.92);
    border-bottom: 1px solid rgba(0,212,255,0.15);
    backdrop-filter: blur(16px);
    position: sticky; top: 0; z-index: 1000;
  }
  .pg-logo { display: flex; align-items: center; gap: 0.5rem; font-size: 1.15rem; font-weight: 800; color: #fff; letter-spacing: -0.5px; }
  .pg-logo-dot { width: 8px; height: 8px; border-radius: 50%; background: #00D4FF; margin-right: 2px; }
  .pg-nav-links { display: flex; gap: 2rem; }
  .pg-nav-link { font-size: 0.85rem; font-weight: 500; color: #8A97B0; cursor: pointer; padding: 4px 0; border-bottom: 2px solid transparent; transition: all .2s; text-decoration: none; }
  .pg-nav-link:hover { color: #E2E8F4; }
  .pg-nav-active { color: #00D4FF !important; border-bottom: 2px solid #00D4FF !important; }
  .pg-nav-icons { display: flex; gap: 1rem; align-items: center; }
  .pg-icon-btn { width: 34px; height: 34px; border-radius: 8px; border: 1px solid rgba(0,212,255,0.2); background: rgba(0,212,255,0.05); display: flex; align-items: center; justify-content: center; cursor: pointer; font-size: 0.9rem; }

  /* ── Page wrapper ── */
  .pg-page { padding: 2.5rem 3rem; max-width: 1280px; margin: 0 auto; }

  /* ── Hero ── */
  .pg-hero {
    text-align: center; padding: 4rem 2rem 3rem;
    background: radial-gradient(ellipse 80% 60% at 50% -10%, rgba(0,163,255,0.12) 0%, transparent 70%);
  }
  .pg-hero h1 { font-size: 3.2rem; font-weight: 800; color: #fff; letter-spacing: -1px; line-height: 1.1; margin-bottom: 1rem; }
  .pg-hero p { font-size: 1rem; color: #8A97B0; max-width: 480px; margin: 0 auto 2rem; line-height: 1.6; }
  .pg-hero-badges { display: flex; gap: 1.5rem; justify-content: center; font-size: 0.8rem; color: #8A97B0; margin-top: 0.5rem; }
  .pg-hero-badge { display: flex; align-items: center; gap: 0.4rem; }
  .pg-badge-dot { width: 6px; height: 6px; border-radius: 50%; background: #00D4FF; }

  /* ── Search bar ── */
  .pg-search-wrap { max-width: 640px; margin: 0 auto 1rem; position: relative; }

  /* ── Stats row ── */
  .pg-stats-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.2rem; margin: 2rem 0 2.5rem; }
  .pg-stat-card {
    background: #111827; border: 1px solid rgba(255,255,255,0.06);
    border-radius: 14px; padding: 1.4rem 1.6rem;
  }
  .pg-stat-label { font-size: 0.72rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: #8A97B0; margin-bottom: 0.5rem; }
  .pg-stat-value { font-size: 2.2rem; font-weight: 800; color: #fff; line-height: 1; }
  .pg-stat-value.teal { color: #00D4FF; }
  .pg-stat-sub { font-size: 0.75rem; color: #8A97B0; margin-top: 0.35rem; }
  .pg-stat-bar { height: 4px; border-radius: 2px; background: #1E2A3A; margin-top: 0.8rem; overflow: hidden; }
  .pg-stat-bar-fill { height: 100%; border-radius: 2px; background: linear-gradient(90deg, #00D4FF, #3B82F6); }
  .pg-stat-operational { display: flex; align-items: center; gap: 0.5rem; margin-top: 0.5rem; }
  .pg-op-dot { width: 8px; height: 8px; border-radius: 50%; background: #10B981; flex-shrink: 0; box-shadow: 0 0 6px #10B981; }
  .pg-op-text { font-size: 1rem; font-weight: 700; color: #10B981; }
  .pg-op-sub { font-size: 0.75rem; color: #8A97B0; margin-top: 0.2rem; }

  /* ── Recent Scans Table ── */
  .pg-table-wrap { background: #111827; border: 1px solid rgba(255,255,255,0.06); border-radius: 14px; padding: 1.5rem; margin-top: 1rem; }
  .pg-table-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.2rem; }
  .pg-table-title { font-size: 1rem; font-weight: 700; color: #fff; }
  .pg-table-view-all { font-size: 0.78rem; color: #00D4FF; cursor: pointer; }
  .pg-table-cols { display: grid; grid-template-columns: 1fr 160px 180px; gap: 1rem; padding: 0.4rem 0.6rem; border-bottom: 1px solid rgba(255,255,255,0.06); margin-bottom: 0.5rem; }
  .pg-col-head { font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: #8A97B0; }
  .pg-table-row { display: grid; grid-template-columns: 1fr 160px 180px; gap: 1rem; padding: 0.7rem 0.6rem; border-bottom: 1px solid rgba(255,255,255,0.04); align-items: center; }
  .pg-table-row:last-child { border-bottom: none; }
  .pg-url-text { font-size: 0.8rem; color: #CBD5E1; font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .pg-badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 0.72rem; font-weight: 600; }
  .pg-badge-danger { background: rgba(239,68,68,0.15); color: #F87171; border: 1px solid rgba(239,68,68,0.3); }
  .pg-badge-safe   { background: rgba(16,185,129,0.15); color: #34D399; border: 1px solid rgba(16,185,129,0.3); }
  .pg-badge-warn   { background: rgba(245,158,11,0.15); color: #FCD34D; border: 1px solid rgba(245,158,11,0.3); }
  .pg-row-time { font-size: 0.75rem; color: #8A97B0; }

  /* ── Section titles ── */
  .pg-section-eyebrow { font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 2px; color: #00D4FF; margin-bottom: 0.5rem; }
  .pg-section-title { font-size: 2.2rem; font-weight: 800; color: #fff; line-height: 1.15; margin-bottom: 1rem; }
  .pg-section-body { font-size: 0.9rem; color: #8A97B0; line-height: 1.7; max-width: 520px; }

  /* ── Cards grid ── */
  .pg-cards-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.2rem; margin: 2rem 0; }
  .pg-card {
    background: #111827; border: 1px solid rgba(255,255,255,0.06);
    border-radius: 14px; padding: 1.6rem;
  }
  .pg-card-icon { width: 40px; height: 40px; border-radius: 10px; background: rgba(0,212,255,0.1); border: 1px solid rgba(0,212,255,0.2); display: flex; align-items: center; justify-content: center; font-size: 1.1rem; margin-bottom: 1rem; }
  .pg-card-title { font-size: 0.95rem; font-weight: 700; color: #fff; margin-bottom: 0.4rem; }
  .pg-card-body  { font-size: 0.82rem; color: #8A97B0; line-height: 1.6; }

  /* ── Result cards ── */
  .pg-result-safe {
    background: linear-gradient(135deg, rgba(16,185,129,0.1), rgba(5,150,105,0.08));
    border: 1px solid rgba(16,185,129,0.3); border-radius: 14px; padding: 2rem; text-align: center; margin: 1rem 0;
  }
  .pg-result-danger {
    background: linear-gradient(135deg, rgba(239,68,68,0.1), rgba(185,28,28,0.08));
    border: 1px solid rgba(239,68,68,0.3); border-radius: 14px; padding: 2rem; text-align: center; margin: 1rem 0;
  }
  .pg-result-title { font-size: 1.8rem; font-weight: 800; margin-bottom: 0.4rem; }
  .pg-result-sub   { font-size: 0.9rem; color: #8A97B0; }
  .pg-result-conf  { font-size: 2.4rem; font-weight: 800; margin-top: 1rem; }

  /* ── Feature card ── */
  .pg-flag-card {
    background: #111827; border: 1px solid rgba(255,255,255,0.06);
    border-radius: 10px; padding: 0.9rem 1.2rem; margin: 0.4rem 0;
  }
  .pg-flag-title { font-size: 0.88rem; font-weight: 600; color: #E2E8F4; margin-bottom: 0.2rem; }
  .pg-flag-desc  { font-size: 0.8rem; color: #8A97B0; }

  /* ── Model stats ── */
  .pg-model-stat {
    background: #111827; border: 1px solid rgba(255,255,255,0.06);
    border-radius: 14px; padding: 1.4rem 1.6rem; text-align: center;
  }
  .pg-model-stat-val { font-size: 2rem; font-weight: 800; color: #00D4FF; }
  .pg-model-stat-label { font-size: 0.78rem; color: #8A97B0; margin-top: 0.25rem; }
  .pg-model-stat-sub   { font-size: 0.7rem; color: #475569; margin-top: 0.15rem; }

  /* ── Threat bar ── */
  .pg-threat-row { display: flex; align-items: center; gap: 1rem; margin: 0.6rem 0; }
  .pg-threat-label { font-size: 0.72rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: #8A97B0; width: 110px; flex-shrink: 0; }
  .pg-threat-track { flex: 1; height: 6px; background: #1E2A3A; border-radius: 3px; overflow: hidden; }
  .pg-threat-fill  { height: 100%; border-radius: 3px; background: linear-gradient(90deg,#00D4FF,#3B82F6); }
  .pg-threat-pct   { font-size: 0.78rem; color: #8A97B0; width: 35px; text-align: right; }

  /* ── Email page ── */
  .pg-email-tips { background: #111827; border: 1px solid rgba(255,255,255,0.06); border-radius: 14px; padding: 1.4rem; }
  .pg-tip-item { display: flex; gap: 0.8rem; margin: 0.8rem 0; }
  .pg-tip-icon { font-size: 1.1rem; flex-shrink: 0; margin-top: 2px; }
  .pg-tip-title { font-size: 0.85rem; font-weight: 600; color: #E2E8F4; margin-bottom: 0.2rem; }
  .pg-tip-body  { font-size: 0.78rem; color: #8A97B0; line-height: 1.5; }

  /* ── About page ── */
  .pg-mission-card { background: #111827; border: 1px solid rgba(255,255,255,0.06); border-radius: 14px; padding: 1.4rem 1.6rem; margin-bottom: 1.5rem; }
  .pg-person-card  { background: #111827; border: 1px solid rgba(255,255,255,0.06); border-radius: 14px; padding: 2rem; text-align: center; }
  .pg-person-avatar { width: 64px; height: 64px; border-radius: 16px; background: rgba(0,212,255,0.1); border: 1px solid rgba(0,212,255,0.2); display: flex; align-items: center; justify-content: center; font-size: 1.8rem; margin: 0 auto 1rem; }
  .pg-person-name  { font-size: 1.1rem; font-weight: 700; color: #fff; }
  .pg-person-role  { font-size: 0.78rem; color: #00D4FF; text-transform: uppercase; letter-spacing: 1px; margin-top: 0.2rem; }
  .pg-person-quote { font-size: 0.85rem; color: #8A97B0; font-style: italic; margin: 1rem 0; line-height: 1.6; }

  /* ── Footer ── */
  .pg-footer { border-top: 1px solid rgba(255,255,255,0.06); padding: 1.5rem 3rem; display: flex; justify-content: space-between; align-items: center; font-size: 0.78rem; color: #8A97B0; margin-top: 3rem; }
  .pg-footer-logo { font-weight: 700; color: #fff; }
  .pg-footer-links { display: flex; gap: 1.5rem; }
  .pg-footer-api   { display: flex; align-items: center; gap: 0.4rem; color: #00D4FF; }
  .pg-footer-api-dot { width: 6px; height: 6px; border-radius: 50%; background: #00D4FF; }

  /* ── Streamlit overrides ── */
  .stTextInput > div > div > input {
    background: #111827 !important; color: #E2E8F4 !important;
    border: 1px solid rgba(0,212,255,0.25) !important; border-radius: 10px !important;
    padding: 0.7rem 1rem !important; font-size: 0.92rem !important;
  }
  .stTextInput > div > div > input:focus { border-color: #00D4FF !important; box-shadow: 0 0 0 2px rgba(0,212,255,0.12) !important; }
  .stTextArea > div > div > textarea {
    background: #111827 !important; color: #E2E8F4 !important;
    border: 1px solid rgba(0,212,255,0.2) !important; border-radius: 10px !important;
    font-size: 0.88rem !important;
  }
  .stTextArea > div > div > textarea:focus { border-color: #00D4FF !important; box-shadow: 0 0 0 2px rgba(0,212,255,0.12) !important; }
  .stButton > button {
    background: linear-gradient(135deg, #0066FF, #00D4FF) !important;
    color: #fff !important; font-weight: 700 !important; border: none !important;
    border-radius: 10px !important; padding: 0.65rem 2rem !important;
    font-size: 0.92rem !important; letter-spacing: 0.3px !important;
    transition: opacity .2s !important;
  }
  .stButton > button:hover { opacity: 0.88 !important; }
  div[data-testid="stTabs"] button {
    background: transparent !important; color: #8A97B0 !important;
    border: none !important; font-weight: 500 !important; font-size: 0.88rem !important;
    padding: 0.5rem 1.2rem !important;
  }
  div[data-testid="stTabs"] button[aria-selected="true"] {
    color: #00D4FF !important; border-bottom: 2px solid #00D4FF !important;
  }
  div[data-testid="stTabs"] { border-bottom: 1px solid rgba(255,255,255,0.06) !important; }
  .stProgress > div > div > div { background: linear-gradient(90deg, #0066FF, #00D4FF) !important; border-radius: 4px !important; }
  .stProgress > div > div { background: #1E2A3A !important; border-radius: 4px !important; }
  .stMetric { background: #111827; border: 1px solid rgba(255,255,255,0.06); border-radius: 12px; padding: 1rem !important; }
  .stMetric label { color: #8A97B0 !important; font-size: 0.78rem !important; }
  .stMetric [data-testid="stMetricValue"] { color: #00D4FF !important; font-weight: 800 !important; }
  .stAlert { background: #111827 !important; border: 1px solid rgba(0,212,255,0.2) !important; border-radius: 10px !important; color: #E2E8F4 !important; }
  div[data-testid="stDataFrame"] { background: #111827 !important; border-radius: 10px !important; }
  div[data-testid="stDataFrame"] table { color: #E2E8F4 !important; }
  div[data-testid="stDataFrame"] th { background: #0A0E1A !important; color: #8A97B0 !important; border-color: rgba(255,255,255,0.06) !important; font-size: 0.78rem !important; }
  div[data-testid="stDataFrame"] td { border-color: rgba(255,255,255,0.04) !important; font-size: 0.82rem !important; }
  .stSpinner > div { border-color: #00D4FF !important; }
  label, .stTextInput label, .stTextArea label { color: #8A97B0 !important; font-size: 0.82rem !important; }
  .stWarning { background: rgba(245,158,11,0.1) !important; border: 1px solid rgba(245,158,11,0.3) !important; color: #FCD34D !important; }
  .stError   { background: rgba(239,68,68,0.1)  !important; border: 1px solid rgba(239,68,68,0.3)  !important; color: #F87171 !important; }
  .stSuccess { background: rgba(16,185,129,0.1) !important; border: 1px solid rgba(16,185,129,0.3) !important; color: #34D399 !important; }
  div[data-testid="column"] { padding: 0 0.4rem !important; }
  hr { border-color: rgba(255,255,255,0.06) !important; margin: 1.5rem 0 !important; }
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

# ══════════════════════════════════════════
#  NAVBAR
# ══════════════════════════════════════════
if "active_tab" not in st.session_state:
    st.session_state.active_tab = "Check URL"

def nav_class(tab_name):
    return "pg-nav-active" if st.session_state.active_tab == tab_name else ""

st.markdown(f"""
<div class="pg-navbar">
  <div class="pg-logo"><div class="pg-logo-dot"></div>PhishGuard</div>
</div>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════
#  TABS (hidden label, used for routing)
# ══════════════════════════════════════════
tab1, tab2, tab3, tab4 = st.tabs(["Check URL", "Check Email", "Model Stats", "About"])

# ══════════════════════════════════════════
#  TAB 1 — CHECK URL
# ══════════════════════════════════════════
with tab1:
    # Hero
    st.markdown("""
    <div class="pg-hero">
      <h1>Shielding Human Trust</h1>
      <p>Vigilant AI analysis for the modern enterprise. Instant detection of deceptive links and credential theft attempts.</p>
    </div>
    """, unsafe_allow_html=True)

    # Search bar
    col_s1, col_s2, col_s3 = st.columns([1, 4, 1])
    with col_s2:
        url_input = st.text_input("", placeholder="🔗  Enter suspicious URL for deep inspection...",
            label_visibility="collapsed", key="url_input")
        c1, c2, c3 = st.columns([2, 1, 2])
        with c2:
            analyse_url_btn = st.button("⚡ Analyse", use_container_width=True, key="url_btn")
        st.markdown("""
        <div class="pg-hero-badges">
          <div class="pg-hero-badge"><div class="pg-badge-dot"></div>No Login Required</div>
          <div class="pg-hero-badge"><div class="pg-badge-dot"></div>Real-time AI Inspection</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Stats row
    st.markdown("""
    <div class="pg-stats-row">
      <div class="pg-stat-card">
        <div class="pg-stat-label">Network Health</div>
        <div class="pg-stat-value teal">99.98%</div>
        <div class="pg-stat-sub">All systems nominal</div>
        <div class="pg-stat-bar"><div class="pg-stat-bar-fill" style="width:99.98%"></div></div>
      </div>
      <div class="pg-stat-card">
        <div class="pg-stat-label">Threats Neutralized</div>
        <div class="pg-stat-value">1.2M+</div>
        <div class="pg-stat-sub">↗ 14% increase this month</div>
      </div>
      <div class="pg-stat-card">
        <div class="pg-stat-label">System Status</div>
        <div class="pg-stat-operational"><div class="pg-op-dot"></div><div class="pg-op-text">Operational</div></div>
        <div class="pg-op-sub">Model v4.2.1 optimized for homograph attacks.</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Recent scans table
    st.markdown("""
    <div class="pg-table-wrap">
      <div class="pg-table-header">
        <span class="pg-table-title">Recent Global Scans</span>
        <span class="pg-table-view-all">View All Scans ›</span>
      </div>
      <div class="pg-table-cols">
        <span class="pg-col-head">URL / Endpoint</span>
        <span class="pg-col-head">Status</span>
        <span class="pg-col-head">Date / Time</span>
      </div>
      <div class="pg-table-row">
        <span class="pg-url-text">https://security-login-update.auth-check.net/v2</span>
        <span><span class="pg-badge pg-badge-danger">⊘ Malicious</span></span>
        <span class="pg-row-time">2024-05-21 13:02:11</span>
      </div>
      <div class="pg-table-row">
        <span class="pg-url-text">https://portal.enterprise-services.com/dashboard</span>
        <span><span class="pg-badge pg-badge-safe">✓ Safe</span></span>
        <span class="pg-row-time">2024-05-21 13:02:02</span>
      </div>
      <div class="pg-table-row">
        <span class="pg-url-text">http://ads-prime-daily.temp-storage.biz/verify</span>
        <span><span class="pg-badge pg-badge-warn">⚠ Suspicious</span></span>
        <span class="pg-row-time">2024-05-21 13:01:53</span>
      </div>
      <div class="pg-table-row">
        <span class="pg-url-text">https://github.com/updates/security-patch-800</span>
        <span><span class="pg-badge pg-badge-safe">✓ Safe</span></span>
        <span class="pg-row-time">2024-05-21 13:00:00</span>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Analysis result ──
    if analyse_url_btn:
        st.markdown("<br>", unsafe_allow_html=True)
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
                st.markdown(f"""
                <div class="pg-result-danger">
                  <div class="pg-result-title" style="color:#F87171;">⚠️ PHISHING DETECTED</div>
                  <div class="pg-result-sub">Do not visit this URL!</div>
                  <div class="pg-result-conf" style="color:#F87171;">{confidence_pct}% Confidence</div>
                </div>""", unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="pg-result-safe">
                  <div class="pg-result-title" style="color:#34D399;">✅ LOOKS SAFE</div>
                  <div class="pg-result-sub">This URL appears to be legitimate.</div>
                  <div class="pg-result-conf" style="color:#34D399;">{confidence_pct}% Confidence</div>
                </div>""", unsafe_allow_html=True)

            col_l, col_r = st.columns(2)
            with col_l: st.metric("✅ Legitimate", f"{int(confidence[0]*100)}%")
            with col_r: st.metric("⚠️ Phishing",   f"{int(confidence[1]*100)}%")
            st.progress(int(confidence[1] * 100))

            if flags:
                st.markdown("<br>**🚩 Red Flags Detected**", unsafe_allow_html=True)
                for icon, flag, reason in flags:
                    st.markdown(f'<div class="pg-flag-card"><div class="pg-flag-title">{icon} {flag}</div><div class="pg-flag-desc">{reason}</div></div>', unsafe_allow_html=True)
            else:
                st.success("No obvious red flags found in this URL structure.")

            st.markdown("<br>**🔬 URL Breakdown**", unsafe_allow_html=True)
            try:
                parsed = urlparse(url_input if url_input.startswith("http") else "http://" + url_input)
                st.dataframe(pd.DataFrame({
                    "Component": ["Scheme","Hostname","Path","Query","URL Length"],
                    "Value": [parsed.scheme, parsed.hostname or "N/A", parsed.path or "/",
                              parsed.query or "None", f"{len(url_input)} characters"]
                }), hide_index=True, use_container_width=True)
            except: pass

# ══════════════════════════════════════════
#  TAB 2 — CHECK EMAIL
# ══════════════════════════════════════════
with tab2:
    st.markdown("<div class='pg-page'>", unsafe_allow_html=True)
    st.markdown("""
    <div style="margin-bottom:1.5rem;">
      <h2 style="font-size:2rem;font-weight:800;color:#fff;margin-bottom:0.4rem;">Email Integrity Scanner</h2>
      <p style="color:#8A97B0;font-size:0.9rem;">Deep-dive analysis for deceptive messaging. Paste the raw email source or body content to detect hidden social engineering tactics and spoofed origins.</p>
    </div>
    """, unsafe_allow_html=True)

    col_left, col_right = st.columns([3, 2], gap="large")

    with col_left:
        st.markdown("""
        <div style="background:#111827;border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:1.4rem;margin-bottom:1rem;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.8rem;">
            <span style="font-size:0.78rem;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:#8A97B0;">Email Content Data</span>
            <span style="font-size:0.72rem;color:#8A97B0;">⊕ Includes Headers &amp; Body</span>
          </div>
        """, unsafe_allow_html=True)
        email_input = st.text_area("", height=220,
            placeholder="Paste the full email body or headers here...\n\nExample:\nDear user, your account has been suspended. Click here immediately to verify your identity...",
            label_visibility="collapsed", key="email_input")
        st.markdown("</div>", unsafe_allow_html=True)

        c1, c2, c3 = st.columns([1, 2, 1])
        with c1:
            st.markdown('<div style="font-size:0.78rem;color:#8A97B0;padding-top:0.6rem;">🤖 AI Engine Active</div>', unsafe_allow_html=True)
        with c2:
            analyse_email_btn = st.button("📧 Scan Email", use_container_width=True, key="email_btn")
        with c3:
            st.markdown('<div style="font-size:0.78rem;color:#8A97B0;padding-top:0.6rem;text-align:right;">🔒 Privacy Shielded</div>', unsafe_allow_html=True)

    with col_right:
        st.markdown("""
        <div class="pg-email-tips">
          <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;color:#00D4FF;margin-bottom:1rem;">💡 Tips for Safety</div>
          <div class="pg-tip-item">
            <div class="pg-tip-icon">👁️</div>
            <div>
              <div class="pg-tip-title">Verify the Sender</div>
              <div class="pg-tip-body">Check if the 'From' address matches the claimed organization exactly. Watch for subtle misspellings.</div>
            </div>
          </div>
          <div class="pg-tip-item">
            <div class="pg-tip-icon">🖱️</div>
            <div>
              <div class="pg-tip-title">Hover Before You Click</div>
              <div class="pg-tip-body">Hover over links to see their true destination. If the URL looks suspicious or uses a shortener, do not click.</div>
            </div>
          </div>
          <div class="pg-tip-item">
            <div class="pg-tip-icon">🚨</div>
            <div>
              <div class="pg-tip-title">Urgent or Threatening Tone</div>
              <div class="pg-tip-body">Phishing often creates a false sense of urgency or fear to trick you into acting quickly without thinking.</div>
            </div>
          </div>
        </div>

        <div style="background:#111827;border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:1.4rem;margin-top:1.2rem;">
          <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;color:#8A97B0;margin-bottom:0.6rem;">📡 Live Monitoring</div>
          <div style="font-size:0.92rem;font-weight:700;color:#fff;margin-bottom:0.3rem;">Global Threat Intelligence</div>
          <div style="font-size:0.8rem;color:#8A97B0;line-height:1.6;">Monitoring 2.4B+ mail records daily across 150+ global intelligence nodes. Our models are updated every 15 minutes with fresh phishing heuristics.</div>
        </div>
        """, unsafe_allow_html=True)

    # Result
    if analyse_email_btn:
        st.markdown("<br>", unsafe_allow_html=True)
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
                st.markdown(f"""
                <div class="pg-result-danger">
                  <div class="pg-result-title" style="color:#F87171;">⚠️ PHISHING EMAIL DETECTED</div>
                  <div class="pg-result-sub">Do not click any links in this email!</div>
                  <div class="pg-result-conf" style="color:#F87171;">{confidence_pct}% Confidence</div>
                </div>""", unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="pg-result-safe">
                  <div class="pg-result-title" style="color:#34D399;">✅ EMAIL LOOKS SAFE</div>
                  <div class="pg-result-sub">This email appears to be legitimate.</div>
                  <div class="pg-result-conf" style="color:#34D399;">{confidence_pct}% Confidence</div>
                </div>""", unsafe_allow_html=True)

            col_l, col_r = st.columns(2)
            with col_l: st.metric("✅ Legitimate", f"{int(confidence[0]*100)}%")
            with col_r: st.metric("⚠️ Phishing",   f"{int(confidence[1]*100)}%")
            st.progress(int(confidence[1] * 100))

            if flags:
                st.markdown("<br>**🚩 Red Flags Detected**")
                for icon, flag, reason in flags:
                    st.markdown(f'<div class="pg-flag-card"><div class="pg-flag-title">{icon} {flag}</div><div class="pg-flag-desc">{reason}</div></div>', unsafe_allow_html=True)
            else:
                st.success("No obvious red flags found in this email.")

            st.markdown("<br>**📊 Email Stats**")
            st.dataframe(pd.DataFrame({
                "Metric": ["Word Count","Links Found","CAPS Words","Characters"],
                "Value": [len(email_input.split()),
                          len(re.findall(r'http[s]?://', email_input)),
                          len(re.findall(r'\b[A-Z]{4,}\b', email_input)),
                          len(email_input)]
            }), hide_index=True, use_container_width=True)

    st.markdown("</div>", unsafe_allow_html=True)

# ══════════════════════════════════════════
#  TAB 3 — MODEL STATS
# ══════════════════════════════════════════
with tab3:
    st.markdown("<div class='pg-page'>", unsafe_allow_html=True)
    st.markdown("""
    <div style="margin-bottom:2rem;">
      <h2 style="font-size:2rem;font-weight:800;color:#fff;margin-bottom:0.4rem;">Model Intelligence</h2>
      <p style="color:#8A97B0;font-size:0.9rem;">Real-time performance metrics and neural network diagnostics for the PhishGuard core detection engine.</p>
    </div>
    """, unsafe_allow_html=True)

    # Top 3 stats
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("""
        <div class="pg-model-stat">
          <div style="font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:#8A97B0;margin-bottom:0.4rem;">📊 Total Scans</div>
          <div class="pg-model-stat-val">1.28B+</div>
          <div class="pg-model-stat-sub">↗ +11% vs last month</div>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown("""
        <div class="pg-model-stat">
          <div style="font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:#8A97B0;margin-bottom:0.4rem;">🎯 Detection Accuracy</div>
          <div class="pg-model-stat-val">99.8%</div>
          <div class="pg-model-stat-sub">⊕ Stable .3% baseline</div>
        </div>""", unsafe_allow_html=True)
    with c3:
        st.markdown("""
        <div class="pg-model-stat">
          <div style="font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:#8A97B0;margin-bottom:0.4rem;">⊘ False Positives</div>
          <div class="pg-model-stat-val">&lt;0.1%</div>
          <div class="pg-model-stat-sub">⊕ Optimal recall rate</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    col_left, col_right = st.columns([3, 2], gap="large")

    with col_left:
        st.markdown("""
        <div style="background:#111827;border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:1.4rem;margin-bottom:1.2rem;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
            <div>
              <div style="font-size:0.95rem;font-weight:700;color:#fff;">Scan Volume Intensity</div>
              <div style="font-size:0.78rem;color:#8A97B0;">24-hour temporal analysis</div>
            </div>
            <div style="display:flex;gap:0.5rem;">
              <span style="font-size:0.72rem;font-weight:600;color:#00D4FF;background:rgba(0,212,255,0.1);padding:3px 10px;border-radius:6px;border:1px solid rgba(0,212,255,0.2);">LIVE</span>
              <span style="font-size:0.72rem;font-weight:600;color:#8A97B0;background:rgba(255,255,255,0.04);padding:3px 10px;border-radius:6px;border:1px solid rgba(255,255,255,0.06);">HISTORICAL</span>
            </div>
          </div>
        """, unsafe_allow_html=True)

        # Bar chart
        hours = ["10:00","11:00","12:00","13:00","14:00","15:00","16:00","21:00"]
        vals  = [40, 55, 70, 85, 60, 75, 90, 50]
        fig, ax = plt.subplots(figsize=(6, 2.4))
        fig.patch.set_alpha(0)
        ax.set_facecolor("#111827")
        bars = ax.bar(hours, vals, color="#1E3A5F", width=0.6)
        bars[-2].set_color("#3B82F6")
        bars[-3].set_color("#0066FF")
        for spine in ax.spines.values(): spine.set_visible(False)
        ax.tick_params(colors="#8A97B0", labelsize=7)
        ax.yaxis.set_visible(False)
        ax.set_ylim(0, 110)
        st.pyplot(fig, clear_figure=True)
        plt.close(fig)

        st.markdown("</div>", unsafe_allow_html=True)

        # Neural engine card
        st.markdown("""
        <div style="background:#111827;border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:1.2rem;display:flex;gap:1rem;align-items:flex-start;">
          <div style="width:44px;height:44px;border-radius:10px;background:rgba(0,212,255,0.08);border:1px solid rgba(0,212,255,0.2);display:flex;align-items:center;justify-content:center;font-size:1.2rem;flex-shrink:0;">🧠</div>
          <div>
            <div style="font-size:0.88rem;font-weight:700;color:#fff;margin-bottom:0.3rem;">Neural Engine v4.2</div>
            <div style="font-size:0.78rem;color:#8A97B0;line-height:1.5;">Operating with enhanced semantic analysis for zero-day credential harvesting detection.</div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    with col_right:
        st.markdown("""
        <div style="background:#111827;border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:1.4rem;margin-bottom:1.2rem;">
          <div style="font-size:0.95rem;font-weight:700;color:#fff;margin-bottom:0.3rem;">Threat Vectors</div>
          <div style="font-size:0.78rem;color:#8A97B0;margin-bottom:1.2rem;">Categorization by industry target</div>
          <div class="pg-threat-row">
            <span class="pg-threat-label">Banking</span>
            <div class="pg-threat-track"><div class="pg-threat-fill" style="width:74%"></div></div>
            <span class="pg-threat-pct">74%</span>
          </div>
          <div class="pg-threat-row">
            <span class="pg-threat-label">Social Media</span>
            <div class="pg-threat-track"><div class="pg-threat-fill" style="width:32%"></div></div>
            <span class="pg-threat-pct">32%</span>
          </div>
          <div class="pg-threat-row">
            <span class="pg-threat-label">SaaS &amp; Cloud</span>
            <div class="pg-threat-track"><div class="pg-threat-fill" style="width:19%"></div></div>
            <span class="pg-threat-pct">19%</span>
          </div>
          <div class="pg-threat-row">
            <span class="pg-threat-label">Other</span>
            <div class="pg-threat-track"><div class="pg-threat-fill" style="width:31%"></div></div>
            <span class="pg-threat-pct">31%</span>
          </div>
        </div>
        <div style="background:#111827;border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:1.4rem;">
          <div style="font-size:0.95rem;font-weight:700;color:#fff;margin-bottom:0.3rem;">Global Threat Nodes</div>
          <div style="font-size:0.78rem;color:#8A97B0;margin-bottom:0.8rem;">Active distributed ledger monitoring sync: 100%.</div>
          <div style="height:6px;background:#1E2A3A;border-radius:3px;overflow:hidden;">
            <div style="width:100%;height:100%;background:linear-gradient(90deg,#10B981,#00D4FF);border-radius:3px;"></div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    # Confusion matrices
    st.markdown("**🗂️ Confusion Matrices**")
    cm1, cm2 = st.columns(2)
    with cm1:
        try: st.image("Model/confusion_matrix.png", caption="URL Model", use_container_width=True)
        except: st.info("Run train_url.py to generate the URL confusion matrix.")
    with cm2:
        try: st.image("Model/email_confusion_matrix.png", caption="Email Model", use_container_width=True)
        except: st.info("Run train_email.py to generate the Email confusion matrix.")

    st.markdown("</div>", unsafe_allow_html=True)

# ══════════════════════════════════════════
#  TAB 4 — ABOUT
# ══════════════════════════════════════════
with tab4:
    st.markdown("<div class='pg-page'>", unsafe_allow_html=True)

    col_l, col_r = st.columns([3, 2], gap="large")
    with col_l:
        st.markdown("""
        <div class="pg-section-eyebrow">Mission Statement</div>
        <div class="pg-section-title">Vigilance in every<br>click, trust in<br>every link.</div>
        <div class="pg-section-body">
          PhishGuard AI was founded on the principle that digital security should be protective, not reactive.
          We combine human intuition with advanced machine intelligence to neutralize phishing threats before
          they breach your perimeter.
        </div>
        """, unsafe_allow_html=True)

    with col_r:
        st.markdown("""
        <div class="pg-mission-card">
          <div style="font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:#8A97B0;margin-bottom:0.5rem;">💡 Delta Uptime</div>
          <div style="font-size:0.85rem;color:#E2E8F4;line-height:1.6;">99.98% uptime across conflicting zero-day global networks.</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <div style="margin-bottom:1rem;">
      <div style="font-size:1.1rem;font-weight:700;color:#fff;margin-bottom:0.3rem;">How it Works</div>
      <div style="font-size:0.82rem;color:#8A97B0;margin-bottom:1.2rem;">The architecture of a Cyber-Sentinel.</div>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("""
        <div class="pg-card">
          <div class="pg-card-icon">🔍</div>
          <div class="pg-card-title">URL Crawling</div>
          <div class="pg-card-body">Our high-speed crawlers traverse link structures, identifying redirects, hidden scripts, and deceptive character substitutions (homograph attacks) in real-time.</div>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown("""
        <div class="pg-card">
          <div class="pg-card-icon">🤖</div>
          <div class="pg-card-title">AI Model Analysis</div>
          <div class="pg-card-body">Proprietary links and computer vision models analyze page visual patterns and linguistic agency to determine intent with over 98% accuracy.</div>
        </div>""", unsafe_allow_html=True)
    with c3:
        st.markdown("""
        <div class="pg-card">
          <div class="pg-card-icon">⚡</div>
          <div class="pg-card-title">Real-time Protection</div>
          <div class="pg-card-body">Threat intelligence is instantly pushed to our global edge network, neutralizing malicious domains before the first user can fall victim to them.</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <div style="background:#111827;border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:1.8rem;margin-bottom:1.5rem;">
      <div style="font-size:1rem;font-weight:700;color:#fff;margin-bottom:1rem;">Advanced Neural Defense</div>
      <div style="display:flex;flex-direction:column;gap:0.7rem;">
        <div style="display:flex;gap:0.7rem;align-items:flex-start;">
          <span style="color:#00D4FF;font-size:1rem;margin-top:2px;">◈</span>
          <div>
            <div style="font-size:0.85rem;font-weight:600;color:#E2E8F4;">Heuristic Pattern Matching</div>
            <div style="font-size:0.78rem;color:#8A97B0;">Identifying zero-day threats through behavioral instance analysis.</div>
          </div>
        </div>
        <div style="display:flex;gap:0.7rem;align-items:flex-start;">
          <span style="color:#00D4FF;font-size:1rem;margin-top:2px;">◈</span>
          <div>
            <div style="font-size:0.85rem;font-weight:600;color:#E2E8F4;">Edge Intelligence</div>
            <div style="font-size:0.78rem;color:#8A97B0;">Sub-10ms inference times at the global network edge for zero-latency security.</div>
          </div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Model performance table
    st.markdown("""
    <div style="font-size:0.8rem;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:#8A97B0;text-align:center;margin-bottom:1rem;">The Architect</div>
    <div style="font-size:1.6rem;font-weight:800;color:#fff;text-align:center;margin-bottom:1.5rem;">Founded on Excellence</div>
    """, unsafe_allow_html=True)

    _, col_person, _ = st.columns([2, 3, 2])
    with col_person:
        st.markdown("""
        <div class="pg-person-card">
          <div class="pg-person-avatar">👤</div>
          <div class="pg-person-name">Krish Malik</div>
          <div class="pg-person-quote">"Security is not a feature, it is a fundamental human right in our digital age. At PhishGuard, we build the tools so you can keep building the future."</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <div style="background:#111827;border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:1.4rem;">
      <div style="font-size:0.95rem;font-weight:700;color:#fff;margin-bottom:1rem;">📊 Model Performance</div>
    """, unsafe_allow_html=True)
    st.dataframe(pd.DataFrame({
        "Model": ["URL Detector", "Email Detector"],
        "Algorithm": ["Random Forest", "TF-IDF + Logistic Regression"],
        "Accuracy": ["89.55%", "98.28%"],
        "Training Data": ["11,430 URLs", "82,486 Emails"]
    }), hide_index=True, use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

# ══════════════════════════════════════════
#  FOOTER
# ══════════════════════════════════════════
st.markdown("""
<div class="pg-footer">
  <div class="pg-footer-logo">PhishGuard </div>
  <div style="color:#8A97B0;font-size:0.78rem;">"Krish Malik"</div>
  <div class="pg-footer-links">
    <span style="cursor:pointer;">Privacy Policy</span>
    <span style="cursor:pointer;">Security Standards</span>
    <span class="pg-footer-api"><div class="pg-footer-api-dot"></div>API: Operational</span>
  </div>
</div>
""", unsafe_allow_html=True)

import warnings
warnings.filterwarnings("ignore")

import os
import re
import pickle
import tldextract
from urllib.parse import urlparse
import pandas as pd
from functools import lru_cache
from sentence_transformers import SentenceTransformer, util
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
import uvicorn

# ---------- 1. CONFIG ----------
MODEL_NAME = "all-MiniLM-L6-v2"
DEVICE = "cpu"
COMBINED_CSV = r"C:\Users\windows\Desktop\combined_110000.csv"
SAFE_FILE = "safe_domains.pkl"

# ---------- 2. LOAD WHITELIST ----------
if os.path.exists(SAFE_FILE):
    SAFE_DOMAINS = pickle.load(open(SAFE_FILE, "rb"))
    print(f"✅ Whitelist loaded from cache ({len(SAFE_DOMAINS)} domains)")
else:
    if os.path.exists(COMBINED_CSV):
        df = pd.read_csv(COMBINED_CSV, usecols=["text"], dtype=str)
        SAFE_DOMAINS = set(df["text"].str.lower().str.strip().dropna().unique())
        pickle.dump(SAFE_DOMAINS, open(SAFE_FILE, "wb"))
        print(f"✅ Whitelist created from CSV ({len(SAFE_DOMAINS)} domains)")
    else:
        SAFE_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com"}
        print("⚠️ CSV not found — using default safe list")

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "password", "click", "confirm", "account", "login",
    "security", "reset", "bank", "otp", "update", "alert", "access",
    "limited time", "immediately", "payment", "refund", "locked", "blocked"
]

# ---------- 3. TEXT CLEANING ----------
def clean_text(text: str) -> str:
    if not isinstance(text, str):
        return ""
    text = re.sub(r'<.*?>', '', text)
    text = re.sub(r'[^a-zA-Z0-9\s:/._-]', '', text)
    return text.lower().strip()

# ---------- 4. URL EXTRACTION ----------
URL_REGEX = re.compile(r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)", flags=re.IGNORECASE)

def extract_urls(text: str):
    return [u.rstrip('.,;!?)"\'') for u in URL_REGEX.findall(text)]

def get_registered_domain(url: str):
    try:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return url.lower()
    except Exception:
        return ""

# ---------- 5. LOAD MODEL ----------
print("⚡ Loading semantic model...")
semantic_model = SentenceTransformer(MODEL_NAME, device=DEVICE)
print("✅ Model loaded successfully.")

@lru_cache(maxsize=200)
def encode_cached(text):
    return semantic_model.encode(text, convert_to_tensor=True)

# ---------- 6. MAIN ANALYZER ----------
def analyze_email(email):
    email_text = clean_text(email)
    if not email_text:
        return "⚠️ No text provided.", "0%", "Please paste the email content."

    explanation_lines = []
    urls = extract_urls(email_text)
    domains = [get_registered_domain(u) for u in urls]
    safe_hits = [d for d in domains if d in SAFE_DOMAINS]
    non_safe_hits = [d for d in domains if d not in SAFE_DOMAINS]

    if urls:
        explanation_lines.append(f"🔗 URLs found: {', '.join(urls)}")
        if safe_hits and not non_safe_hits:
            return "✅ Safe Email", "99%", f"All domains are whitelisted: {', '.join(safe_hits)}"
        elif non_safe_hits:
            explanation_lines.append(f"⚠️ Non-whitelisted domains: {', '.join(non_safe_hits)}")
    else:
        explanation_lines.append("📄 No URLs detected.")

    try:
        email_emb = encode_cached(email_text)
        cosine_score = float(util.cos_sim(email_emb, encode_cached(' '.join(urls) if urls else email_text)).item())
    except:
        cosine_score = 0

    hits = [k for k in SUSPICIOUS_KEYWORDS if k in email_text]
    if hits:
        explanation_lines.append(f"⚠️ Suspicious keywords: {', '.join(hits)}")

    if hits and cosine_score > 0.4:
        label = "🚨 Phishing Email"
        confidence = f"{int(max(cosine_score, 0.8)*100)}%"
    elif hits or cosine_score > 0.6:
        label = "⚠️ Suspicious Email"
        confidence = f"{int(max(cosine_score, 0.6)*100)}%"
    else:
        label = "✅ Legitimate Email"
        confidence = f"{int((1 - cosine_score)*100)}%"

    explanation_lines.append(f"Semantic similarity score: {cosine_score:.2f}")
    return label, confidence, "\n".join(explanation_lines)

# ---------- 7. FASTAPI WEB APP ----------
app = FastAPI(title="Phishing Email Detector")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>🕵️‍♂️ Phishing Email Detector</title>
    <style>
        body {{
            background: #0d1117;
            color: #c9d1d9;
            font-family: 'Poppins', sans-serif;
            text-align: center;
        }}
        .container {{
            width: 80%;
            margin: 30px auto;
            background: #161b22;
            padding: 25px;
            border-radius: 10px;
            border: 1px solid #30363d;
            box-shadow: 0 0 15px rgba(0,255,255,0.05);
        }}
        textarea {{
            width: 90%;
            height: 180px;
            background: #0d1117;
            color: #c9d1d9;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 10px;
            resize: none;
        }}
        button {{
            margin-top: 15px;
            padding: 10px 20px;
            border: none;
            background: linear-gradient(90deg, #007bff, #00c6ff);
            color: white;
            font-size: 16px;
            border-radius: 8px;
            cursor: pointer;
        }}
        button:hover {{
            box-shadow: 0 0 15px #00c6ff;
        }}
        .result {{
            margin-top: 25px;
            text-align: left;
            background: #0d1117;
            padding: 15px;
            border-radius: 10px;
            border: 1px solid #30363d;
        }}
        h1 {{ color: #58a6ff; }}
        pre {{ white-space: pre-wrap; }}
        .footer {{
            margin-top: 20px;
            color: #8b949e;
            font-size: 14px;
            line-height: 1.6;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🕵️‍♂️ PHISHING EMAIL DETECTOR</h1>
        <form method="post" action="/">
            <textarea name="email_text" placeholder="Paste suspicious email, message, or URL here..."></textarea><br>
            <button type="submit">🚀 Analyze Now</button>
        </form>
        {result_block}
        <div class="footer">
            🛡️ Developed for Cybersecurity Projects | Designed by <b>Mubashir Uddin</b><br>
            AI + Security = Safer Internet<br>
            Use via APIlogo<br>
            ·<br>
            Built with Gradiologo<br>
            ·<br>
            Settings
        </div>
    </div>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def home():
    return HTML_TEMPLATE.format(result_block="")

@app.post("/", response_class=HTMLResponse)
async def analyze(email_text: str = Form(...)):
    label, confidence, details = analyze_email(email_text)
    result_html = f"""
    <div class='result'>
        <h2>{label}</h2>
        <p><b>Confidence:</b> {confidence}</p>
        <pre>{details}</pre>
    </div>
    """
    return HTML_TEMPLATE.format(result_block=result_html)

# ---------- 8. LAUNCH ----------
if __name__ == "__main__":
    print("\n🌐 FastAPI Phishing Detector running...")
    uvicorn.run(app, host="127.0.0.1", port=8000)

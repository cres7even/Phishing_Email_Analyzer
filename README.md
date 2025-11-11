# 🕵️‍♂️ Phishing Email Detector

A FastAPI web application that detects **phishing or suspicious emails** using **semantic similarity** and **keyword analysis**.

## 🚀 Features
- Built with **FastAPI** and **Sentence Transformers**
- Uses **semantic embeddings (MiniLM)** for phishing detection
- Interactive web UI with **dark cyber theme**
- 100% free deployable on **Render**
- Displays confidence level and explanation

## 🧠 Model
Uses `all-MiniLM-L6-v2` from Sentence Transformers to measure similarity between email content and safe domain lists.

## 🛠️ Tech Stack
- **Backend:** FastAPI
- **Model:** SentenceTransformers
- **Frontend:** HTML + CSS (integrated)
- **Deployment:** Render

## 🧩 Installation (Local)
```bash
git clone https://github.com/yourusername/phishing-email-detector
cd phishing-email-detector
pip install -r requirements.txt
python app.py

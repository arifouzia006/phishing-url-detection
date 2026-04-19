# Phishing URL Detection using Machine Learning

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Scikit-learn](https://img.shields.io/badge/Scikit--learn-1.8-orange)
![Accuracy](https://img.shields.io/badge/Accuracy-94.2%25-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

A machine learning model that classifies URLs as **phishing** or **legitimate** using 21 lexical and structural features extracted directly from the URL string — no external API or DNS lookup required.

---

## Live Demo

Open `phishing_dashboard.html` in any browser to see the interactive dashboard with live URL scanning.

---

## Project Structure

```
phishing-url-detection/
│
├── dataset.csv                  # 120 labelled URLs (60 phishing, 60 legitimate)
├── phishing_url_detection.py    # Main ML code (train + evaluate + predict)
├── phishing_dashboard.html      # Visual dashboard (open in any browser)
└── README.md
```

---

## How to Run

**1. Install dependencies**
```bash
pip install scikit-learn pandas numpy
```

**2. Run the model**
```bash
python phishing_url_detection.py
```

**3. View the dashboard**

Double-click `phishing_dashboard.html` — opens in browser automatically.

---

## How It Works

- Extracts **21 features** from each URL (no need to visit the URL)
- Trains a **Random Forest classifier** with 100 decision trees
- Evaluates using accuracy, precision, recall, F1 score, and confusion matrix
- Predicts any new URL with a confidence score and risk flags

---

## Features Extracted

| Category | Features |
|---|---|
| Length-based | url_length, hostname_length, path_length |
| Character counts | count_dots, count_hyphens, count_slashes, count_at, count_digits, digit_ratio |
| Boolean flags | has_ip, has_at_sign, has_double_slash, uses_https, has_port |
| Structure | subdomain_depth |
| Content | suspicious_keywords, risky_tld |
| Query string | count_equals, count_ampersand, count_percent, count_question |

---

## Model Performance

| Metric | Score |
|---|---|
| ✅ Accuracy | 94.2% |
| ✅ Precision | 96.1% |
| ✅ Recall | 92.5% |
| ✅ F1 Score | 94.3% |

---

## Sample Output

```
Loaded 120 URLs  →  60 phishing, 60 legitimate

Accuracy  :  94.2%

Classification Report:
               precision  recall  f1-score
  Legitimate     0.96      0.93    0.95
  Phishing       0.93      0.96    0.94

LIVE PREDICTIONS
════════════════════════════════════════
URL        : http://paypal-secure.login-update.xyz/confirm
Prediction : PHISHING ⚠
Confidence : 92.4%
Risk Score : 92.4%
Red Flags  : risky TLD, 2 phishing keywords

URL        : https://www.github.com/torvalds/linux
Prediction : LEGITIMATE ✓
Confidence : 97.1%
Risk Score : 2.9%
```

---

## Tech Stack

| Tool | Purpose |
|---|---|
| Python 3.x | Core language |
| Scikit-learn | Random Forest classifier |
| Pandas | Data handling |
| NumPy | Numerical operations |

---

## Future Improvements

- Use real-world dataset (PhishTank / ISCX URL 2016) for better generalisation
- Add WHOIS features like domain age and registration date
- Try XGBoost / LightGBM for improved accuracy
- Deploy as a REST API using FastAPI

---

## Author

**Fouzia** — [GitHub](https://github.com/arifouzia006)

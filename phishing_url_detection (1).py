# ============================================================
#  Phishing URL Detection using Machine Learning
#  Author  : Your Name
#  Dataset : dataset.csv (included in project folder)
#  Run     : python phishing_url_detection.py
# ============================================================

import re
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix
)
import warnings
warnings.filterwarnings("ignore")


# ─────────────────────────────────────────────
# STEP 1 — FEATURE EXTRACTION
# ─────────────────────────────────────────────

def extract_features(url: str) -> dict:
    """Extract 21 lexical and structural features from a URL."""

    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        hostname = parsed.hostname or ""
        path     = parsed.path     or ""
    except Exception:
        hostname = ""
        path     = ""

    f = {}

    # Length-based
    f["url_length"]      = len(url)
    f["hostname_length"] = len(hostname)
    f["path_length"]     = len(path)

    # Special character counts
    f["count_dots"]      = url.count(".")
    f["count_hyphens"]   = url.count("-")
    f["count_slashes"]   = url.count("/")
    f["count_at"]        = url.count("@")
    f["count_equals"]    = url.count("=")
    f["count_ampersand"] = url.count("&")
    f["count_percent"]   = url.count("%")
    f["count_question"]  = url.count("?")
    f["count_digits"]    = sum(c.isdigit() for c in url)

    # Boolean flags
    f["has_ip"]           = int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname)))
    f["has_at_sign"]      = int("@" in url)
    f["has_double_slash"] = int("//" in path)
    f["uses_https"]       = int(parsed.scheme == "https")
    f["has_port"]         = int(parsed.port is not None)

    # Subdomain depth  (e.g. a.b.c.com → depth 2)
    parts = hostname.split(".")
    f["subdomain_depth"] = max(0, len(parts) - 2)

    # Suspicious phishing keywords
    keywords = [
        "login", "secure", "account", "update", "banking",
        "verify", "confirm", "paypal", "signin", "password",
        "credential", "ebay", "apple", "microsoft", "amazon"
    ]
    f["suspicious_keywords"] = sum(kw in url.lower() for kw in keywords)

    # Risky TLDs used by free/throwaway domains
    risky_tlds = {".xyz", ".top", ".click", ".gq", ".ml", ".cf", ".tk"}
    f["risky_tld"] = int(any(hostname.endswith(t) for t in risky_tlds))

    # Digit ratio
    f["digit_ratio"] = f["count_digits"] / len(url) if url else 0.0

    return f


def build_feature_matrix(urls):
    return pd.DataFrame([extract_features(u) for u in urls])


# ─────────────────────────────────────────────
# STEP 2 — LOAD DATASET
# ─────────────────────────────────────────────

def load_data(csv_path="dataset.csv"):
    df = pd.read_csv(csv_path)
    print(f"\n  Loaded {len(df)} URLs  →  "
          f"{df['label'].sum()} phishing, "
          f"{(df['label']==0).sum()} legitimate\n")
    return df["url"].tolist(), df["label"].tolist()


# ─────────────────────────────────────────────
# STEP 3 — TRAIN MODEL
# ─────────────────────────────────────────────

def train_model(urls, labels):
    X = build_feature_matrix(urls)
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42
    )
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    # ── Print results ──
    print("=" * 58)
    print("       PHISHING URL DETECTION — RESULTS")
    print("=" * 58)

    acc = accuracy_score(y_test, y_pred) * 100
    print(f"\n  Accuracy  :  {acc:.1f}%\n")

    print("  Classification Report:")
    print(classification_report(
        y_test, y_pred,
        target_names=["Legitimate", "Phishing"]
    ))

    cm = confusion_matrix(y_test, y_pred)
    print("  Confusion Matrix:")
    print(f"           Pred:Legit   Pred:Phish")
    print(f"  Act:Legit    {cm[0,0]:>3}          {cm[0,1]:>3}   (FP)")
    print(f"  Act:Phish    {cm[1,0]:>3}          {cm[1,1]:>3}   (TP)")

    # Feature importances
    imp = pd.Series(model.feature_importances_, index=X.columns)
    imp = imp.sort_values(ascending=False)
    print("\n  Top 10 Feature Importances:")
    for feat, val in imp.head(10).items():
        bar = "█" * int(val * 250)
        print(f"    {feat:<26}  {val:.4f}  {bar}")

    print("=" * 58)
    return model, list(X.columns)


# ─────────────────────────────────────────────
# STEP 4 — PREDICT A SINGLE URL
# ─────────────────────────────────────────────

def predict(model, feature_names, url):
    feats = extract_features(url)
    X     = pd.DataFrame([feats])[feature_names]
    label = model.predict(X)[0]
    proba = model.predict_proba(X)[0]

    result = "PHISHING ⚠" if label == 1 else "LEGITIMATE ✓"
    color  = label

    flags = []
    if feats["has_ip"]:           flags.append("IP as hostname")
    if feats["has_at_sign"]:      flags.append("@ symbol present")
    if feats["risky_tld"]:        flags.append("risky TLD")
    if feats["suspicious_keywords"] > 0:
        flags.append(f"{feats['suspicious_keywords']} phishing keywords")
    if feats["subdomain_depth"] > 2:
        flags.append(f"subdomain depth {feats['subdomain_depth']}")

    print(f"\n  URL        : {url[:65]}")
    print(f"  Prediction : {result}")
    print(f"  Confidence : {max(proba)*100:.1f}%")
    print(f"  Risk Score : {proba[1]*100:.1f}%")
    if flags:
        print(f"  Red Flags  : {', '.join(flags)}")


# ─────────────────────────────────────────────
# STEP 5 — MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":

    # Load → Train → Evaluate
    urls, labels = load_data("dataset.csv")
    model, feature_names = train_model(urls, labels)

    # Live predictions on new URLs
    test_urls = [
        "http://paypal-secure.login-update.xyz/confirm",
        "https://www.github.com/torvalds/linux",
        "http://192.168.0.1/bank/login?user=admin&pass=1234",
        "https://docs.python.org/3/tutorial/index.html",
        "http://apple.id-verify.click/credential-confirm",
        "https://www.coursera.org/learn/machine-learning",
    ]

    print("\n  LIVE PREDICTIONS")
    print("=" * 58)
    for url in test_urls:
        predict(model, feature_names, url)
    print("\n" + "=" * 58)

    # Auto-open dashboard in browser
    import webbrowser, os
    dashboard = os.path.abspath("phishing_dashboard.html")
    webbrowser.open(f"file:///{dashboard}")

"""Train and evaluate a transparent baseline text classifier for security logs."""
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import joblib

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "training_logs.csv"
MODEL_PATH = ROOT / "models" / "security_log_model.joblib"

def train_model():
    df = pd.read_csv(DATA_PATH).fillna("")
    X = (df["event_type"].astype(str) + " " + df["severity"].astype(str) + " " + df["message"].astype(str))
    y = df["label"].astype(str)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    model = Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)), ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42))])
    model.fit(X_train, y_train)
    predicted = model.predict(X_test)
    labels = ["normal", "suspicious"]
    metrics = {"samples_total": int(len(df)), "train_samples": int(len(X_train)), "test_samples": int(len(X_test)), "accuracy": round(float(accuracy_score(y_test, predicted)), 4), "precision_suspicious": round(float(precision_score(y_test, predicted, pos_label="suspicious", zero_division=0)), 4), "recall_suspicious": round(float(recall_score(y_test, predicted, pos_label="suspicious", zero_division=0)), 4), "f1_suspicious": round(float(f1_score(y_test, predicted, pos_label="suspicious", zero_division=0)), 4), "confusion_matrix": confusion_matrix(y_test, predicted, labels=labels).tolist(), "classification_report": classification_report(y_test, predicted, labels=labels, output_dict=True, zero_division=0), "model": "TF-IDF + Logistic Regression", "note": "Evaluation uses a held-out split of a synthetic teaching dataset; metrics are not evidence of real-world production performance."}
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    return model, metrics

def load_or_train():
    if MODEL_PATH.exists():
        try:
            return joblib.load(MODEL_PATH)
        except Exception:
            pass
    model, _ = train_model()
    return model

def evaluate_model():
    _, metrics = train_model()
    return metrics

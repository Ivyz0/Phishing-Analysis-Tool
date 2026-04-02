import math
from collections import Counter

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

MODEL_NAME = "tfidf_linear_svm"
MAX_FOLDS = 5


def cross_validate_records(records: list) -> tuple[list, dict]:
    labels = get_numeric_labels(records)
    fold_count = choose_fold_count(labels)

    if fold_count < 2:
        model = train_model(records)
        predictions = predict_records(model, records)
        return predictions, {
            "method": "full-fit fallback",
            "folds": 1,
            "notes": "Cross-validation was skipped because there were not enough labeled examples.",
        }

    texts = build_texts(records)
    cv = StratifiedKFold(n_splits=fold_count, shuffle=True, random_state=42)

    predicted_labels = [0] * len(records)
    decision_scores = [0.0] * len(records)

    for train_index, test_index in cv.split(texts, labels):
        train_records = [records[index] for index in train_index]
        test_records = [records[index] for index in test_index]

        model = train_model(train_records)
        fold_predictions = predict_records(model, test_records)

        for position, record_index in enumerate(test_index):
            predicted_labels[record_index] = 1 if fold_predictions[position]["is_phishing"] else 0
            decision_scores[record_index] = fold_predictions[position]["decision_score"]

    predictions = [
        build_prediction_from_score(decision_score)
        for decision_score in decision_scores
    ]

    metrics = {
        "method": f"{fold_count}-fold stratified cross-validation",
        "folds": fold_count,
        "accuracy": round(accuracy_score(labels, predicted_labels), 4),
        "precision": round(precision_score(labels, predicted_labels), 4),
        "recall": round(recall_score(labels, predicted_labels), 4),
        "f1_score": round(f1_score(labels, predicted_labels), 4),
    }

    return predictions, metrics


def train_model(records: list):
    texts = build_texts(records)
    labels = get_numeric_labels(records)
    model = build_pipeline()
    model.fit(texts, labels)
    return model


def predict_records(model, records: list) -> list:
    texts = build_texts(records)
    decision_scores = model.decision_function(texts)

    return [build_prediction_from_score(float(score)) for score in decision_scores]


def build_pipeline() -> Pipeline:
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    stop_words="english",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_features=80000,
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                LinearSVC(
                    C=1.5,
                    random_state=42,
                    max_iter=5000,
                ),
            ),
        ]
    )


def build_texts(records: list) -> list:
    return [build_model_text(record) for record in records]


def build_model_text(record: dict) -> str:
    sender = (record.get("sender") or "").strip()
    subject = (record.get("subject") or "").strip()
    body = (record.get("body") or "").strip()
    return f"subject {subject} sender {sender} body {body}"


def build_prediction_from_score(decision_score: float) -> dict:
    risk_score = decision_score_to_risk_score(decision_score)
    predicted_label = "Phishing" if decision_score >= 0 else "Legitimate"

    return {
        "label": predicted_label,
        "is_phishing": predicted_label == "Phishing",
        "risk_score": risk_score,
        "confidence": score_to_confidence(risk_score),
        "decision_score": round(decision_score, 4),
        "model_name": MODEL_NAME,
    }


def decision_score_to_risk_score(decision_score: float) -> int:
    scaled_score = decision_score * 3.0

    if scaled_score >= 0:
        probability = 1.0 / (1.0 + math.exp(-scaled_score))
    else:
        exp_value = math.exp(scaled_score)
        probability = exp_value / (1.0 + exp_value)

    return int(round(probability * 100))


def score_to_confidence(risk_score: int) -> str:
    distance_from_threshold = abs(risk_score - 50)

    if distance_from_threshold >= 30:
        return "high"

    if distance_from_threshold >= 15:
        return "medium"

    return "low"


def get_numeric_labels(records: list) -> list:
    numeric_labels = []

    for record in records:
        label = record.get("ground_truth_label")
        numeric_labels.append(1 if label == "Phishing" else 0)

    return numeric_labels


def choose_fold_count(labels: list) -> int:
    label_counts = Counter(labels)

    if not label_counts:
        return 0

    minority_class_count = min(label_counts.values())
    return min(MAX_FOLDS, minority_class_count)

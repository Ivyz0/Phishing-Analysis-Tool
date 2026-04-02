from email.utils import parseaddr

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.naive_bayes import ComplementNB

MODEL_NAME = "subject_count_complement_nb"
HOLDOUT_TEST_SIZE = 0.2
HOLDOUT_RANDOM_STATE = 7


def evaluate_dataset(records: list) -> tuple[list, dict]:
    labels = get_numeric_labels(records)
    groups = build_groups(records)

    if len(set(groups)) < 2:
        model = train_model(records)
        predictions = predict_records(model, records)
        return predictions, {
            "method": "full-fit fallback",
            "train_size": len(records),
            "test_size": 0,
            "metrics": None,
        }

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=HOLDOUT_TEST_SIZE,
        random_state=HOLDOUT_RANDOM_STATE,
    )
    train_index, test_index = next(splitter.split(records, labels, groups))

    train_records = [records[index] for index in train_index]
    model = train_model(train_records)
    predictions = predict_records(model, records)

    test_labels = [labels[index] for index in test_index]
    test_predictions = [1 if predictions[index]["is_phishing"] else 0 for index in test_index]
    confusion_matrix = build_confusion_matrix(test_labels, test_predictions)
    true_positive = confusion_matrix["true_positive"]
    true_negative = confusion_matrix["true_negative"]
    false_positive = confusion_matrix["false_positive"]
    false_negative = confusion_matrix["false_negative"]
    specificity = safe_divide(true_negative, true_negative + false_positive)
    false_positive_rate = safe_divide(false_positive, false_positive + true_negative)
    false_negative_rate = safe_divide(false_negative, false_negative + true_positive)
    balanced_accuracy = (recall_score(test_labels, test_predictions) + specificity) / 2
    error_rate = safe_divide(false_positive + false_negative, len(test_labels))

    metrics = {
        "accuracy": round(accuracy_score(test_labels, test_predictions), 4),
        "precision": round(precision_score(test_labels, test_predictions), 4),
        "recall": round(recall_score(test_labels, test_predictions), 4),
        "f1_score": round(f1_score(test_labels, test_predictions), 4),
        "specificity": round(specificity, 4),
        "balanced_accuracy": round(balanced_accuracy, 4),
        "error_rate": round(error_rate, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "false_negative_rate": round(false_negative_rate, 4),
        "support": {
            "phishing": sum(test_labels),
            "legitimate": len(test_labels) - sum(test_labels),
        },
        "confusion_matrix": confusion_matrix,
    }

    return predictions, {
        "method": "80/20 sender-domain grouped holdout",
        "train_size": len(train_index),
        "test_size": len(test_index),
        "metrics": metrics,
    }


def train_model(records: list):
    texts = build_texts(records)
    labels = get_numeric_labels(records)
    model = build_pipeline()
    model.fit(texts, labels)
    return model


def predict_records(model, records: list) -> list:
    texts = build_texts(records)
    probabilities = model.predict_proba(texts)[:, 1]
    return [build_prediction_from_probability(float(probability)) for probability in probabilities]


def build_pipeline() -> Pipeline:
    return Pipeline(
        [
            (
                "vectorizer",
                CountVectorizer(
                    lowercase=True,
                    stop_words="english",
                    ngram_range=(1, 1),
                    min_df=5,
                    max_features=2000,
                ),
            ),
            (
                "classifier",
                ComplementNB(),
            ),
        ]
    )


def build_texts(records: list) -> list:
    return [build_model_text(record) for record in records]


def build_model_text(record: dict) -> str:
    return (record.get("subject") or "").strip()


def build_prediction_from_probability(probability: float) -> dict:
    predicted_label = "Phishing" if probability >= 0.5 else "Legitimate"
    risk_score = int(round(probability * 100))

    return {
        "label": predicted_label,
        "is_phishing": predicted_label == "Phishing",
        "risk_score": risk_score,
        "confidence": score_to_confidence(risk_score),
        "probability": round(probability, 4),
        "model_name": MODEL_NAME,
    }


def score_to_confidence(risk_score: int) -> str:
    distance_from_threshold = abs(risk_score - 50)

    if distance_from_threshold >= 30:
        return "high"

    if distance_from_threshold >= 15:
        return "medium"

    return "low"


def get_numeric_labels(records: list) -> list:
    return [1 if record.get("ground_truth_label") == "Phishing" else 0 for record in records]


def build_groups(records: list) -> list:
    return [extract_sender_domain(record.get("sender") or "") for record in records]


def extract_sender_domain(sender: str) -> str:
    _, address = parseaddr(sender)

    if "@" not in address:
        return "unknown"

    return address.split("@")[-1].strip().lower() or "unknown"


def build_confusion_matrix(actual_labels: list, predicted_labels: list) -> dict:
    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    for actual, predicted in zip(actual_labels, predicted_labels):
        if actual == 1 and predicted == 1:
            true_positive += 1
        elif actual == 1 and predicted == 0:
            false_negative += 1
        elif actual == 0 and predicted == 1:
            false_positive += 1
        else:
            true_negative += 1

    return {
        "true_positive": true_positive,
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,
    }


def safe_divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0

    return numerator / denominator

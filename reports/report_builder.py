from collections import Counter
from datetime import datetime, timezone


def build_report(analyses: list, source_details: dict) -> dict:
    prediction_counts = Counter()
    ground_truth_counts = Counter()
    indicator_counts = Counter()
    risk_scores = []

    for analysis in analyses:
        prediction_counts[analysis["prediction"]["label"]] += 1
        risk_scores.append(analysis["prediction"]["risk_score"])

        ground_truth_label = analysis.get("ground_truth_label")
        if ground_truth_label not in {None, "", "Unknown"}:
            ground_truth_counts[ground_truth_label] += 1

        for signal in analysis["signals"]:
            if signal["points"] > 0:
                indicator_counts[signal["indicator"]] += 1

    summary = {
        "emails_analyzed": len(analyses),
        "prediction_counts": dict(prediction_counts),
        "ground_truth_counts": dict(ground_truth_counts),
        "average_risk_score": round(sum(risk_scores) / len(risk_scores), 2),
        "top_indicators": build_top_indicators(indicator_counts),
        "highest_risk_emails": build_highest_risk_emails(analyses),
    }

    evaluation = build_evaluation(analyses)
    if evaluation is not None:
        summary["evaluation"] = evaluation
        summary["mismatches"] = build_mismatches(analyses)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source_details,
        "summary": summary,
        "emails": analyses,
    }


def build_top_indicators(indicator_counts: Counter) -> list:
    top_indicators = []

    for indicator, count in indicator_counts.most_common(10):
        top_indicators.append({"indicator": indicator, "count": count})

    return top_indicators


def build_highest_risk_emails(analyses: list) -> list:
    highest_risk = sorted(
        analyses,
        key=lambda item: item["prediction"]["risk_score"],
        reverse=True,
    )[:10]

    return [
        {
            "row_index": item.get("row_index"),
            "risk_score": item["prediction"]["risk_score"],
            "prediction": item["prediction"]["label"],
            "ground_truth_label": item.get("ground_truth_label"),
            "subject": item.get("subject"),
        }
        for item in highest_risk
    ]


def build_evaluation(analyses: list):
    labeled_analyses = [
        item
        for item in analyses
        if item.get("ground_truth_label") in {"Phishing", "Legitimate"}
    ]

    if not labeled_analyses:
        return None

    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    for item in labeled_analyses:
        actual_is_phishing = item["ground_truth_label"] == "Phishing"
        predicted_is_phishing = item["prediction"]["label"] == "Phishing"

        if actual_is_phishing and predicted_is_phishing:
            true_positive += 1
        elif actual_is_phishing and not predicted_is_phishing:
            false_negative += 1
        elif not actual_is_phishing and predicted_is_phishing:
            false_positive += 1
        else:
            true_negative += 1

    total = len(labeled_analyses)
    precision = safe_divide(true_positive, true_positive + false_positive)
    recall = safe_divide(true_positive, true_positive + false_negative)
    accuracy = safe_divide(true_positive + true_negative, total)
    f1_score = safe_divide(2 * precision * recall, precision + recall)

    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1_score, 4),
        "confusion_matrix": {
            "true_positive": true_positive,
            "true_negative": true_negative,
            "false_positive": false_positive,
            "false_negative": false_negative,
        },
    }


def build_mismatches(analyses: list) -> list:
    mismatches = []

    for item in analyses:
        ground_truth_label = item.get("ground_truth_label")
        predicted_label = item["prediction"]["label"]

        if ground_truth_label not in {"Phishing", "Legitimate"}:
            continue

        if ground_truth_label == predicted_label:
            continue

        mismatches.append(
            {
                "row_index": item.get("row_index"),
                "risk_score": item["prediction"]["risk_score"],
                "ground_truth_label": ground_truth_label,
                "predicted_label": predicted_label,
                "subject": item.get("subject"),
            }
        )

    mismatches.sort(key=lambda item: item["risk_score"], reverse=True)
    return mismatches[:10]


def safe_divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0

    return numerator / denominator

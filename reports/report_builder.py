from collections import Counter
from datetime import datetime, timezone


def build_report(analyses: list, source_details: dict, evaluation_metrics: dict = None) -> dict:
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
    }

    if source_details.get("model_name"):
        summary["model_name"] = source_details["model_name"]

    if source_details.get("evaluation_method"):
        summary["evaluation_method"] = source_details["evaluation_method"]

    if source_details.get("train_size") is not None:
        summary["train_size"] = source_details["train_size"]

    if source_details.get("test_size") is not None:
        summary["test_size"] = source_details["test_size"]

    if evaluation_metrics is not None:
        summary["evaluation"] = evaluation_metrics

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

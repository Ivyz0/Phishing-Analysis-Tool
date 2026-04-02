import os


def write_pdf_overview(report: dict, output_path: str) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Spacer, Table, TableStyle
        from reportlab.platypus.paragraph import Paragraph
    except ImportError as exc:
        raise RuntimeError(
            "PDF output requires reportlab. Install dependencies with `pip install -r requirements.txt`."
        ) from exc

    output_folder = os.path.dirname(output_path)
    if output_folder != "":
        os.makedirs(output_folder, exist_ok=True)

    styles = getSampleStyleSheet()
    document = SimpleDocTemplate(output_path, pagesize=letter)
    story = []

    summary = report["summary"]
    evaluation = summary.get("evaluation")

    story.append(Paragraph("CEAS Email Analysis Overview", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Generated at: {report['generated_at']}", styles["Normal"]))
    story.append(Paragraph(f"Source: {report['source']['path']}", styles["Normal"]))
    story.append(Spacer(1, 12))

    summary_rows = [
        ["Emails analyzed", summary["emails_analyzed"]],
        ["Model", summary.get("model_name", "n/a")],
        ["Predicted phishing", summary["prediction_counts"].get("Phishing", 0)],
        ["Predicted legitimate", summary["prediction_counts"].get("Legitimate", 0)],
        ["Average risk score", summary["average_risk_score"]],
    ]

    if summary.get("evaluation_method"):
        summary_rows.append(["Evaluation method", summary["evaluation_method"]])

    if summary.get("train_size") is not None:
        summary_rows.append(["Training rows", summary["train_size"]])

    if summary.get("test_size") is not None:
        summary_rows.append(["Test rows", summary["test_size"]])

    if evaluation is not None:
        summary_rows.extend(
            [
                ["Accuracy", format_metric(evaluation["accuracy"])],
                ["Precision", format_metric(evaluation["precision"])],
                ["Recall", format_metric(evaluation["recall"])],
                ["F1 score", format_metric(evaluation["f1_score"])],
            ]
        )

    story.append(Paragraph("Summary", styles["Heading2"]))
    story.append(build_table(Table, TableStyle, colors, [["Metric", "Value"]] + summary_rows))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Top Indicators", styles["Heading2"]))
    indicator_rows = [["Indicator", "Count"]]
    indicators_for_pdf = summary["top_indicators"]
    if len(indicators_for_pdf) > 1:
        indicators_for_pdf = indicators_for_pdf[:-1]

    for indicator in indicators_for_pdf:
        indicator_rows.append([indicator["indicator"], indicator["count"]])

    if len(indicator_rows) == 1:
        indicator_rows.append(["No positive indicators", 0])

    story.append(build_table(Table, TableStyle, colors, indicator_rows))

    document.build(story)


def build_table(Table, TableStyle, colors, rows: list, col_widths=None):
    table = Table(rows, colWidths=col_widths)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DDEBF7")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F7F7")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def format_metric(value: float) -> str:
    return f"{value:.3f}"

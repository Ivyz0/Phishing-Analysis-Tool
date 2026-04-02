import os


def write_pdf_overview(report: dict, output_path: str) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import PageBreak, SimpleDocTemplate, Spacer, Table, TableStyle
        from reportlab.platypus.paragraph import Paragraph
        from reportlab.lib.styles import getSampleStyleSheet
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
        ["Predicted phishing", summary["prediction_counts"].get("Phishing", 0)],
        ["Predicted legitimate", summary["prediction_counts"].get("Legitimate", 0)],
        ["Average risk score", summary["average_risk_score"]],
    ]

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
    for indicator in summary["top_indicators"]:
        indicator_rows.append([indicator["indicator"], indicator["count"]])

    if len(indicator_rows) == 1:
        indicator_rows.append(["No positive indicators", 0])

    story.append(build_table(Table, TableStyle, colors, indicator_rows))
    story.append(Spacer(1, 24))
    story.append(Spacer(1, 24))
    story.append(PageBreak())

    story.append(Paragraph("Highest Risk Emails", styles["Heading2"]))
    high_risk_rows = [["Row", "Risk", "Prediction", "Truth", "Subject"]]
    for item in summary["highest_risk_emails"]:
        high_risk_rows.append(
            [
                item["row_index"],
                item["risk_score"],
                item["prediction"],
                item["ground_truth_label"] or "n/a",
                shorten(item["subject"]),
            ]
        )

    story.append(build_table(Table, TableStyle, colors, high_risk_rows, col_widths=[45, 45, 85, 80, 280]))

    mismatches = summary.get("mismatches", [])
    if mismatches:
        story.append(Spacer(1, 16))
        story.append(Paragraph("Top Prediction Mismatches", styles["Heading2"]))
        mismatch_rows = [["Row", "Risk", "Truth", "Predicted", "Subject"]]

        for item in mismatches:
            mismatch_rows.append(
                [
                    item["row_index"],
                    item["risk_score"],
                    item["ground_truth_label"],
                    item["predicted_label"],
                    shorten(item["subject"]),
                ]
            )

        story.append(build_table(Table, TableStyle, colors, mismatch_rows, col_widths=[45, 45, 80, 80, 285]))

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


def shorten(text: str, max_length: int = 80) -> str:
    if text is None:
        return ""

    single_line = " ".join(text.split())

    if len(single_line) <= max_length:
        return single_line

    return single_line[: max_length - 3] + "..."

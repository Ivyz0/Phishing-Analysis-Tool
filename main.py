import argparse
import os
import sys

from analyzer.ml_classifier import evaluate_dataset, train_model, predict_records, MODEL_NAME
from analyzer.suspicious import analyze_record
from parser.csv_loader import load_emails_from_csv
from parser.header_parser import extract_body_text, parse_email
from reports.json_report import write_json_report
from reports.pdf_report import write_pdf_overview
from reports.report_builder import build_report

DEFAULT_DATASET_PATH = os.path.join("data", "CEAS_08.csv")
DEFAULT_JSON_OUTPUT = os.path.join("reports", "ceas_analysis.json")
DEFAULT_PDF_OUTPUT = os.path.join("reports", "ceas_overview.pdf")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze CEAS emails and produce JSON and PDF reports."
    )
    parser.add_argument(
        "input_path",
        nargs="?",
        default=DEFAULT_DATASET_PATH,
        help="Path to a CEAS CSV file or a single .eml file.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Analyze only the first N emails from a CSV file.",
    )
    parser.add_argument(
        "--json-out",
        default=DEFAULT_JSON_OUTPUT,
        help="Where to write the machine-readable JSON report.",
    )
    parser.add_argument(
        "--pdf-out",
        default=DEFAULT_PDF_OUTPUT,
        help="Where to write the PDF overview.",
    )
    return parser.parse_args()


def load_records(input_path: str, limit: int = None) -> tuple[list, dict]:
    if input_path.lower().endswith(".csv"):
        records = load_emails_from_csv(input_path, max_emails=limit)
        source_details = {
            "input_type": "csv",
            "dataset_name": "CEAS_08",
            "path": os.path.abspath(input_path),
            "limit": limit,
            "model_name": MODEL_NAME,
            "evaluation_method": "80/20 sender-domain grouped holdout",
        }
        return records, source_details

    msg = parse_email(input_path)
    body = extract_body_text(msg)

    record = {
        "index": 1,
        "source_type": "eml_file",
        "dataset_name": None,
        "sender": msg.get("From") or "",
        "receiver": msg.get("To") or "",
        "date": msg.get("Date") or "",
        "subject": msg.get("Subject") or "",
        "body": body,
        "ground_truth_label": None,
        "dataset_url_count": 0,
        "msg": msg,
    }

    source_details = {
        "input_type": "eml",
        "dataset_name": None,
        "path": os.path.abspath(input_path),
        "limit": None,
        "model_name": MODEL_NAME,
        "evaluation_method": "not applicable for single-email prediction",
    }

    return [record], source_details


def run_dataset_analysis(records: list) -> tuple[list, dict]:
    predictions, evaluation_details = evaluate_dataset(records)
    analyses = []

    for record, prediction in zip(records, predictions):
        analyses.append(analyze_record(record, prediction))

    return analyses, evaluation_details


def run_single_email_analysis(record: dict) -> list:
    training_records = load_training_records()
    model = train_model(training_records)
    prediction = predict_records(model, [record])[0]
    return [analyze_record(record, prediction)]


def load_training_records() -> list:
    try:
        return load_emails_from_csv(DEFAULT_DATASET_PATH)
    except (FileNotFoundError, ValueError) as exc:
        raise RuntimeError(
            "A trained model is built from the local CEAS dataset. "
            f"Could not load {DEFAULT_DATASET_PATH}: {exc}"
        ) from exc


def print_summary(report: dict, json_output_path: str, pdf_output_path: str, pdf_written: bool) -> None:
    summary = report["summary"]
    evaluation = summary.get("evaluation")

    print(f"Analyzed {summary['emails_analyzed']} email(s).")
    print(
        "Predicted phishing: "
        f"{summary['prediction_counts'].get('Phishing', 0)} | "
        "Predicted legitimate: "
        f"{summary['prediction_counts'].get('Legitimate', 0)}"
    )

    if evaluation is not None:
        print(
            "Accuracy vs dataset labels: "
            f"{evaluation['accuracy']:.4f} | "
            f"Precision: {evaluation['precision']:.4f} | "
            f"Recall: {evaluation['recall']:.4f} | "
            f"F1: {evaluation['f1_score']:.4f}"
        )

    print(f"JSON report: {os.path.abspath(json_output_path)}")

    if pdf_written:
        print(f"PDF overview: {os.path.abspath(pdf_output_path)}")
    else:
        print("PDF overview: not written")


def main() -> int:
    args = parse_args()

    if args.limit is not None and args.limit <= 0:
        print("The --limit value must be greater than zero.", file=sys.stderr)
        return 1

    try:
        records, source_details = load_records(args.input_path, args.limit)
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if not records:
        print("No emails were loaded from the input file.", file=sys.stderr)
        return 1

    try:
        if source_details["input_type"] == "csv":
            analyses, evaluation_details = run_dataset_analysis(records)
            source_details["evaluation_method"] = evaluation_details["method"]
            source_details["train_size"] = evaluation_details["train_size"]
            source_details["test_size"] = evaluation_details["test_size"]
        else:
            analyses = run_single_email_analysis(records[0])
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    report = build_report(
        analyses,
        source_details,
        evaluation_metrics=evaluation_details.get("metrics") if source_details["input_type"] == "csv" else None,
    )

    write_json_report(report, args.json_out)

    pdf_written = True
    try:
        write_pdf_overview(report, args.pdf_out)
    except RuntimeError as exc:
        pdf_written = False
        print(str(exc), file=sys.stderr)

    print_summary(report, args.json_out, args.pdf_out, pdf_written)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

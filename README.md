# Phish Triage

Phish Triage is a phishing-email analysis project built around the `CEAS_08` dataset.

The current version does two things:

- scores each email as phishing or legitimate
- writes both a machine-readable JSON report and a PDF overview

The project started as a simpler rule-based analyzer, then evolved into a lightweight text-classification pipeline after error analysis showed the rules were too brittle on CEAS. The current model uses TF-IDF features with a linear SVM, which kept the code fast and readable while producing a large jump in accuracy.

## Why I Built It

I wanted a phishing-analysis project that felt practical instead of demo-only:

- a real public dataset
- measurable evaluation
- outputs that could be useful in automation or reporting
- code that is still understandable without turning into a giant ML framework

The goal was not just to classify emails, but to make the tradeoffs visible. That is why the repo keeps both model predictions and human-readable supporting signals in the final output.

## Current Approach

For CEAS CSV runs, the project:

1. loads the dataset in a fixed CEAS-only format
2. builds TF-IDF features from sender, subject, and body text
3. evaluates the classifier with stratified cross-validation
4. writes a JSON report with per-email predictions
5. writes a PDF overview with summary metrics and dataset-level results

For single `.eml` files, it trains on the local CEAS dataset and then predicts the file you pass in.

The explanation layer still adds readable supporting signals such as:

- brand impersonation
- suspicious account language
- link-heavy content
- authentication failures in real `.eml` files
- common signs of legitimate mailing-list or thread traffic

## Results

Current full-dataset CEAS results:

- Accuracy: `0.9985`
- Precision: `0.9990`
- Recall: `0.9982`
- F1: `0.9986`

Previous rule-based baseline:

- Accuracy: `0.8793`
- Precision: `0.8465`
- Recall: `0.9572`
- F1: `0.8985`

That improvement came mainly from replacing hand-tuned scoring rules with a simple linear model that handles wording, formatting, and sender patterns much better across the full dataset.

## Project Structure

- `main.py`: CLI entry point
- `parser/csv_loader.py`: CEAS dataset loading
- `parser/header_parser.py`: `.eml` parsing helpers
- `analyzer/ml_classifier.py`: model training, prediction, and cross-validation
- `analyzer/suspicious.py`: supporting explanation signals
- `reports/json_report.py`: JSON output
- `reports/pdf_report.py`: PDF overview
- `reports/report_builder.py`: summary metrics and report assembly

## Usage

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the default CEAS dataset analysis:

```bash
python main.py
```

Run a smaller slice while iterating:

```bash
python main.py data/CEAS_08.csv --limit 500
```

Analyze a single email file:

```bash
python main.py samples/real-sample-1.eml
```

Default outputs:

- `reports/ceas_analysis.json`
- `reports/ceas_overview.pdf`

## Notes

- The repo is CEAS-only now. Old multi-dataset code paths were intentionally removed.
- Generated JSON and PDF reports are overwritten when the tool runs again with the same output names.
- The PDF overview is meant for quick inspection; the JSON report contains the detailed per-email results.

# Phishing Analysis Tool

Phishing Analysis Tool is a phishing email analysis project built around the `CEAS_08` dataset.

The project takes a practical approach:

- train a simple, explainable classifier
- score emails as phishing or legitimate
- produce both JSON output for automation and a PDF overview for reporting

It is intentionally not a deep learning project. The goal was to build something that feels realistic to explain, maintain, and run locally.

## What It Does

For a CEAS CSV run, the tool:

1. loads the dataset in a fixed CEAS-only format
2. builds a lightweight text model from email subjects
3. evaluates that model on a sender-domain holdout split
4. predicts phishing vs legitimate labels
5. writes:
   - `reports/ceas_analysis.json`
   - `reports/ceas_overview.pdf`

For a single `.eml` file, it trains on the local CEAS dataset and predicts the email you pass in.

## Model Choice

The current classifier is deliberately simple:

- subject text only
- `CountVectorizer`
- `ComplementNB` (Complement Naive Bayes)

That combination is easy to reason about, fast to train, and much more believable as a production-ready baseline than a near-perfect benchmark model.

The repo still keeps a small explanation layer for reporting, so the output can show supporting indicators such as:

- suspicious account language
- links or marketing-style language
- brand impersonation
- authentication failures in real `.eml` files
- signals that look more like legitimate thread or list traffic

## Evaluation Approach

The reported CEAS metrics are based on an `80/20 sender-domain grouped holdout`.

That means:

- the model trains on 80% of the dataset
- the test split is 20%
- sender domains in the test split are held out from training

This is stricter and more realistic than a plain random split because it reduces leakage from very similar senders appearing in both train and test.

## Current Results

Current full-dataset CEAS results:

- Accuracy: `0.9419`
- Precision: `0.9519`
- Recall: `0.9443`
- F1: `0.9481`

Previous rule-based baseline:

- Accuracy: `0.8793`
- Precision: `0.8465`
- Recall: `0.9572`
- F1: `0.8985`

So the project improved substantially over the original rule scoring, but still stays in a realistic range for a simple classical ML approach.

## Why I Built It This Way

I wanted the project to feel like something I could defend in an interview:

- a real dataset
- measurable performance
- straightforward modeling choices
- readable code
- useful outputs instead of just notebook metrics

The point was not to squeeze out the flashiest number possible. It was to build a phishing analysis tool that looks like something an engineer could actually own and explain.

## Project Structure

- `main.py`: CLI entry point
- `parser/csv_loader.py`: CEAS dataset loading
- `parser/header_parser.py`: `.eml` parsing helpers
- `analyzer/ml_classifier.py`: training, holdout evaluation, and prediction
- `analyzer/suspicious.py`: supporting explanation signals
- `reports/json_report.py`: JSON output
- `reports/pdf_report.py`: PDF overview
- `reports/report_builder.py`: report summary logic

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

## Notes

- The project is CEAS-only now. Old multi-dataset code paths were removed.
- Generated JSON and PDF reports are overwritten when the tool runs again with the same output names.
- The PDF overview focuses on evaluation metrics and class balance instead of row-by-row examples.

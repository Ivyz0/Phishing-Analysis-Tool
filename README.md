**A CEAS-focused phishing email analysis tool.**

It reads the `CEAS_08.csv` dataset, scores each email with simple rule-based checks, and writes:

- a machine-readable JSON report for automation
- a PDF overview with summary metrics and top findings

You can still analyze a single `.eml` file, but the default flow is the CEAS dataset.

## Usage

Install dependencies:

```bash
pip install -r requirements.txt
```

Analyze the default CEAS dataset:

```bash
python main.py
```

Analyze only the first 500 rows:

```bash
python main.py data/CEAS_08.csv --limit 500
```

Analyze a single email file:

```bash
python main.py samples/real-sample-1.eml
```

By default the project writes:

- `reports/ceas_analysis.json`
- `reports/ceas_overview.pdf`

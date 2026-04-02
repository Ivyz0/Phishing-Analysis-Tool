import io
import os
import sys
from parser.header_parser import parse_email, extract_sender, extract_received_chain, extract_auth_results
from parser.csv_loader import load_emails_from_csv
from analyzer.suspicious import analyze

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

# ANSI color codes
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"

WIDTH = 72

AUTH_COLORS = {
    "pass":      GREEN,
    "fail":      RED,
    "softfail":  YELLOW,
    "temperror": YELLOW,
    "permerror": RED,
    "neutral":   DIM,
    "none":      DIM,
}

SEVERITY_COLORS = {
    "high":   RED,
    "medium": YELLOW,
    "low":    DIM,
}


def color_auth(value):
    if value is None:
        return DIM + "n/a" + RESET
    col = AUTH_COLORS.get(value.lower(), WHITE)
    return col + value.upper() + RESET


def color_severity(severity):
    col = SEVERITY_COLORS.get(severity.lower(), WHITE)
    return col + severity.upper() + RESET


def divider(char="─"):
    return DIM + char * WIDTH + RESET


def section(title):
    return f"\n  {BOLD}{WHITE}{title}{RESET}\n  " + DIM + "─" * (WIDTH - 2) + RESET


def print_header(title):
    inner = f"  ANALYSIS  {BOLD}{CYAN}{title}{RESET}"
    print(f"\n{DIM}┌{'─' * WIDTH}┐{RESET}")
    print(f"{DIM}│{RESET}{inner}")
    print(f"{DIM}└{'─' * WIDTH}┘{RESET}")


def print_sender_section(msg):
    print(section("SENDER"))
    sender = extract_sender(msg)
    rows = [
        ("From",        sender["from"]),
        ("Reply-To",    sender["reply_to"]),
        ("Return-Path", sender["return_path"]),
    ]
    for label, val in rows:
        display = val if val is not None else DIM + "—" + RESET
        print(f"    {WHITE}{label:<12}{RESET} {display}")


def print_routing_section(msg):
    chain = extract_received_chain(msg)
    hop_label = f"{DIM}({len(chain)} hop{'s' if len(chain) != 1 else ''}){RESET}"
    print(f"\n  {BOLD}{WHITE}ROUTING{RESET}  {hop_label}\n  " + DIM + "─" * (WIDTH - 2) + RESET)

    if not chain:
        print(f"    {DIM}No Received headers found{RESET}")
    else:
        for i, hop in enumerate(chain):
            # Truncate very long hops so the output stays readable
            if len(hop) > WIDTH - 8:
                display = hop[:WIDTH - 11] + DIM + "..." + RESET
            else:
                display = hop
            print(f"    {DIM}{i}{RESET}  {display}")


def print_auth_section(msg):
    print(section("AUTHENTICATION"))
    auth = extract_auth_results(msg)
    for method in ("spf", "dkim", "dmarc"):
        val = auth.get(method)
        print(f"    {WHITE}{method.upper():<8}{RESET} {color_auth(val)}")


def print_findings_section(findings: list):
    print(section("SUSPICIOUS INDICATORS"))

    if not findings:
        print(f"    {GREEN}No suspicious indicators found.{RESET}")
        return

    for finding in findings:
        severity = finding["severity"]
        indicator = finding["indicator"]
        explanation = finding["explanation"]

        # Print the indicator code and severity on one line
        print(f"    {color_severity(severity):<30}  {BOLD}{WHITE}{indicator}{RESET}")

        # Word-wrap the explanation so it fits within our width
        words = explanation.split()
        current_line = "      "
        for word in words:
            # If adding this word would go over the width, start a new line
            if len(current_line) + len(word) + 1 > WIDTH - 2:
                print(f"{DIM}{current_line}{RESET}")
                current_line = "      " + word
            else:
                if current_line == "      ":
                    current_line += word
                else:
                    current_line += " " + word
        # Print whatever is left
        if current_line.strip() != "":
            print(f"{DIM}{current_line}{RESET}")

        print()  # blank line between findings


def run_analysis(file_path: str):
    filename = os.path.basename(file_path)
    print_header(filename)

    msg = parse_email(file_path)

    print_sender_section(msg)
    print_routing_section(msg)
    print_auth_section(msg)

    findings = analyze(msg)
    print_findings_section(findings)

    print(f"\n{DIM}{'─' * (WIDTH + 2)}{RESET}\n")


def run_analysis_from_record(record: dict):
    msg = record["msg"]
    label = record["label"]
    index = record["index"]

    # Build a title that shows the row number and the ground-truth label
    title = f"Row {index}  [{label}]"
    print_header(title)

    print_sender_section(msg)
    print_routing_section(msg)
    print_auth_section(msg)

    findings = analyze(msg)
    print_findings_section(findings)

    print(f"\n{DIM}{'─' * (WIDTH + 2)}{RESET}\n")


def run_all_samples():
    samples_dir = "samples"

    if not os.path.exists(samples_dir):
        print(f"{RED}Samples folder not found: {samples_dir}{RESET}")
        sys.exit(1)

    eml_files = [f for f in os.listdir(samples_dir) if f.endswith(".eml")]

    if not eml_files:
        print(f"{YELLOW}No .eml files found in samples/{RESET}")
        sys.exit(1)

    print(f"\n{DIM}Found {len(eml_files)} sample(s) in samples/ ...{RESET}")

    for filename in sorted(eml_files):
        file_path = os.path.join(samples_dir, filename)
        try:
            run_analysis(file_path)
        except Exception as e:
            print(f"\n{RED}Skipping {filename}: {e}{RESET}\n")


def run_csv_dataset(csv_path: str, max_emails: int = 20):
    print(f"\n{DIM}Loading emails from: {csv_path}{RESET}")

    try:
        records = load_emails_from_csv(csv_path, max_emails=max_emails)
    except (FileNotFoundError, ValueError) as e:
        print(f"\n{RED}{e}{RESET}\n")
        sys.exit(1)

    if not records:
        print(f"{YELLOW}No emails found in the CSV file.{RESET}")
        sys.exit(1)

    print(f"{DIM}Analyzing {len(records)} email(s)...{RESET}")

    for record in records:
        try:
            run_analysis_from_record(record)
        except Exception as e:
            print(f"\n{RED}Skipping row {record['index']}: {e}{RESET}\n")


def find_csv_in_data_folder() -> str:
    data_dir = "data"

    if not os.path.exists(data_dir):
        return None

    csv_files = [f for f in os.listdir(data_dir) if f.endswith(".csv")]

    if not csv_files:
        return None

    # If there are multiple CSVs, just use the first one alphabetically
    csv_files.sort()
    return os.path.join(data_dir, csv_files[0])


if __name__ == "__main__":
    # Usage:
    #   python main.py                        -> auto-detect CSV or fall back to samples/
    #   python main.py data/my_dataset.csv    -> analyze a specific CSV file
    #   python main.py path/to/email.eml      -> analyze a single .eml file
    #   python main.py data/my_dataset.csv 50 -> analyze up to 50 emails from the CSV

    if len(sys.argv) >= 2:
        first_arg = sys.argv[1]

        if first_arg.endswith(".csv"):
            # User passed a CSV file path
            limit = 20
            if len(sys.argv) >= 3:
                try:
                    limit = int(sys.argv[2])
                except ValueError:
                    print(f"{YELLOW}Warning: '{sys.argv[2]}' is not a number, using default limit of 20.{RESET}")
            run_csv_dataset(first_arg, max_emails=limit)

        else:
            # User passed an .eml file (or any other file)
            run_analysis(first_arg)

    else:
        # No arguments — look for a CSV in data/ first, then fall back to samples/
        csv_path = find_csv_in_data_folder()

        if csv_path is not None:
            print(f"\n{DIM}Found dataset: {csv_path}{RESET}")
            run_csv_dataset(csv_path, max_emails=20)
        else:
            print(f"\n{DIM}No CSV dataset found in data/ — using samples/ folder instead.{RESET}")
            print(f"{DIM}To use the Kaggle dataset, download the CSV and place it in data/{RESET}")
            run_all_samples()

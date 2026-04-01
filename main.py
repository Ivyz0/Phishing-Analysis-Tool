import io
import os
import sys
from parser.header_parser import parse_email, extract_sender, extract_received_chain, extract_auth_results

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


def color_auth(value):
    if value is None:
        return DIM + "n/a" + RESET
    col = AUTH_COLORS.get(value.lower(), WHITE)
    return col + value.upper() + RESET


def divider(char="─"):
    return DIM + char * WIDTH + RESET


def section(title):
    return f"\n  {BOLD}{WHITE}{title}{RESET}\n  " + DIM + "─" * (WIDTH - 2) + RESET


def run_analysis(file_path: str):
    filename = os.path.basename(file_path)

    # box header
    inner = f"  ANALYSIS  {BOLD}{CYAN}{filename}{RESET}"
    print(f"\n{DIM}┌{'─' * WIDTH}┐{RESET}")
    print(f"{DIM}│{RESET}{inner}")
    print(f"{DIM}└{'─' * WIDTH}┘{RESET}")

    msg = parse_email(file_path)

    # sender
    print(section("SENDER"))
    sender = extract_sender(msg)
    labels = [("From", sender["from"]), ("Reply-To", sender["reply_to"]), ("Return-Path", sender["return_path"])]
    for label, val in labels:
        display = val if val is not None else DIM + "—" + RESET
        print(f"    {WHITE}{label:<12}{RESET} {display}")

    # routing chain
    chain = extract_received_chain(msg)
    hop_count = f"{DIM}({len(chain)} hop{'s' if len(chain) != 1 else ''}){RESET}"
    print(f"\n  {BOLD}{WHITE}ROUTING{RESET}  {hop_count}\n  " + DIM + "─" * (WIDTH - 2) + RESET)
    if not chain:
        print(f"    {DIM}No Received headers found{RESET}")
    else:
        for i, hop in enumerate(chain):
            # truncate very long hops to keep output readable
            display = hop if len(hop) <= WIDTH - 8 else hop[:WIDTH - 11] + DIM + "..." + RESET
            print(f"    {DIM}{i}{RESET}  {display}")

    # authentication
    print(section("AUTHENTICATION"))
    auth = extract_auth_results(msg)
    for method in ("spf", "dkim", "dmarc"):
        val = auth.get(method)
        print(f"    {WHITE}{method.upper():<8}{RESET} {color_auth(val)}")

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

    print(f"\n{DIM}Found {len(eml_files)} sample(s) to analyze...{RESET}")

    for filename in sorted(eml_files):
        file_path = os.path.join(samples_dir, filename)
        try:
            run_analysis(file_path)
        except Exception as e:
            print(f"\n{RED}Skipping {filename}: {e}{RESET}\n")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_analysis(sys.argv[1])
    else:
        run_all_samples()

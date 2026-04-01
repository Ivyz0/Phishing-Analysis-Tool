import os
import sys
from parser.header_parser import parse_email, extract_sender, extract_received_chain, extract_auth_results


def run_analysis(file_path: str):
    print(f"\nAnalyzing: {file_path}")
    print("=" * 50)

    msg = parse_email(file_path)

    # sender info
    print("\n[Sender Info]")
    sender = extract_sender(msg)
    for key, val in sender.items():
        print(f"  {key}: {val}")

    # received chain
    print("\n[Received Chain]")
    chain = extract_received_chain(msg)
    if len(chain) == 0:
        print("  No Received headers found")
    else:
        for i, hop in enumerate(chain):
            print(f"  [{i}] {hop}")

    # auth results
    print("\n[Authentication Results]")
    auth = extract_auth_results(msg)
    for key, val in auth.items():
        result = val if val != None else "not found"
        print(f"  {key.upper()}: {result}")

    print()


def run_all_samples():
    samples_dir = "samples"

    if not os.path.exists(samples_dir):
        print(f"Samples folder not found: {samples_dir}")
        sys.exit(1)

    eml_files = [f for f in os.listdir(samples_dir) if f.endswith(".eml")]

    if len(eml_files) == 0:
        print("No .eml files found in samples/")
        sys.exit(1)

    print(f"Found {len(eml_files)} sample(s) to analyze...")

    for filename in sorted(eml_files):
        file_path = os.path.join(samples_dir, filename)
        try:
            run_analysis(file_path)
        except Exception as e:
            print(f"\nSkipping {filename}: {e}\n")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_analysis(sys.argv[1])
    else:
        run_all_samples()

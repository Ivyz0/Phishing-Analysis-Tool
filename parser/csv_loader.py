import csv
from email.message import Message

csv.field_size_limit(10 * 1024 * 1024)

CEAS_COLUMNS = [
    "sender",
    "receiver",
    "date",
    "subject",
    "body",
    "label",
    "urls",
]


def load_emails_from_csv(csv_file_path: str, max_emails: int = None) -> list:
    results = []

    try:
        csv_file = open(csv_file_path, "r", encoding="utf-8", errors="replace", newline="")
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Dataset file not found: {csv_file_path}") from exc

    with csv_file:
        reader = csv.DictReader(csv_file)

        if reader.fieldnames is None:
            raise ValueError(f"CSV has no header row: {csv_file_path}")

        validate_ceas_columns(reader.fieldnames, csv_file_path)

        for row_number, row in enumerate(reader, start=1):
            if max_emails is not None and len(results) >= max_emails:
                break

            record = build_record(row, row_number)
            if record is not None:
                results.append(record)

    return results


def validate_ceas_columns(fieldnames: list, csv_file_path: str) -> None:
    normalized_fieldnames = {name.strip().lower() for name in fieldnames if name is not None}
    missing_columns = [column for column in CEAS_COLUMNS if column not in normalized_fieldnames]

    if missing_columns:
        raise ValueError(
            "This project now expects the CEAS CSV layout only.\n"
            f"Missing columns in {csv_file_path}: {missing_columns}\n"
            f"Expected columns: {CEAS_COLUMNS}"
        )


def build_record(row: dict, row_number: int):
    sender = (row.get("sender") or "").strip()
    receiver = (row.get("receiver") or "").strip()
    date = (row.get("date") or "").strip()
    subject = (row.get("subject") or "").strip()
    body = (row.get("body") or "").strip()
    label = normalize_label(row.get("label") or "")
    dataset_url_count = parse_int(row.get("urls"))

    if sender == "" and subject == "" and body == "":
        return None

    return {
        "index": row_number,
        "source_type": "ceas_csv",
        "dataset_name": "CEAS_08",
        "sender": sender,
        "receiver": receiver,
        "date": date,
        "subject": subject,
        "body": body,
        "ground_truth_label": label,
        "dataset_url_count": dataset_url_count,
        "msg": build_message(sender, receiver, subject, date, body),
    }


def normalize_label(label: str) -> str:
    normalized = label.strip().lower()

    if normalized in {"1", "phishing email", "phishing"}:
        return "Phishing"

    if normalized in {"0", "safe email", "legitimate", "ham"}:
        return "Legitimate"

    if normalized == "":
        return "Unknown"

    return normalized.capitalize()


def parse_int(value) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def build_message(sender: str, receiver: str, subject: str, date: str, body: str) -> Message:
    msg = Message()

    if sender != "":
        msg["From"] = sender

    if receiver != "":
        msg["To"] = receiver

    if subject != "":
        msg["Subject"] = subject

    if date != "":
        msg["Date"] = date

    if body != "":
        msg.set_payload(body)

    return msg

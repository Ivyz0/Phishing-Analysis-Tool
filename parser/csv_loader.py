import csv
import email
from email.message import Message

# download from: https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset
# place the CSV in data/ and run: python main.py

# common column name variations for the email body field
EMAIL_TEXT_COLUMNS = [
    "Email Text",
    "email_text",
    "text",
    "body",
    "content",
    "message",
    "email",
]

# common column name variations for the phishing/safe label field
EMAIL_LABEL_COLUMNS = [
    "Email Type",
    "email_type",
    "label",
    "type",
    "is_phishing",
    "class",
    "category",
]


# returns a list of dicts: {msg, label, index}
def load_emails_from_csv(csv_file_path: str, max_emails: int = None) -> list:
    results = []

    try:
        csv_file = open(csv_file_path, "r", encoding="utf-8", errors="replace", newline="")
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Could not find the dataset file: {csv_file_path}\n"
            f"Download it from:\n"
            f"  https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset\n"
            f"Then place the CSV file at: {csv_file_path}"
        )

    reader = csv.DictReader(csv_file)

    if reader.fieldnames is None:
        csv_file.close()
        raise ValueError(f"CSV file appears to be empty or has no header row: {csv_file_path}")

    text_column = find_column_name(reader.fieldnames, EMAIL_TEXT_COLUMNS)
    if text_column is None:
        csv_file.close()
        raise ValueError(
            f"Could not find the email text column in the CSV.\n"
            f"Found columns: {list(reader.fieldnames)}\n"
            f"Expected one of: {EMAIL_TEXT_COLUMNS}"
        )

    label_column = find_column_name(reader.fieldnames, EMAIL_LABEL_COLUMNS)
    if label_column is None:
        csv_file.close()
        raise ValueError(
            f"Could not find the label column in the CSV.\n"
            f"Found columns: {list(reader.fieldnames)}\n"
            f"Expected one of: {EMAIL_LABEL_COLUMNS}"
        )

    row_number = 0

    for row in reader:
        row_number += 1

        if max_emails is not None and len(results) >= max_emails:
            break

        email_text = row.get(text_column, "")
        label = row.get(label_column, "unknown")

        if email_text is None or email_text.strip() == "":
            continue

        msg = parse_email_from_text(email_text.strip())

        results.append({
            "msg":   msg,
            "label": label,
            "index": row_number,
        })

    csv_file.close()

    return results


# case-insensitive search through fieldnames, returns the actual column name or None
def find_column_name(fieldnames, candidates: list):
    lowercase_to_actual = {}
    for fieldname in fieldnames:
        if fieldname is not None:
            lowercase_to_actual[fieldname.lower().strip()] = fieldname

    for candidate in candidates:
        candidate_lower = candidate.lower().strip()
        if candidate_lower in lowercase_to_actual:
            return lowercase_to_actual[candidate_lower]

    return None


# tries to parse text as a real email; falls back to a body-only Message if there are no headers
def parse_email_from_text(email_text: str) -> Message:
    parsed = email.message_from_string(email_text)

    has_from = parsed.get("From") is not None
    has_subject = parsed.get("Subject") is not None
    has_received = parsed.get("Received") is not None
    has_auth = parsed.get("Authentication-Results") is not None

    has_any_header = has_from or has_subject or has_received or has_auth

    if has_any_header:
        return parsed

    # no headers — wrap the raw text in a minimal Message so the rest of the code won't break
    body_only_msg = Message()
    body_only_msg.set_payload(email_text)

    return body_only_msg

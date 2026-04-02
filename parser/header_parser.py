import email
from email.message import Message
from typing import Optional


def parse_email(file_path: str) -> Message:
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as email_file:
            file_content = email_file.read()
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Could not find email file: {file_path}") from exc

    if file_content == "":
        raise ValueError(f"Email file is empty: {file_path}")

    msg = email.message_from_string(file_content)

    if msg["From"] is None and msg["Subject"] is None:
        raise ValueError(f"Doesn't look like a valid email file: {file_path}")

    return msg


def extract_body_text(msg: Message) -> str:
    if msg.is_multipart():
        body_parts = []

        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue

            disposition = (part.get("Content-Disposition") or "").lower()
            if disposition.startswith("attachment"):
                continue

            body_text = decode_part_payload(part)
            if body_text != "":
                body_parts.append(body_text)

        return "\n".join(body_parts).strip()

    return decode_part_payload(msg).strip()


def decode_part_payload(part: Message) -> str:
    payload = part.get_payload(decode=True)

    if isinstance(payload, bytes):
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")

    raw_payload = part.get_payload()

    if isinstance(raw_payload, str):
        return raw_payload

    return ""
def extract_received_chain(msg: Message) -> list:
    received_headers = msg.get_all("Received")

    if received_headers is None:
        return []

    cleaned_headers = []

    for header in received_headers:
        cleaned_headers.append(" ".join(header.split()))

    return cleaned_headers


def extract_auth_results(msg: Message) -> dict:
    auth_results = {
        "spf": None,
        "dkim": None,
        "dmarc": None,
    }

    auth_header = msg.get("Authentication-Results")

    if auth_header is None:
        return auth_results

    auth_text = " ".join(auth_header.lower().split())

    spf_result = _find_auth_value(auth_text, "spf")
    dkim_result = _find_auth_value(auth_text, "dkim")
    dmarc_result = _find_auth_value(auth_text, "dmarc")

    if spf_result is not None:
        auth_results["spf"] = spf_result

    if dkim_result is not None:
        auth_results["dkim"] = dkim_result

    if dmarc_result is not None:
        auth_results["dmarc"] = dmarc_result

    return auth_results


def _find_auth_value(auth_text: str, method: str) -> Optional[str]:
    search_for = method + "="
    position = auth_text.find(search_for)

    if position == -1:
        return None

    start = position + len(search_for)
    remaining = auth_text[start:]

    end = len(remaining)
    for i, char in enumerate(remaining):
        if char == " " or char == ";":
            end = i
            break

    value = remaining[:end].strip()

    if value != "":
        return value

    return None

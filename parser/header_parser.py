import email
from email.message import Message
from typing import Optional


def parse_email(file_path: str) -> Message:
    file_content = None

    try:
        f = open(file_path, "r", encoding="utf-8")
        file_content = f.read()
        f.close()
    except FileNotFoundError:
        raise FileNotFoundError(f"Could not find email file: {file_path}")

    if file_content == "" or file_content == None:
        raise ValueError(f"Email file is empty: {file_path}")

    msg = email.message_from_string(file_content)

    if msg["From"] == None:
        raise ValueError(f"Doesn't look like a valid email file: {file_path}")

    return msg


def extract_sender(msg: Message) -> dict:
    from_header = msg.get("From")
    reply_to_header = msg.get("Reply-To")
    return_path_header = msg.get("Return-Path")

    sender_info = {
        "from": from_header,
        "reply_to": reply_to_header,
        "return_path": return_path_header,
    }

    return sender_info


def extract_received_chain(msg: Message) -> list:
    received_headers = msg.get_all("Received")

    if received_headers == None:
        return []

    cleaned_headers = []

    for header in received_headers:
        # strip out newlines and extra spaces
        parts = header.split()
        cleaned = " ".join(parts)
        cleaned_headers.append(cleaned)

    return cleaned_headers


def extract_auth_results(msg: Message) -> dict:
    auth_results = {
        "spf": None,
        "dkim": None,
        "dmarc": None,
    }

    auth_header = msg.get("Authentication-Results")

    if auth_header == None:
        return auth_results

    # normalize it so its easier to work with
    auth_text = auth_header.lower()
    auth_text = " ".join(auth_text.split())

    spf_result = _find_auth_value(auth_text, "spf")
    dkim_result = _find_auth_value(auth_text, "dkim")
    dmarc_result = _find_auth_value(auth_text, "dmarc")

    if spf_result != None:
        auth_results["spf"] = spf_result

    if dkim_result != None:
        auth_results["dkim"] = dkim_result

    if dmarc_result != None:
        auth_results["dmarc"] = dmarc_result

    return auth_results


# looks for patterns like "spf=fail" and returns the value after the =
def _find_auth_value(auth_text: str, method: str) -> Optional[str]:
    search_for = method + "="
    position = auth_text.find(search_for)

    if position == -1:
        return None

    start = position + len(search_for)
    remaining = auth_text[start:]

    end = len(remaining)
    for i in range(len(remaining)):
        char = remaining[i]
        if char == " " or char == ";":
            end = i
            break

    value = remaining[:end].strip()

    if value != "":
        return value

    return None

import re
from email.message import Message
from email.utils import parseaddr

from parser.header_parser import extract_auth_results, extract_body_text, extract_received_chain

KNOWN_BRANDS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca"],
    "apple": ["apple.com"],
    "microsoft": ["microsoft.com", "outlook.com", "hotmail.com"],
    "google": ["google.com", "gmail.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "citibank": ["citibank.com", "citi.com"],
    "irs": ["irs.gov"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "dhl": ["dhl.com"],
    "dropbox": ["dropbox.com"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "cnn": ["cnn.com"],
}

FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "hotmail.com",
    "outlook.com",
    "yahoo.com",
    "aol.com",
    "icloud.com",
    "live.com",
    "msn.com",
}

URL_PATTERN = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
URGENT_PATTERN = re.compile(
    r"\b(?:urgent|immediate|immediately|alert|warning|attention|important|"
    r"action required|final notice|limited time|expires?|suspended?)\b",
    re.IGNORECASE,
)
ACCOUNT_PATTERN = re.compile(
    r"\b(?:verify|verification|login|log in|password|account|confirm|security|"
    r"unlock|suspend|reset|update your account)\b",
    re.IGNORECASE,
)
FINANCE_PATTERN = re.compile(
    r"\b(?:bank|payment|invoice|billing|credit card|debit|wire transfer|refund|"
    r"tax|statement)\b",
    re.IGNORECASE,
)
MARKETING_PATTERN = re.compile(
    r"\b(?:replica|rolex|watches?|pharmacy|pharm|viagra|cialis|casino|lottery|"
    r"winner|sex|dating|penis|enlargement|loan|mortgage)\b",
    re.IGNORECASE,
)
CALL_TO_ACTION_PATTERN = re.compile(
    r"\b(?:click here|open the link|follow the link|visit|act now|claim now|"
    r"apply now|sign in)\b",
    re.IGNORECASE,
)
TECHNICAL_THREAD_PATTERN = re.compile(
    r"\b(?:patch|bug|issue|commit|svn|python|perl|opensuse|apache|mailing list|"
    r"buildbot|wrote:|spamassassin|submission notes|virus total|clamav|cvsroot|"
    r"log message)\b",
    re.IGNORECASE,
)
SPACED_TEXT_PATTERN = re.compile(r"(?:\b[A-Za-z]\b\s+){6,}")


def analyze_record(record: dict) -> dict:
    msg = record["msg"]
    sender = record.get("sender") or msg.get("From") or ""
    subject = record.get("subject") or msg.get("Subject") or ""
    body = record.get("body") or extract_body_text(msg)
    detected_urls = extract_urls(" ".join([subject, body]))

    signals = []
    signals.extend(check_domain_mismatch(msg))
    signals.extend(check_reply_to_mismatch(msg))
    signals.extend(check_auth_failures(msg))
    signals.extend(check_received_chain(msg))
    signals.extend(check_brand_impersonation(sender, subject))
    signals.extend(check_content_signals(record, sender, subject, body, len(detected_urls)))

    total_points = sum(signal["points"] for signal in signals)
    risk_score = clamp_score(50 + total_points)
    predicted_label = "Phishing" if risk_score >= 50 else "Legitimate"

    return {
        "row_index": record.get("index"),
        "source_type": record.get("source_type"),
        "ground_truth_label": record.get("ground_truth_label"),
        "sender": sender,
        "receiver": record.get("receiver") or msg.get("To"),
        "date": record.get("date") or msg.get("Date"),
        "subject": subject,
        "prediction": {
            "label": predicted_label,
            "is_phishing": predicted_label == "Phishing",
            "risk_score": risk_score,
            "confidence": score_to_confidence(risk_score),
        },
        "signals": sort_signals(signals),
        "body_preview": build_preview(body),
        "url_summary": {
            "dataset_url_count": record.get("dataset_url_count", 0),
            "detected_url_count": len(detected_urls),
        },
        "explanation": build_explanation(predicted_label, signals),
    }


def analyze(msg: Message) -> list:
    return analyze_record({"msg": msg}).get("signals", [])


def check_domain_mismatch(msg: Message) -> list:
    from_domain = get_domain_from_address(msg.get("From"))
    return_path_domain = get_domain_from_address(msg.get("Return-Path"))

    if from_domain is None or return_path_domain is None:
        return []

    if from_domain == return_path_domain:
        return []

    return [
        make_signal(
            indicator="DOMAIN_MISMATCH",
            points=25,
            category="sender",
            explanation=(
                f"The visible From domain '{from_domain}' does not match the "
                f"Return-Path domain '{return_path_domain}'."
            ),
        )
    ]


def check_reply_to_mismatch(msg: Message) -> list:
    from_domain = get_domain_from_address(msg.get("From"))
    reply_to_domain = get_domain_from_address(msg.get("Reply-To"))

    if from_domain is None or reply_to_domain is None:
        return []

    if from_domain == reply_to_domain:
        return []

    return [
        make_signal(
            indicator="REPLY_TO_MISMATCH",
            points=15,
            category="sender",
            explanation=(
                f"The Reply-To domain '{reply_to_domain}' is different from the "
                f"From domain '{from_domain}'."
            ),
        )
    ]


def check_auth_failures(msg: Message) -> list:
    auth_results = extract_auth_results(msg)
    signals = []

    if auth_results.get("spf") == "fail":
        signals.append(
            make_signal(
                indicator="SPF_FAIL",
                points=25,
                category="authentication",
                explanation="SPF failed, so the sending server was not authorized for the domain.",
            )
        )
    elif auth_results.get("spf") == "softfail":
        signals.append(
            make_signal(
                indicator="SPF_SOFTFAIL",
                points=12,
                category="authentication",
                explanation="SPF soft failed, which is weaker than a hard fail but still suspicious.",
            )
        )

    if auth_results.get("dkim") == "fail":
        signals.append(
            make_signal(
                indicator="DKIM_FAIL",
                points=25,
                category="authentication",
                explanation="DKIM failed, which means the signature could not be trusted.",
            )
        )

    if auth_results.get("dmarc") == "fail":
        signals.append(
            make_signal(
                indicator="DMARC_FAIL",
                points=25,
                category="authentication",
                explanation="DMARC failed, which means the message did not align with the domain policy.",
            )
        )

    return signals


def check_received_chain(msg: Message) -> list:
    chain = extract_received_chain(msg)

    if not chain:
        return []

    signals = []

    if len(chain) > 10:
        signals.append(
            make_signal(
                indicator="EXCESSIVE_HOPS",
                points=8,
                category="routing",
                explanation=f"The email passed through {len(chain)} hops before delivery.",
            )
        )

    private_ips = []
    for hop in chain:
        for ip_address in extract_ipv4_addresses(hop):
            if is_private_ip(ip_address) and ip_address not in private_ips:
                private_ips.append(ip_address)

    if private_ips:
        signals.append(
            make_signal(
                indicator="PRIVATE_IP_IN_CHAIN",
                points=12,
                category="routing",
                explanation=(
                    "Private IP addresses appeared in the Received chain: "
                    + ", ".join(private_ips)
                ),
            )
        )

    return signals


def check_brand_impersonation(sender: str, subject: str) -> list:
    sender_domain = get_domain_from_address(sender)

    if sender_domain is None:
        return []

    text_to_check = " ".join(filter(None, [extract_display_name(sender), subject])).lower()

    for brand_name, allowed_domains in KNOWN_BRANDS.items():
        if brand_name not in text_to_check:
            continue

        if sender_domain_matches(sender_domain, allowed_domains):
            return []

        return [
            make_signal(
                indicator="BRAND_IMPERSONATION",
                points=22,
                category="sender",
                explanation=(
                    f"The sender name or subject references '{brand_name}', but the sender "
                    f"domain is '{sender_domain}'."
                ),
            )
        ]

    return []


def check_content_signals(
    record: dict,
    sender: str,
    subject: str,
    body: str,
    detected_url_count: int,
) -> list:
    signals = []
    full_text = " ".join([subject, body])
    sender_domain = get_domain_from_address(sender)
    display_name = extract_display_name(sender)
    dataset_url_count = record.get("dataset_url_count", 0)

    has_urgent_language = URGENT_PATTERN.search(subject) is not None
    has_account_language = ACCOUNT_PATTERN.search(full_text) is not None
    has_finance_language = FINANCE_PATTERN.search(full_text) is not None
    has_marketing_language = MARKETING_PATTERN.search(full_text) is not None
    has_call_to_action = CALL_TO_ACTION_PATTERN.search(full_text) is not None

    if has_urgent_language:
        signals.append(
            make_signal(
                indicator="URGENT_LANGUAGE",
                points=18,
                category="content",
                explanation="The subject uses urgent language that tries to push quick action.",
            )
        )

    if has_account_language:
        signals.append(
            make_signal(
                indicator="ACCOUNT_LANGUAGE",
                points=20,
                category="content",
                explanation="The email asks about account access, passwords, or verification.",
            )
        )

    if has_finance_language:
        signals.append(
            make_signal(
                indicator="FINANCIAL_LANGUAGE",
                points=12,
                category="content",
                explanation="The message talks about payments, invoices, tax, or other money topics.",
            )
        )

    if has_marketing_language:
        signals.append(
            make_signal(
                indicator="MARKETING_SPAM_LANGUAGE",
                points=28,
                category="content",
                explanation="The wording matches common scam or spam campaigns in the CEAS dataset.",
            )
        )

    if has_call_to_action:
        signals.append(
            make_signal(
                indicator="ACTION_LINK_LANGUAGE",
                points=15,
                category="content",
                explanation="The text encourages the reader to click or visit a link.",
            )
        )

    if detected_url_count >= 2:
        signals.append(
            make_signal(
                indicator="MULTIPLE_LINKS",
                points=10,
                category="content",
                explanation=f"The message contains {detected_url_count} detected links.",
            )
        )
    elif detected_url_count >= 1 and (has_account_language or has_urgent_language or has_marketing_language):
        signals.append(
            make_signal(
                indicator="LINK_WITH_RISKY_LANGUAGE",
                points=8,
                category="content",
                explanation="A link appears together with phishing-style language.",
            )
        )

    if dataset_url_count >= 1 and (has_account_language or has_marketing_language):
        signals.append(
            make_signal(
                indicator="DATASET_URL_SIGNAL",
                points=8,
                category="content",
                explanation="The CEAS row says the message contains at least one URL with suspicious wording.",
            )
        )

    if SPACED_TEXT_PATTERN.search(body):
        signals.append(
            make_signal(
                indicator="OBFUSCATED_TEXT",
                points=15,
                category="content",
                explanation="The body contains spaced-out text, which is often used to dodge filters.",
            )
        )

    if sender_domain in FREE_EMAIL_DOMAINS and display_name is not None and " " in display_name:
        signals.append(
            make_signal(
                indicator="FREE_EMAIL_SENDER",
                points=6,
                category="sender",
                explanation="The sender uses a free-email domain while presenting a person or brand name.",
            )
        )

    if subject.lower().startswith(("re:", "fwd:")):
        signals.append(
            make_signal(
                indicator="THREAD_SUBJECT",
                points=-15,
                category="content",
                explanation="The subject looks like part of an existing email thread.",
            )
        )

    if subject.startswith("[") and "]" in subject:
        signals.append(
            make_signal(
                indicator="MAILING_LIST_SUBJECT",
                points=-15,
                category="content",
                explanation="The bracketed subject looks like a mailing-list or group email.",
            )
        )

    if TECHNICAL_THREAD_PATTERN.search(full_text):
        signals.append(
            make_signal(
                indicator="TECHNICAL_DISCUSSION_LANGUAGE",
                points=-22,
                category="content",
                explanation="The wording looks like a technical discussion thread, which is common in legitimate mail.",
            )
        )

    if ("wrote:" in body.lower() or subject.lower().startswith(("re:", "fwd:"))) and body.count(">") >= 5:
        signals.append(
            make_signal(
                indicator="QUOTED_CONVERSATION",
                points=-10,
                category="content",
                explanation="The body contains quoted conversation text, which often appears in normal threads.",
            )
        )

    if "unsubscribe" in body.lower() and not has_marketing_language:
        signals.append(
            make_signal(
                indicator="NEWSLETTER_STYLE_TEXT",
                points=-8,
                category="content",
                explanation="The email reads more like a newsletter or list message than a phishing lure.",
            )
        )

    return signals


def make_signal(indicator: str, points: int, category: str, explanation: str) -> dict:
    severity = "low"

    if abs(points) >= 20:
        severity = "high"
    elif abs(points) >= 10:
        severity = "medium"

    return {
        "indicator": indicator,
        "category": category,
        "direction": "increase" if points > 0 else "decrease",
        "points": points,
        "severity": severity,
        "explanation": explanation,
    }


def sort_signals(signals: list) -> list:
    return sorted(signals, key=lambda signal: (abs(signal["points"]), signal["indicator"]), reverse=True)


def build_explanation(predicted_label: str, signals: list) -> str:
    positive_signals = [signal["indicator"] for signal in signals if signal["points"] > 0][:3]
    negative_signals = [signal["indicator"] for signal in signals if signal["points"] < 0][:2]

    if predicted_label == "Phishing":
        if positive_signals:
            return "Predicted phishing because of: " + ", ".join(positive_signals) + "."
        return "Predicted phishing because the score stayed at or above the phishing threshold."

    if negative_signals:
        return "Predicted legitimate because of: " + ", ".join(negative_signals) + "."

    return "Predicted legitimate because the score stayed below the phishing threshold."


def clamp_score(score: int) -> int:
    return max(0, min(100, score))


def score_to_confidence(score: int) -> str:
    distance_from_threshold = abs(score - 50)

    if distance_from_threshold >= 25:
        return "high"

    if distance_from_threshold >= 10:
        return "medium"

    return "low"


def build_preview(text: str, max_length: int = 220) -> str:
    single_line = " ".join(text.split())

    if len(single_line) <= max_length:
        return single_line

    return single_line[: max_length - 3] + "..."


def extract_urls(text: str) -> list:
    return [match.rstrip(".,);]>") for match in URL_PATTERN.findall(text)]


def get_domain_from_address(address_string: str):
    if address_string is None:
        return None

    _, email_address = parseaddr(address_string)

    if "@" not in email_address:
        return None

    return email_address.split("@")[-1].strip().lower() or None


def extract_display_name(address_string: str):
    if address_string is None:
        return None

    display_name, _ = parseaddr(address_string)
    cleaned_name = display_name.strip().strip('"').strip("'").strip()

    if cleaned_name == "":
        return None

    return cleaned_name


def sender_domain_matches(sender_domain: str, expected_domains: list) -> bool:
    for expected_domain in expected_domains:
        if sender_domain == expected_domain:
            return True

        if sender_domain.endswith("." + expected_domain):
            return True

    return False


def extract_ipv4_addresses(text: str) -> list:
    ip_list = []

    for token in text.split():
        clean_token = token.strip("[](){}<>,;:")
        parts = clean_token.split(".")

        if len(parts) != 4:
            continue

        if all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
            ip_list.append(clean_token)

    return ip_list


def is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    first = int(parts[0])
    second = int(parts[1])

    if first == 10:
        return True

    if first == 172 and 16 <= second <= 31:
        return True

    if first == 192 and second == 168:
        return True

    if first == 127:
        return True

    return False

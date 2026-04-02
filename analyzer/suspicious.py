from email.message import Message

# brand name -> list of domains it legitimately sends from
KNOWN_BRANDS = {
    "paypal":          ["paypal.com"],
    "amazon":          ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca"],
    "apple":           ["apple.com"],
    "microsoft":       ["microsoft.com", "outlook.com", "hotmail.com"],
    "google":          ["google.com", "gmail.com"],
    "facebook":        ["facebook.com", "fb.com"],
    "instagram":       ["instagram.com"],
    "netflix":         ["netflix.com"],
    "chase":           ["chase.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo":     ["wellsfargo.com"],
    "citibank":        ["citibank.com", "citi.com"],
    "irs":             ["irs.gov"],
    "fedex":           ["fedex.com"],
    "ups":             ["ups.com"],
    "dhl":             ["dhl.com"],
    "dropbox":         ["dropbox.com"],
    "linkedin":        ["linkedin.com"],
    "twitter":         ["twitter.com", "x.com"],
}


# runs all checks and returns a combined list of findings
# each finding: {"severity": "high"/"medium"/"low", "indicator": "CODE", "explanation": "..."}
def analyze(msg: Message) -> list:
    findings = []

    domain_finding = check_domain_mismatch(msg)
    if domain_finding is not None:
        findings.append(domain_finding)

    reply_to_finding = check_reply_to_mismatch(msg)
    if reply_to_finding is not None:
        findings.append(reply_to_finding)

    auth_findings = check_auth_failures(msg)
    for finding in auth_findings:
        findings.append(finding)

    chain_findings = check_received_chain(msg)
    for finding in chain_findings:
        findings.append(finding)

    spoofing_finding = check_display_name_spoofing(msg)
    if spoofing_finding is not None:
        findings.append(spoofing_finding)

    return findings


# --- checks ---

# flags when the visible From domain differs from where the email actually came from
def check_domain_mismatch(msg: Message):
    from_header = msg.get("From")
    return_path_header = msg.get("Return-Path")

    if from_header is None or return_path_header is None:
        return None

    from_domain = get_domain_from_address(from_header)
    return_path_domain = get_domain_from_address(return_path_header)

    if from_domain is None or return_path_domain is None:
        return None

    if from_domain != return_path_domain:
        return {
            "severity": "high",
            "indicator": "DOMAIN_MISMATCH",
            "explanation": (
                f"The From domain '{from_domain}' does not match the Return-Path "
                f"domain '{return_path_domain}'. This often means the visible sender "
                f"address is forged, and the email actually came from a different server."
            )
        }

    return None


# flags when Reply-To points somewhere different so replies go to the attacker
def check_reply_to_mismatch(msg: Message):
    from_header = msg.get("From")
    reply_to_header = msg.get("Reply-To")

    if from_header is None or reply_to_header is None:
        return None

    from_domain = get_domain_from_address(from_header)
    reply_to_domain = get_domain_from_address(reply_to_header)

    if from_domain is None or reply_to_domain is None:
        return None

    if from_domain != reply_to_domain:
        return {
            "severity": "medium",
            "indicator": "REPLY_TO_MISMATCH",
            "explanation": (
                f"The Reply-To domain '{reply_to_domain}' is different from the "
                f"From domain '{from_domain}'. If you reply to this email, your "
                f"message will go to a different address than the stated sender."
            )
        }

    return None


# checks the Authentication-Results header for SPF, DKIM, and DMARC failures
def check_auth_failures(msg: Message) -> list:
    findings = []

    auth_header = msg.get("Authentication-Results")

    if auth_header is None:
        return findings

    auth_text = auth_header.lower()

    spf_value = get_auth_result(auth_text, "spf")

    if spf_value == "fail":
        findings.append({
            "severity": "high",
            "indicator": "SPF_FAIL",
            "explanation": (
                "SPF check failed. The mail server that sent this email is NOT "
                "listed as an authorized sender for the From domain. The domain "
                "owner did not allow this server to send on their behalf."
            )
        })
    elif spf_value == "softfail":
        findings.append({
            "severity": "medium",
            "indicator": "SPF_SOFTFAIL",
            "explanation": (
                "SPF returned a soft fail. The domain owner suggests this server "
                "should not be sending mail, but has not set a strict policy. "
                "Treat this email with caution."
            )
        })

    dkim_value = get_auth_result(auth_text, "dkim")

    if dkim_value == "fail":
        findings.append({
            "severity": "high",
            "indicator": "DKIM_FAIL",
            "explanation": (
                "DKIM signature check failed. Either the email was modified after "
                "it was sent, or the digital signature is invalid. Legitimate emails "
                "from reputable senders should pass DKIM."
            )
        })

    dmarc_value = get_auth_result(auth_text, "dmarc")

    if dmarc_value == "fail":
        findings.append({
            "severity": "high",
            "indicator": "DMARC_FAIL",
            "explanation": (
                "DMARC policy check failed. The email does not align with the "
                "domain's published authentication policy. This means the email "
                "likely did not originate from an authorized source for this domain."
            )
        })

    return findings


# scans Received headers for too many hops, bulk-mail keywords, and private IPs
def check_received_chain(msg: Message) -> list:
    findings = []

    received_headers = msg.get_all("Received")

    if received_headers is None:
        return findings

    hop_count = len(received_headers)

    if hop_count > 10:
        findings.append({
            "severity": "low",
            "indicator": "EXCESSIVE_HOPS",
            "explanation": (
                f"This email passed through {hop_count} hops. Legitimate emails "
                f"typically have fewer than 10. A large hop count can indicate "
                f"routing through multiple third-party relay servers."
            )
        })

    bulk_keywords = [
        "bulk", "mass", "blast", "smtp-relay",
        "newsletter", "campaign", "listserv", "mailer-daemon",
        "mail-relay", "bulk-out",
    ]

    # track already-flagged keywords so we don't duplicate findings
    flagged_keywords = []

    for hop in received_headers:
        hop_lower = hop.lower()

        for keyword in bulk_keywords:
            if keyword in hop_lower and keyword not in flagged_keywords:
                flagged_keywords.append(keyword)
                findings.append({
                    "severity": "low",
                    "indicator": "BULK_MAIL_HOP",
                    "explanation": (
                        f"A Received header contains the keyword '{keyword}', "
                        f"which is often associated with bulk mailing infrastructure. "
                        f"This email may have been sent through a mass-mailing service."
                    )
                })

        ip_list = extract_ipv4_addresses(hop)

        for ip in ip_list:
            if is_private_ip(ip):
                findings.append({
                    "severity": "medium",
                    "indicator": "PRIVATE_IP_IN_CHAIN",
                    "explanation": (
                        f"A Received header contains the private IP address {ip}. "
                        f"Private IPs should not appear in public email routing headers "
                        f"and may indicate a misconfigured or spoofed mail server."
                    )
                })

    return findings


# flags when the display name says e.g. "PayPal" but the email is from gmail.com
def check_display_name_spoofing(msg: Message):
    from_header = msg.get("From")

    if from_header is None:
        return None

    display_name = extract_display_name(from_header)

    if display_name is None:
        return None

    display_name_lower = display_name.lower()
    email_domain = get_domain_from_address(from_header)

    if email_domain is None:
        return None

    for brand_name in KNOWN_BRANDS:
        if brand_name not in display_name_lower:
            continue

        expected_domains = KNOWN_BRANDS[brand_name]
        domain_is_legit = False

        for expected_domain in expected_domains:
            if email_domain == expected_domain:
                domain_is_legit = True
                break
            # also allow subdomains like mail.paypal.com
            if email_domain.endswith("." + expected_domain):
                domain_is_legit = True
                break

        if not domain_is_legit:
            return {
                "severity": "high",
                "indicator": "DISPLAY_NAME_SPOOFING",
                "explanation": (
                    f"The display name '{display_name}' implies the email is from "
                    f"{brand_name.title()}, but the actual sending domain is "
                    f"'{email_domain}'. {brand_name.title()} would not send email "
                    f"from this domain. This is a classic brand impersonation technique."
                )
            }

    return None


# --- helpers ---

# handles both "user@domain.com" and "Display Name <user@domain.com>"
def get_domain_from_address(address_string: str):
    if address_string is None:
        return None

    address_string = address_string.strip()

    if "<" in address_string and ">" in address_string:
        start = address_string.find("<") + 1
        end = address_string.find(">")
        address_string = address_string[start:end]

    address_string = address_string.strip()

    if "@" not in address_string:
        return None

    parts = address_string.split("@")
    domain = parts[-1].strip().lower()

    if domain == "":
        return None

    return domain


# returns the part before the < bracket, e.g. "PayPal Security" from "PayPal Security <x@y.com>"
def extract_display_name(from_header: str):
    if from_header is None:
        return None

    from_header = from_header.strip()

    if "<" not in from_header:
        return None

    display_name = from_header[:from_header.find("<")].strip()
    display_name = display_name.strip('"').strip("'").strip()

    if display_name == "":
        return None

    return display_name


# finds e.g. "spf=fail" in a lowercased auth-results string and returns "fail"
def get_auth_result(auth_text: str, method: str):
    search_token = method + "="
    position = auth_text.find(search_token)

    if position == -1:
        return None

    value_start = position + len(search_token)
    remaining = auth_text[value_start:]

    end_index = len(remaining)
    for i in range(len(remaining)):
        char = remaining[i]
        if char == " " or char == ";" or char == "\n" or char == "\r":
            end_index = i
            break

    value = remaining[:end_index].strip()

    if value == "":
        return None

    return value


# pulls all x.x.x.x style addresses out of a string
def extract_ipv4_addresses(text: str) -> list:
    ip_list = []
    tokens = text.split()

    for token in tokens:
        clean_token = token.strip("[](){}<>,;:")
        parts = clean_token.split(".")

        if len(parts) != 4:
            continue

        is_valid_ip = True
        for part in parts:
            if not part.isdigit():
                is_valid_ip = False
                break
            number = int(part)
            if number < 0 or number > 255:
                is_valid_ip = False
                break

        if is_valid_ip:
            ip_list.append(clean_token)

    return ip_list


# private ranges: 10.x, 172.16-31.x, 192.168.x, 127.x (loopback)
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

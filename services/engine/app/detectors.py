from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


AADHAAR_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")
PAN_RE = re.compile(r"(?i)(?<![A-Z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Z0-9])")
PHONE_RE = re.compile(r"(?<!\d)([6-9]\d{9})(?!\d)")
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
EMAIL_RE = re.compile(r"(?i)(?<![\w.+-])[\w.+-]{1,64}@[\w-]+(?:\.[\w-]+)+")
UPI_RE = re.compile(r"(?i)(?<![\w.+-])[\w.-]{2,64}@[a-z][a-z0-9]{1,31}(?![\w.-])")
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")

KEYWORDS = {
    "aadhaar": {"aadhaar", "aadhar", "uidai", "uid_number"},
    "pan": {"pan_number", "pancard", "tax_id"},
    "phone": {"phone", "mobile", "telephone", "phone_number"},
    "email": {"email", "email_address"},
    "financial": {"card_number", "credit_card", "debit_card", "account_number", "upi_id", "bank_account", "ifsc"},
    "health": {"health", "medical", "diagnosis", "patient", "biometric", "fingerprint", "faceprint", "genetic", "disability"},
    "children": {"child", "child_name", "child_data", "children", "minor", "guardian", "parental_consent", "date_of_birth", "dob"},
    "location": {"location", "gps", "latitude", "longitude", "geolocation", "address", "pincode", "postal_code"},
    "contact": {"name", "full_name", "first_name", "last_name", "contact", "user_id", "device_id"},
    "credential": {"password", "passwd", "secret", "token", "api_key", "access_key", "private_key"},
}

SENSITIVITY = {
    "aadhaar": 1.5, "children": 1.5, "financial": 1.3, "health": 1.3,
    "phone": 1.0, "email": 1.0, "contact": 1.0, "location": 1.0,
    "pan": 1.3, "credential": 1.3, "ip": 0.7, "other": 0.7,
}


@dataclass(frozen=True, order=True)
class PiiMatch:
    category: str
    value: str


def _verhoeff_valid(value: str) -> bool:
    multiplication = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ]
    permutation = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ]
    inverse = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]
    checksum = 0
    for index, digit in enumerate(reversed(value)):
        checksum = multiplication[checksum][permutation[index % 8][int(digit)]]
    return inverse[checksum] == 0


def _luhn_valid(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def detect_literals(text: str) -> list[PiiMatch]:
    found: set[PiiMatch] = set()
    for match in AADHAAR_RE.finditer(text):
        if _verhoeff_valid(match.group(1)):
            found.add(PiiMatch("aadhaar", match.group(1)))
    for match in PAN_RE.finditer(text):
        found.add(PiiMatch("pan", match.group(0).upper()))
    for match in EMAIL_RE.finditer(text):
        found.add(PiiMatch("email", match.group(0)))
    for match in UPI_RE.finditer(text):
        candidate = match.group(0)
        if not EMAIL_RE.fullmatch(candidate):
            found.add(PiiMatch("financial", candidate))
    for match in PHONE_RE.finditer(text):
        found.add(PiiMatch("phone", match.group(1)))
    for match in CARD_RE.finditer(text):
        candidate = re.sub(r"\D", "", match.group(0))
        if _luhn_valid(candidate):
            found.add(PiiMatch("financial", candidate))
    for match in IP_RE.finditer(text):
        try:
            found.add(PiiMatch("ip", str(ipaddress.ip_address(match.group(0)))))
        except ValueError:
            pass
    return sorted(found)


def categories_from_names(text: str) -> set[str]:
    normalized = re.sub(r"([a-z])([A-Z])", r"\1_\2", text).lower()
    tokens = set(re.findall(r"[a-z][a-z0-9_]*", normalized))
    categories: set[str] = set()
    for category, words in KEYWORDS.items():
        if tokens & words or any(word in normalized for word in words if "_" in word):
            categories.add(category)
    return categories


def redact_sensitive(text: str) -> str:
    text = UPI_RE.sub("<redacted:upi>", text)
    text = EMAIL_RE.sub("<redacted:email>", text)
    text = PAN_RE.sub("<redacted:pan>", text)
    text = AADHAAR_RE.sub("<redacted:identifier>", text)
    text = PHONE_RE.sub("<redacted:phone>", text)
    text = CARD_RE.sub("<redacted:card>", text)
    text = IP_RE.sub("<redacted:ip>", text)
    return re.sub(r"(?i)(api[_-]?key|secret|token|password)\s*([=:])\s*(['\"])[^'\"]{6,}\3", r"\1\2<redacted:secret>", text)

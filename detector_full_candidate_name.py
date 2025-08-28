#!/usr/bin/env python3


"""
Project Guardian 2.0 — PII Detector & Redactor
Run:
  python3 detector_full_candidate_name.py iscp_pii_dataset.csv

Input:  CSV columns -> record_id, data_json  (or Data_json)
Output: redacted_output_candidate_full_name.csv
"""

import csv, json, re, sys
from typing import Any, Dict, Tuple

# ---------- Regexes ----------
RE_TEN_DIGITS = re.compile(r'(?<!\d)(\d{10})(?!\d)')                  # phone
RE_AADHAR     = re.compile(r'(?<!\d)(\d{12})(?!\d)')                  # aadhar
RE_PASSPORT   = re.compile(r'\b([A-PR-WYa-pr-wy][0-9]{7})\b')         # passport
RE_UPI        = re.compile(r'\b([A-Za-z0-9._-]{2,})@([A-Za-z][A-Za-z0-9._-]{1,})\b')
RE_EMAIL      = re.compile(r'\b([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24})\b')
RE_IPV4       = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')

NUMERIC_ID_KEYS = {
    "order_id","transaction_id","product_id","booking_reference",
    "customer_id","warehouse_code","ticket_id","gst_number","state_code"
}

PHONEY_KEYS     = {"phone","contact"}
B_NAME_KEYS     = {"name"}
B_FIRST, B_LAST = "first_name","last_name"
B_EMAIL_KEYS    = {"email","username"}
B_ADDRESS_KEYS  = {"address"}
B_ADDR_PARTS    = {"city","state","pin_code"}
B_DEVICE_KEYS   = {"device_id"}
B_IP_KEYS       = {"ip_address"}

# ---------- Masking helpers ----------
def mask_phone_digits(s: str) -> str:
    def _m(m): d = m.group(1); return f"{d[:2]}{'X'*6}{d[-2:]}"
    return RE_TEN_DIGITS.sub(_m, s)

def mask_aadhar_digits(s: str) -> str:
    def _m(m): d = m.group(1); return f"XXXX XXXX {d[-4:]}"
    s_norm = re.sub(r'(?<!\d)(\d{4})\s*(\d{4})\s*(\d{4})(?!\d)',
                    lambda m: m.group(1)+m.group(2)+m.group(3), s)
    return RE_AADHAR.sub(_m, s_norm)

def mask_passport_in(s: str) -> str:
    def _m(m): p = m.group(1); return p[0] + "X"*6 + p[-1]
    return RE_PASSPORT.sub(_m, s)

def mask_upi_in(s: str) -> str:
    def _m(m):
        user, prov = m.group(1), m.group(2)
        keep = min(2, len(user))
        return f"{user[:keep]}{'X'*(len(user)-keep)}@{prov}"
    return RE_UPI.sub(_m, s)

def mask_email_str(s: str) -> str:
    def _m(m):
        local, dom = m.group(1), m.group(2)
        keep = min(2, len(local))
        return f"{local[:keep]}{'X'*(len(local)-keep)}@{dom}"
    return RE_EMAIL.sub(_m, s)

def mask_name_full(name: str) -> str:
    parts = re.split(r'(\s+)', str(name))
    out = []
    for t in parts:
        if t.isspace(): out.append(t)
        elif re.fullmatch(r"[A-Za-z][A-Za-z.'-]*", t): out.append(t[0] + "X"*max(0,len(t)-1))
        else: out.append(t)
    return "".join(out)

def mask_ip_in(s: str) -> str:
    def _m(m):
        parts = m.group(1).split(".")
        if len(parts)==4:
            parts[-1] = "X"; return ".".join(parts)
        return m.group(1)
    return RE_IPV4.sub(_m, s)

def hard_redact(_: str) -> str:
    return "[REDACTED_PII]"

# ---------- Utilities ----------
def looks_like_full_name(val: Any) -> bool:
    s = str(val or "").strip()
    tokens = [t for t in re.split(r'\s+', s) if t]
    alpha  = [t for t in tokens if re.fullmatch(r"[A-Za-z][A-Za-z.'-]*", t)]
    return len(alpha) >= 2

def valid_email(val: Any) -> bool:
    return RE_EMAIL.search(str(val) or "") is not None

def safe_json_load(raw: str) -> Dict[str, Any]:
    txt = (raw or "").strip()
    try:
        return json.loads(txt)
    except Exception:
        try:
            txt2 = txt.replace('""','"').strip('"')
            return json.loads(txt2)
        except Exception:
            return {}

# ---------- Count B-signals ----------
def count_b_signals(rec: Dict[str, Any]) -> Tuple[int, Dict[str,bool], int, bool]:
    flags = {"name": False, "email": False, "address": False, "device_or_ip": False}
    # name
    if rec.get("name") and looks_like_full_name(rec["name"]): flags["name"] = True
    elif rec.get(B_FIRST) and rec.get(B_LAST): flags["name"] = True
    # email / username
    for k in B_EMAIL_KEYS:
        if rec.get(k) and valid_email(rec[k]): flags["email"] = True
    # address
    addr_parts = sum(1 for k in B_ADDR_PARTS if rec.get(k))
    has_addr_field = bool(rec.get("address"))
    if has_addr_field or addr_parts >= 2: flags["address"] = True
    # device/ip
    device_present = any(rec.get(k) for k in B_DEVICE_KEYS)
    ip_present = rec.get("ip_address") and RE_IPV4.search(str(rec["ip_address"]))
    if device_present or ip_present: flags["device_or_ip"] = True
    return sum(1 for v in flags.values() if v), flags, addr_parts, has_addr_field

# ---------- A-detection ----------
def detect_a_in_value(key: str, value: Any) -> Dict[str,bool]:
    s = str(value or "")
    found = {"phone": False, "aadhar": False, "passport": False, "upi": False}
    if key not in NUMERIC_ID_KEYS:
        if RE_TEN_DIGITS.search(s): found["phone"] = True
        if RE_AADHAR.search(re.sub(r'\s+','',s)): found["aadhar"] = True
    if RE_PASSPORT.search(s): found["passport"] = True
    if RE_UPI.search(s):      found["upi"] = True
    return found

# ---------- Redaction ----------
def redact_value(key: str, value: Any, do_b: bool, addr_parts: int, has_addr_field: bool) -> Any:
    if value is None: return value
    sval = str(value)
    before = sval

    # A-class always
    sval = mask_phone_digits(sval)
    sval = mask_aadhar_digits(sval)
    sval = mask_passport_in(sval)
    sval = mask_upi_in(sval)

    # B-class only if >=2 B-signals
    if do_b:
        if key in B_NAME_KEYS and looks_like_full_name(before):
            sval = mask_name_full(before)
        if key in {B_FIRST, B_LAST}:
            sval = sval[:1] + "X"*max(0, len(sval)-1)
        if key in B_EMAIL_KEYS:
            sval = mask_email_str(sval)
        if key in B_ADDRESS_KEYS:
            sval = hard_redact(sval)
        elif key in B_ADDR_PARTS:
            if has_addr_field or addr_parts >= 2:
                sval = hard_redact(sval)
        if key in B_DEVICE_KEYS:
            sval = hard_redact(sval)
        if key in B_IP_KEYS:
            sval = mask_ip_in(sval)

    return sval

# ---------- Record processing ----------
def process_record(obj: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    a_hit = any(any(detect_a_in_value(k, v).values()) for k, v in obj.items())
    b_count, flags, addr_parts, has_addr_field = count_b_signals(obj)
    do_b = b_count >= 2
    is_pii = a_hit or do_b

    #  Force email-alone case to NOT be PII
    if flags["email"] and not (flags["name"] or flags["address"] or flags["device_or_ip"]):
        is_pii = False
        do_b = False  # Ensure B-class redaction is also disabled

    red = {k: redact_value(k, v, do_b, addr_parts, has_addr_field) for k, v in obj.items()}
    return red, bool(is_pii)

# ---------- Main ----------
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py iscp_pii_dataset.csv", file=sys.stderr)
        sys.exit(2)

    in_csv = sys.argv[1]
    out_csv = "redacted_output_candidate_full_name.csv"

    with open(in_csv, newline='', encoding="utf-8") as fin, \
         open(out_csv, "w", newline='', encoding="utf-8") as fout:

        reader = csv.DictReader(fin)
        json_col = "data_json" if "data_json" in reader.fieldnames else \
                   "Data_json" if "Data_json" in reader.fieldnames else None
        if not json_col or "record_id" not in reader.fieldnames:
            raise SystemExit("Input must have columns: record_id and data_json (or Data_json)")

        writer = csv.DictWriter(fout, fieldnames=["record_id","redacted_data_json","is_pii"])
        writer.writeheader()

        for row in reader:
            obj = safe_json_load(row.get(json_col, "{}"))
            red, is_pii = process_record(obj)
            writer.writerow({
                "record_id": row.get("record_id"),
                "redacted_data_json": json.dumps(red, ensure_ascii=False),
                "is_pii": str(bool(is_pii))
            })
    print(f"[+] Wrote {out_csv}")

if __name__ == "__main__":
    main()


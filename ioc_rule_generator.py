#!/usr/bin/env python3
"""
ioc_rule_generator.py
=====================
Converts threat intelligence Excel/CSV spreadsheets into:
  - Suricata IDS/IPS rules  (.rules)
  - YARA detection rules    (.yar)

Supports Mandiant threat intelligence format and generic IOC spreadsheets.
Tracks SID allocation across runs to prevent conflicts with Emerging Threats (ET).

IOC types handled:
  IPv4 / IPv4 CIDR, Domain, URL, MD5 / SHA1 / SHA256,
  Email, User-Agent, Registry key, Mutex, Filename

Usage:
  python ioc_rule_generator.py -i mandiant_report.xlsx
  python ioc_rule_generator.py -i iocs.xlsx -o ./output --severity Major
  python ioc_rule_generator.py -i iocs.csv  --update-et-sids
  python ioc_rule_generator.py -i iocs.xlsx --sid-start 9500000

Author:  https://github.com/willerker/ioc-rule-generator
License: MIT
Version: 1.0.0
"""

import re
import sys
import json
import argparse
import urllib.request
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import pandas as pd
except ImportError:
    sys.exit("[!] pandas not found. Install with: pip install pandas openpyxl")

# ══════════════════════════════════════════════════════════════════════════════
# Constants
# ══════════════════════════════════════════════════════════════════════════════

VERSION = "1.0.0"

# Local/custom rule SID range — safe from ET and Snort reserved ranges.
# Emerging Threats uses  2,000,000 – 2,999,999 (and 3,000,000 – 3,999,999).
# Snort community rules  1,000,000 – 1,999,999.
# We default to 9,000,001+ which is universally accepted for local rules.
SID_RANGE_START: int = 9_000_001
SID_RANGE_END:   int = 9_999_999

SID_TRACKER_FILE = "sid_tracker.json"

# SID ranges that must never be allocated (inclusive on both ends).
ET_FORBIDDEN_RANGES: List[Tuple[int, int]] = [
    (1,         99),          # Reserved / Snort built-in
    (100,       999_999),     # Snort-distributed rules
    (1_000_000, 1_999_999),   # Snort community / some older ET categories
    (2_000_000, 2_999_999),   # Emerging Threats Open & Pro
    (3_000_000, 3_999_999),   # ET extended categories
    (4_000_000, 4_999_999),   # ET additional ranges
]

# URL for the Emerging Threats Open rules bundle (used with --update-et-sids)
ET_RULES_URL = (
    "https://rules.emergingthreats.net/open/suricata-5.0/rules/emerging-all.rules"
)

# ══════════════════════════════════════════════════════════════════════════════
# IOC Classification
# ══════════════════════════════════════════════════════════════════════════════

_RE_IPV4 = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::\d+)?$"
)
_RE_IPV4_CIDR = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$"
)
_RE_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_RE_URL    = re.compile(r"^https?://", re.IGNORECASE)
_RE_MD5    = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_SHA1   = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_RE_EMAIL  = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_RE_REG    = re.compile(r"^(HKEY_|HKLM|HKCU|HKU|HKCR|HKCC)\\", re.IGNORECASE)

# Hint strings from a "Type" column that map directly to IOC types
_HINT_MAP: Dict[str, str] = {
    "ip":              "ipv4",
    "ip address":      "ipv4",
    "ipv4":            "ipv4",
    "ipv4-addr":       "ipv4",
    "ipv6":            "ipv6",
    "domain":          "domain",
    "domain-name":     "domain",
    "fqdn":            "domain",
    "hostname":        "domain",
    "host":            "domain",
    "url":             "url",
    "uri":             "url",
    "md5":             "md5",
    "sha1":            "sha1",
    "sha256":          "sha256",
    "sha-1":           "sha1",
    "sha-256":         "sha256",
    "file":            "filename",
    "filename":        "filename",
    "file name":       "filename",
    "email":           "email",
    "email address":   "email",
    "email-message":   "email",
    "user-agent":      "user_agent",
    "useragent":       "user_agent",
    "user_agent":      "user_agent",
    "registry key":    "registry",
    "registry-key":    "registry",
    "registry":        "registry",
    "mutex":           "mutex",
    "mutant":          "mutex",
}


def classify_ioc(value: str, hint: str = "") -> Optional[str]:
    """
    Determine the IOC type for a given string value.

    Args:
        value: The raw IOC string (IP, domain, hash, etc.)
        hint:  Optional type hint from a spreadsheet 'Type' column.

    Returns:
        IOC type string or None if unrecognized.
    """
    value = value.strip()
    if not value:
        return None

    # Hint-based fast path (avoids regex when the spreadsheet tells us the type)
    if hint:
        mapped = _HINT_MAP.get(hint.lower().strip())
        if mapped:
            return mapped
        # If hint says "hash", resolve from value length below
        if hint.lower() in ("hash", "file hash", "filehash"):
            hint = ""

    # URL — check first because URLs often also match domain patterns
    if _RE_URL.match(value):
        return "url"

    # Hash fingerprints — ordered by length (no ambiguity)
    if _RE_MD5.match(value):
        return "md5"
    if _RE_SHA256.match(value):
        return "sha256"
    if _RE_SHA1.match(value):
        return "sha1"

    # Email before domain (emails contain @domain)
    if _RE_EMAIL.match(value):
        return "email"

    # Registry keys
    if _RE_REG.match(value):
        return "registry"

    # IPv4 CIDR
    m_cidr = _RE_IPV4_CIDR.match(value)
    if m_cidr:
        octets = [int(m_cidr.group(i)) for i in range(1, 5)]
        prefix = int(m_cidr.group(5))
        if all(0 <= o <= 255 for o in octets) and 0 <= prefix <= 32:
            return "ipv4_cidr"

    # IPv4 (with optional :port)
    m = _RE_IPV4.match(value)
    if m:
        if all(0 <= int(m.group(i)) <= 255 for i in range(1, 5)):
            return "ipv4"

    # Domain
    if _RE_DOMAIN.match(value) and "." in value:
        return "domain"

    return None


# ══════════════════════════════════════════════════════════════════════════════
# SID Tracker
# ══════════════════════════════════════════════════════════════════════════════

class SIDTracker:
    """
    Persistent SID allocator.

    State is serialised to a JSON file between runs so that SIDs are never
    reused and never overlap with ET or Snort reserved ranges.

    JSON schema
    -----------
    {
      "next_sid":    int,
      "used_sids":   [int, ...],
      "et_sids":     [int, ...],   # parsed from a live ET rules download
      "generated":   [{ioc, ioc_type, sid, rule_type, timestamp}, ...],
      "last_updated": ISO-8601 string
    }
    """

    def __init__(self, tracker_path: Path, sid_start: int = SID_RANGE_START):
        self.path      = tracker_path
        self.sid_start = sid_start
        self._state: Dict = {}
        self._load()

    # ── persistence ──────────────────────────────────────────────────────────

    def _load(self):
        if self.path.exists():
            with open(self.path) as fh:
                self._state = json.load(fh)
            # Ensure new keys exist for forward-compatibility
            self._state.setdefault("et_sids",   [])
            self._state.setdefault("generated", [])
        else:
            self._state = {
                "next_sid":    self.sid_start,
                "used_sids":   [],
                "et_sids":     [],
                "generated":   [],
                "last_updated": "",
            }

    def save(self):
        self._state["last_updated"] = (
            datetime.now(timezone.utc).isoformat()
        )
        with open(self.path, "w") as fh:
            json.dump(self._state, fh, indent=2)

    # ── allocation ────────────────────────────────────────────────────────────

    def _is_forbidden(self, sid: int) -> bool:
        """Return True if the SID falls in any blocked range."""
        for lo, hi in ET_FORBIDDEN_RANGES:
            if lo <= sid <= hi:
                return True
        if sid in self._state.get("et_sids", []):
            return True
        return False

    def next_sid(self) -> int:
        """Allocate and return the next available SID."""
        used: set = set(self._state["used_sids"])
        sid = self._state["next_sid"]

        while sid <= SID_RANGE_END:
            if sid not in used and not self._is_forbidden(sid):
                used.add(sid)
                self._state["used_sids"] = sorted(used)
                self._state["next_sid"]  = sid + 1
                return sid
            sid += 1

        raise RuntimeError(
            f"[!] SID pool exhausted: all SIDs in "
            f"{self.sid_start:,}–{SID_RANGE_END:,} are taken."
        )

    def record(self, ioc: str, ioc_type: str, sid: int, rule_type: str):
        """Append a log entry for an allocated rule."""
        self._state["generated"].append({
            "ioc":       ioc,
            "ioc_type":  ioc_type,
            "sid":       sid,
            "rule_type": rule_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    # ── ET SID loading ────────────────────────────────────────────────────────

    def load_et_sids_from_text(self, rules_text: str):
        """Parse all SIDs from a blob of ET rules text."""
        sids = [int(s) for s in re.findall(r"\bsid:(\d+);", rules_text)]
        self._state["et_sids"] = sorted(set(sids))
        print(f"[+] Loaded {len(sids):,} ET SIDs into blocklist.")

    # ── properties ────────────────────────────────────────────────────────────

    @property
    def used_count(self) -> int:
        return len(self._state["used_sids"])


# ══════════════════════════════════════════════════════════════════════════════
# Suricata Rule Generation
# ══════════════════════════════════════════════════════════════════════════════

def _esc_msg(s: str) -> str:
    """Strip characters that are illegal in Suricata msg fields."""
    return re.sub(r'[";\\]', "", s)[:120]


def _esc_content(s: str) -> str:
    """Escape backslashes and double-quotes for Suricata content keywords."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _suricata_rule(
    action: str,
    proto: str,
    src: str,
    sport: str,
    dst: str,
    dport: str,
    options: str,
    msg: str,
    sid: int,
    severity: str,
    tag: str,
) -> str:
    """Assemble a single Suricata rule string."""
    date = datetime.now(timezone.utc).strftime("%Y_%m_%d")
    metadata = (
        f"affected_product Any, attack_target Any, "
        f"created_at {date}, deployment Perimeter, "
        f"signature_severity {severity}, tag {_esc_msg(tag)}, "
        f"updated_at {date}"
    )
    return (
        f'{action} {proto} {src} {sport} -> {dst} {dport} '
        f'(msg:"{_esc_msg(msg)}"; {options}'
        f'sid:{sid}; rev:1; metadata:{metadata};)'
    )


def make_suricata_rules(
    ioc_value:   str,
    ioc_type:    str,
    tracker:     SIDTracker,
    description: str = "",
    malware:     str = "",
    severity:    str = "Major",
) -> List[str]:
    """
    Generate Suricata rules for one IOC.  Returns a list of rule strings.
    Hash-based IOCs get a commented placeholder (hashes cannot be matched in
    line-rate Suricata without filestore + external tooling).
    """
    rules: List[str] = []
    tag = malware or "ThreatIntel"
    base = f"THREAT-INTEL {ioc_type.upper()} {ioc_value}"
    if description:
        base += f" - {description}"

    def _add(proto, src, sport, dst, dport, opts, msg_suffix=""):
        msg = base + (f" {msg_suffix}" if msg_suffix else "")
        sid = tracker.next_sid()
        rule = _suricata_rule("alert", proto, src, sport, dst, dport,
                              opts, msg, sid, severity, tag)
        tracker.record(ioc_value, ioc_type, sid, "suricata")
        rules.append(rule)

    # ── IPv4 ──────────────────────────────────────────────────────────────────
    if ioc_type in ("ipv4", "ipv4_cidr"):
        vt_ref = f"reference:url,virustotal.com/search?query={ioc_value}; "
        _add("ip", "any",       "any", ioc_value, "any", vt_ref,  "OUTBOUND")
        _add("ip", ioc_value,   "any", "any",     "any", vt_ref,  "INBOUND")

    # ── Domain ────────────────────────────────────────────────────────────────
    elif ioc_type == "domain":
        safe = _esc_content(ioc_value)
        vt_ref = f"reference:url,virustotal.com/search?query={ioc_value}; "
        # DNS query for the domain
        _add("dns", "any", "any", "any", "any",
             f'dns.query; content:"{safe}"; nocase; {vt_ref}',
             "DNS")
        # HTTP Host header
        _add("http", "any", "any", "any", "any",
             f'flow:established,to_server; http.host; content:"{safe}"; nocase; {vt_ref}',
             "HTTP HOST")
        # TLS SNI
        _add("tls", "any", "any", "any", "443",
             f'tls.sni; content:"{safe}"; nocase; {vt_ref}',
             "TLS SNI")

    # ── URL ───────────────────────────────────────────────────────────────────
    elif ioc_type == "url":
        try:
            p    = urlparse(ioc_value)
            host = _esc_content(p.netloc or "")
            path = _esc_content(p.path   or "/")
            opts = (
                f'flow:established,to_server; '
                f'http.host; content:"{host}"; nocase; '
                f'http.uri;  content:"{path}"; nocase; '
            )
        except Exception:
            opts = f'content:"{_esc_content(ioc_value)}"; nocase; '
        _add("http", "any", "any", "any", "any", opts)

    # ── Hashes ────────────────────────────────────────────────────────────────
    elif ioc_type in ("md5", "sha1", "sha256"):
        # Reserve a SID so the tracker records it, but emit a comment.
        sid = tracker.next_sid()
        tracker.record(ioc_value, ioc_type, sid, "suricata-placeholder")
        rules.append(
            f"# [HASH-IOC] {ioc_type.upper()} = {ioc_value}  "
            f"SID {sid} reserved — deploy via YARA + Suricata filestore."
        )
        return rules

    # ── Email ─────────────────────────────────────────────────────────────────
    elif ioc_type == "email":
        safe = _esc_content(ioc_value)
        _add("smtp", "any", "any", "any", "25",
             f'flow:established,to_server; '
             f'content:"MAIL FROM"; content:"{safe}"; nocase; distance:0; ')

    # ── User-Agent ────────────────────────────────────────────────────────────
    elif ioc_type == "user_agent":
        safe = _esc_content(ioc_value)
        _add("http", "any", "any", "any", "any",
             f'flow:established,to_server; '
             f'http.user_agent; content:"{safe}"; nocase; ')

    # ── Registry / Mutex / Filename ───────────────────────────────────────────
    elif ioc_type in ("registry", "mutex", "filename"):
        safe = _esc_content(ioc_value)
        _add("tcp", "any", "any", "any", "any",
             f'content:"{safe}"; nocase; ')

    return rules


# ══════════════════════════════════════════════════════════════════════════════
# YARA Rule Generation
# ══════════════════════════════════════════════════════════════════════════════

_YARA_ID_RE = re.compile(r"[^a-zA-Z0-9_]")


def _yara_identifier(value: str) -> str:
    """Produce a valid YARA rule name from an IOC value."""
    safe = _YARA_ID_RE.sub("_", value)
    if safe and safe[0].isdigit():
        safe = "ioc_" + safe
    return safe[:120] or "ioc"


_YARA_HASH_TMPL = """\
rule ThreatIntel_{ioc_type_upper}_{rule_id}
{{
    meta:
        description = "{description}"
        author      = "IOC Rule Generator v{version}"
        date        = "{date}"
        hash_type   = "{ioc_type}"
        hash_value  = "{hash_value}"
        malware     = "{malware}"
        severity    = "{severity}"
        reference   = "Threat Intelligence"

    condition:
        {hash_func}(0, filesize) == "{hash_value}"
}}
"""

_YARA_STRING_TMPL = """\
rule ThreatIntel_{ioc_type_upper}_{rule_id}
{{
    meta:
        description = "{description}"
        author      = "IOC Rule Generator v{version}"
        date        = "{date}"
        ioc_type    = "{ioc_type}"
        ioc_value   = "{ioc_value_meta}"
        malware     = "{malware}"
        severity    = "{severity}"
        reference   = "Threat Intelligence"

    strings:
        $ioc = "{string_value}" {modifiers}

    condition:
        any of them
}}
"""

_HASH_FUNC = {"md5": "hash.md5", "sha1": "hash.sha1", "sha256": "hash.sha256"}

_STRING_MODIFIERS = {
    "domain":      "ascii wide nocase",
    "url":         "ascii wide nocase",
    "ipv4":        "ascii wide",
    "ipv4_cidr":   "ascii wide",
    "email":       "ascii wide nocase",
    "registry":    "ascii wide nocase",
    "mutex":       "ascii wide nocase",
    "filename":    "ascii wide nocase",
    "user_agent":  "ascii wide nocase",
}


def make_yara_rule(
    ioc_value:   str,
    ioc_type:    str,
    description: str = "",
    malware:     str = "",
    severity:    str = "high",
) -> Optional[str]:
    """
    Generate a YARA rule for one IOC.
    Returns None for IOC types that cannot be expressed in YARA.
    """
    date     = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rule_id  = _yara_identifier(ioc_value)
    desc     = description or f"Threat Intel {ioc_type.upper()} indicator"
    mal      = malware  or "Unknown"
    sev      = severity or "high"
    itype_up = ioc_type.upper().replace("_", "_")

    common = dict(
        version=VERSION, date=date, malware=mal,
        severity=sev, description=desc,
        ioc_type=ioc_type, ioc_type_upper=itype_up, rule_id=rule_id,
    )

    # Hash-based rules (require `import "hash"` at the top of the .yar file)
    if ioc_type in _HASH_FUNC:
        return _YARA_HASH_TMPL.format(
            **common,
            hash_value=ioc_value.lower(),
            hash_func=_HASH_FUNC[ioc_type],
        )

    # String-based rules
    modifiers = _STRING_MODIFIERS.get(ioc_type)
    if modifiers is None:
        return None  # unsupported type

    safe_value = ioc_value.replace("\\", "\\\\").replace('"', '\\"')
    return _YARA_STRING_TMPL.format(
        **common,
        ioc_value_meta=ioc_value.replace('"', '\\"'),
        string_value=safe_value,
        modifiers=modifiers,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Spreadsheet Parser
# ══════════════════════════════════════════════════════════════════════════════

# Ordered candidate column names — first match wins
_INDICATOR_CANDIDATES = [
    "indicator", "indicator value", "indicator_value", "ioc", "ioc value",
    "value", "observable", "artifact", "attribute value",
    "ip", "ip address", "domain", "url", "hash", "md5", "sha1", "sha256",
    "file hash", "network indicator",
]
_TYPE_CANDIDATES = [
    "type", "indicator type", "indicator_type", "ioc type", "category",
    "observable type", "attribute type",
]
_DESC_CANDIDATES = [
    "description", "notes", "note", "comment", "context", "details",
    "information",
]
_MALWARE_CANDIDATES = [
    "malware family", "malware", "threat", "threat actor", "actor",
    "campaign", "family",
]
_SEV_CANDIDATES = [
    "confidence", "confidence level", "severity", "score", "rating",
]


def _find_col(df_cols: List[str], candidates: List[str]) -> Optional[str]:
    """Return the first df column that case-insensitively matches a candidate."""
    lc = {c.lower().strip(): c for c in df_cols}
    for cand in candidates:
        if cand.lower() in lc:
            return lc[cand.lower()]
    return None


def _clean(val) -> str:
    """Convert a pandas cell to a clean string, treating NaN as empty."""
    s = str(val).strip()
    return "" if s.lower() in ("nan", "none", "n/a", "na", "") else s


def parse_spreadsheet(filepath: Path) -> List[Dict]:
    """
    Parse an Excel (.xlsx/.xls/.xlsm) or CSV file.

    Tries every sheet in a workbook and concatenates results.
    Auto-detects the indicator column and optional metadata columns.
    Returns a list of dicts: {value, type, desc, malware, severity}.
    """
    ext = filepath.suffix.lower()

    if ext in (".xlsx", ".xls", ".xlsm"):
        xl     = pd.ExcelFile(filepath)
        frames = []
        for sheet in xl.sheet_names:
            try:
                df = xl.parse(sheet, dtype=str)
                if not df.empty:
                    frames.append(df)
                    print(f"  [+] Sheet '{sheet}': {len(df)} rows")
            except Exception as exc:
                print(f"  [!] Could not parse sheet '{sheet}': {exc}")
        if not frames:
            sys.exit("[!] No readable data found in the Excel file.")
        df = pd.concat(frames, ignore_index=True)

    elif ext == ".csv":
        df = pd.read_csv(filepath, dtype=str)
        print(f"  [+] CSV: {len(df)} rows")

    else:
        sys.exit(f"[!] Unsupported file type: {ext}  (use .xlsx/.xls/.csv)")

    # Normalise column names
    df.columns = [str(c).strip() for c in df.columns]
    cols = list(df.columns)

    ioc_col  = _find_col(cols, _INDICATOR_CANDIDATES)
    type_col = _find_col(cols, _TYPE_CANDIDATES)
    desc_col = _find_col(cols, _DESC_CANDIDATES)
    mal_col  = _find_col(cols, _MALWARE_CANDIDATES)
    sev_col  = _find_col(cols, _SEV_CANDIDATES)

    if not ioc_col:
        ioc_col = cols[0]
        print(f"  [!] Indicator column not found — falling back to '{ioc_col}'")
    else:
        print(f"  [+] Indicator column : '{ioc_col}'")

    if type_col:
        print(f"  [+] Type column      : '{type_col}'")
    if desc_col:
        print(f"  [+] Description col  : '{desc_col}'")
    if mal_col:
        print(f"  [+] Malware column   : '{mal_col}'")

    iocs: List[Dict] = []
    skipped = 0

    for _, row in df.iterrows():
        value = _clean(row.get(ioc_col, ""))
        if not value:
            continue

        hint    = _clean(row.get(type_col, "")) if type_col else ""
        desc    = _clean(row.get(desc_col, "")) if desc_col else ""
        malware = _clean(row.get(mal_col,  "")) if mal_col  else ""
        sev     = _clean(row.get(sev_col,  "")) if sev_col  else ""

        ioc_type = classify_ioc(value, hint)
        if not ioc_type:
            skipped += 1
            continue

        iocs.append({
            "value":    value,
            "type":     ioc_type,
            "desc":     desc,
            "malware":  malware,
            "severity": sev,
        })

    if skipped:
        print(f"  [?] Skipped {skipped} unrecognized rows.")

    return iocs


# ══════════════════════════════════════════════════════════════════════════════
# ET SID Downloader
# ══════════════════════════════════════════════════════════════════════════════

def fetch_et_sids(tracker: SIDTracker, timeout: int = 60):
    """
    Download the Emerging Threats Open rules bundle and load its SIDs.
    This is optional but provides the most accurate SID conflict detection.
    """
    print(f"[*] Downloading ET Open rules (this may take a moment)…")
    print(f"    {ET_RULES_URL}")
    try:
        req = urllib.request.Request(
            ET_RULES_URL,
            headers={"User-Agent": f"ioc-rule-generator/{VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
        tracker.load_et_sids_from_text(text)
        tracker.save()
        print("[+] ET SID blocklist updated and saved.")
    except Exception as exc:
        print(f"[!] ET download failed: {exc}")
        print("    Static range rules will still block ET SID space.")


# ══════════════════════════════════════════════════════════════════════════════
# File Headers
# ══════════════════════════════════════════════════════════════════════════════

def _suricata_header(source: str, sid_start: int) -> str:
    return (
        "# " + "=" * 68 + "\n"
        f"# Suricata Rules — generated by IOC Rule Generator v{VERSION}\n"
        f"# Source    : {source}\n"
        f"# Generated : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
        f"# SID range : {sid_start:,} – {SID_RANGE_END:,}\n"
        "#\n"
        "# ET forbidden ranges are excluded from SID allocation:\n"
        + "".join(
            f"#   {lo:,} – {hi:,}\n" for lo, hi in ET_FORBIDDEN_RANGES
        )
        + "# " + "=" * 68 + "\n\n"
    )


def _yara_header(source: str) -> str:
    return (
        "/*\n"
        f" * YARA Rules — generated by IOC Rule Generator v{VERSION}\n"
        f" * Source    : {source}\n"
        f" * Generated : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
        " *\n"
        " * Required YARA modules: hash\n"
        " * Compile with: yara -C ioc_yara.yar\n"
        " */\n\n"
        'import "hash"\n\n'
    )


# ══════════════════════════════════════════════════════════════════════════════
# CLI Entry-Point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="ioc_rule_generator.py",
        description=(
            "Convert threat-intel spreadsheets (Mandiant / generic) "
            "into Suricata rules and YARA rules."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s -i mandiant_report.xlsx
  %(prog)s -i iocs.xlsx -o ./output --severity Major
  %(prog)s -i iocs.csv  --update-et-sids
  %(prog)s -i iocs.xlsx --sid-start 9500000 --no-yara
  %(prog)s -i iocs.xlsx --suricata-out custom.rules --yara-out custom.yar
        """,
    )

    io_group = parser.add_argument_group("input / output")
    io_group.add_argument(
        "-i", "--input", required=True, metavar="FILE",
        help="Excel (.xlsx/.xls/.xlsm) or CSV file containing IOCs",
    )
    io_group.add_argument(
        "-o", "--output", default=".", metavar="DIR",
        help="Output directory (default: current directory)",
    )
    io_group.add_argument(
        "--suricata-out", default="ioc_suricata.rules", metavar="FILENAME",
        help="Suricata rules file name (default: ioc_suricata.rules)",
    )
    io_group.add_argument(
        "--yara-out", default="ioc_yara.yar", metavar="FILENAME",
        help="YARA rules file name (default: ioc_yara.yar)",
    )

    sid_group = parser.add_argument_group("SID management")
    sid_group.add_argument(
        "--sid-tracker", default=SID_TRACKER_FILE, metavar="FILE",
        help=f"SID tracker JSON file (default: {SID_TRACKER_FILE})",
    )
    sid_group.add_argument(
        "--sid-start", type=int, default=SID_RANGE_START, metavar="INT",
        help=f"Starting SID (default: {SID_RANGE_START:,}). "
             f"Must be >= {SID_RANGE_START:,} to avoid ET ranges.",
    )
    sid_group.add_argument(
        "--update-et-sids", action="store_true",
        help="Download ET Open rules and refresh the SID blocklist before processing",
    )

    rule_group = parser.add_argument_group("rule options")
    rule_group.add_argument(
        "--severity", default="Major",
        choices=["Informational", "Minor", "Major", "Critical"],
        help="Default Suricata metadata severity when not in spreadsheet (default: Major)",
    )
    rule_group.add_argument(
        "--no-suricata", action="store_true",
        help="Skip Suricata rule generation",
    )
    rule_group.add_argument(
        "--no-yara", action="store_true",
        help="Skip YARA rule generation",
    )

    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    args = parser.parse_args()

    # ── Validate arguments ────────────────────────────────────────────────────
    input_path   = Path(args.input)
    output_dir   = Path(args.output)
    tracker_file = Path(args.sid_tracker)

    if not input_path.exists():
        sys.exit(f"[!] Input file not found: {input_path}")

    for lo, hi in ET_FORBIDDEN_RANGES:
        if lo <= args.sid_start <= hi:
            sys.exit(
                f"[!] --sid-start {args.sid_start:,} falls inside a forbidden "
                f"range ({lo:,}–{hi:,}). Use {SID_RANGE_START:,} or higher."
            )

    output_dir.mkdir(parents=True, exist_ok=True)

    suricata_path = output_dir / args.suricata_out
    yara_path     = output_dir / args.yara_out

    # ── Banner ────────────────────────────────────────────────────────────────
    print(f"\n{'=' * 62}")
    print(f"  IOC Rule Generator  v{VERSION}")
    print(f"{'=' * 62}")
    print(f"  Input      : {input_path}")
    print(f"  Output dir : {output_dir}")
    print(f"  SID file   : {tracker_file}")
    print(f"  SID start  : {args.sid_start:,}")
    print(f"{'=' * 62}\n")

    # ── SID tracker ───────────────────────────────────────────────────────────
    tracker = SIDTracker(tracker_file, sid_start=args.sid_start)

    if args.update_et_sids:
        fetch_et_sids(tracker)

    # ── Parse spreadsheet ─────────────────────────────────────────────────────
    print(f"[*] Parsing: {input_path.name}")
    iocs = parse_spreadsheet(input_path)
    print(f"[+] Valid IOCs found: {len(iocs)}\n")

    if not iocs:
        sys.exit("[!] No valid IOCs found. Check your spreadsheet format.")

    # ── Generate rules ────────────────────────────────────────────────────────
    suricata_rules: List[str] = []
    yara_rules:     List[str] = []
    counters:       Dict[str, int] = {}

    for ioc in iocs:
        val     = ioc["value"]
        itype   = ioc["type"]
        desc    = ioc["desc"]
        malware = ioc["malware"]
        sev     = ioc["severity"] or args.severity

        counters[itype] = counters.get(itype, 0) + 1

        if not args.no_suricata:
            rules = make_suricata_rules(val, itype, tracker, desc, malware, sev)
            suricata_rules.extend(rules)
            suricata_rules.append("")  # blank line between rule groups

        if not args.no_yara:
            rule = make_yara_rule(val, itype, desc, malware, sev)
            if rule:
                yara_rules.append(rule)

    # ── Write output files ────────────────────────────────────────────────────
    source = input_path.name

    if not args.no_suricata:
        with open(suricata_path, "w") as fh:
            fh.write(_suricata_header(source, args.sid_start))
            fh.write("\n".join(suricata_rules))
        n_rules = sum(1 for r in suricata_rules if r.startswith("alert"))
        print(f"[+] Suricata rules  → {suricata_path}  ({n_rules} rules)")

    if not args.no_yara:
        with open(yara_path, "w") as fh:
            fh.write(_yara_header(source))
            fh.write("\n".join(yara_rules))
        print(f"[+] YARA rules      → {yara_path}  ({len(yara_rules)} rules)")

    tracker.save()
    print(f"[+] SID tracker     → {tracker_file}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'=' * 62}")
    print(f"  Summary")
    print(f"{'=' * 62}")
    print(f"  IOCs processed    : {len(iocs)}")
    if not args.no_suricata:
        print(f"  Suricata rules    : {sum(1 for r in suricata_rules if r.startswith('alert'))}")
    if not args.no_yara:
        print(f"  YARA rules        : {len(yara_rules)}")
    print(f"  SIDs allocated    : {tracker.used_count}")
    print(f"\n  IOC type breakdown:")
    for itype, count in sorted(counters.items()):
        print(f"    {itype:<20} {count}")
    print(f"{'=' * 62}\n")


if __name__ == "__main__":
    main()

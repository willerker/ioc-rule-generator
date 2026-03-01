# IOC Rule Generator

Converts threat intelligence Excel / CSV spreadsheets (Mandiant and generic formats) into **Suricata IDS/IPS rules** and **YARA detection rules**.

Key features:
- Auto-detects IOC types (IPv4, CIDR, domain, URL, MD5/SHA1/SHA256, email, user-agent, registry key, mutex, filename)
- Persistent SID tracker — SIDs never repeat across runs
- Validates against Emerging Threats SID ranges to prevent conflicts
- Optional: download the live ET Open rule set and extract exact SIDs
- Outputs two separate files: `.rules` (Suricata) and `.yar` (YARA)

---

## Requirements

- Python 3.8 or later
- pip packages: `pandas`, `openpyxl`, `xlrd`

```bash
pip install -r requirements.txt
```

---

## Quick start

```bash
# Basic usage — processes iocs.xlsx, writes to current directory
python ioc_rule_generator.py -i iocs.xlsx

# Specify output directory
python ioc_rule_generator.py -i mandiant_report.xlsx -o ./output

# Pull live ET SIDs before processing (most accurate conflict detection)
python ioc_rule_generator.py -i iocs.xlsx --update-et-sids

# Use a custom SID starting point
python ioc_rule_generator.py -i iocs.xlsx --sid-start 9500000

# Only generate Suricata rules
python ioc_rule_generator.py -i iocs.xlsx --no-yara

# Override default severity and output file names
python ioc_rule_generator.py -i iocs.xlsx \
    --severity Critical \
    --suricata-out my_env.rules \
    --yara-out    my_env.yar
```

---

## Output files

| File | Description |
|---|---|
| `ioc_suricata.rules` | Suricata alert rules, one group per IOC |
| `ioc_yara.yar` | YARA rules; hash rules require `import "hash"` (included automatically) |
| `sid_tracker.json` | Persistent SID state — **commit this alongside your rules** |

---

## SID ranges

| Range | Owner |
|---|---|
| 1 – 99 | Snort reserved |
| 100 – 999,999 | Snort distributed rules |
| 1,000,000 – 1,999,999 | Snort community / older ET categories |
| 2,000,000 – 2,999,999 | Emerging Threats Open & Pro |
| 3,000,000 – 3,999,999 | ET extended categories |
| 4,000,000 – 4,999,999 | ET additional ranges |
| **9,000,001 – 9,999,999** | **This tool (default)** |

All forbidden ranges are blocked even when `--update-et-sids` is not used.
Use `--update-et-sids` to additionally block every individual SID present in the live ET Open rule set.

---

## Spreadsheet format

The script auto-detects column names. It looks for (case-insensitive):

| Purpose | Accepted column names |
|---|---|
| **IOC value** | `indicator`, `indicator value`, `ioc`, `value`, `observable`, `ip`, `domain`, `url`, `hash`, `md5`, `sha1`, `sha256` … |
| **IOC type** (optional) | `type`, `indicator type`, `ioc type`, `category`, `attribute type` … |
| **Description** (optional) | `description`, `notes`, `comment`, `context` … |
| **Malware family** (optional) | `malware family`, `malware`, `threat`, `actor`, `campaign` … |
| **Severity** (optional) | `confidence`, `severity`, `score`, `rating` … |

Multi-sheet workbooks are fully supported — all sheets are parsed and combined.

### Minimum valid CSV

```csv
indicator,type,description
8.8.8.8,ip,Google DNS (example only)
evil.example.com,domain,C2 domain
https://evil.example.com/beacon,url,Malware callback
d41d8cd98f00b204e9800998ecf8427e,md5,Empty file hash (example)
```

### Mandiant Intelligence export

The script recognises standard Mandiant column names (`Indicator`, `Indicator Type`, `Malware Family`, etc.) automatically.

---

## IOC types and rules generated

| IOC type | Suricata rules | YARA rule |
|---|---|---|
| IPv4 / CIDR | 2 (outbound + inbound) | string match |
| Domain | 3 (DNS, HTTP Host, TLS SNI) | string match |
| URL | 1 (HTTP host + URI) | string match |
| MD5 | comment + SID reserved | `hash.md5()` condition |
| SHA1 | comment + SID reserved | `hash.sha1()` condition |
| SHA256 | comment + SID reserved | `hash.sha256()` condition |
| Email | 1 (SMTP MAIL FROM) | string match |
| User-Agent | 1 (HTTP user-agent) | string match |
| Registry key | 1 (TCP content) | string match |
| Mutex / Filename | 1 (TCP content) | string match |

> **Hash note:** File hashes cannot be matched at line rate in Suricata without enabling the filestore engine and post-processing scripts. The YARA rule handles on-disk / in-memory detection; the Suricata entry is a comment with a reserved SID.

---

## GitHub / GitLab deployment

```bash
git init
git add ioc_rule_generator.py requirements.txt README.md .gitignore
git add sid_tracker.json   # commit the SID state so CI/CD picks it up
git commit -m "Initial commit: IOC rule generator"

# GitHub
git remote add origin https://github.com/YOUR_USERNAME/ioc-rule-generator.git
git push -u origin main

# GitLab
git remote add origin https://gitlab.com/YOUR_USERNAME/ioc-rule-generator.git
git push -u origin main
```

### Suggested CI usage (GitHub Actions example)

```yaml
# .github/workflows/generate-rules.yml
name: Generate detection rules
on:
  push:
    paths: ['*.xlsx', '*.csv']

jobs:
  generate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install -r requirements.txt
      - run: python ioc_rule_generator.py -i iocs.xlsx -o ./rules
      - uses: actions/upload-artifact@v4
        with:
          name: detection-rules
          path: rules/
```

---

## License

MIT — see [LICENSE](LICENSE) for details.

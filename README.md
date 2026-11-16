# Passive website OSINT comparison

This command-line script queries five provider APIs for a DNS hostname and writes
a comparison workbook (`.xlsx`) containing a summary and raw responses:

- VirusTotal
- WHOISXML
- Shodan
- Censys
- AbuseIPDB

Use it only for a website you own or are authorized to assess. This script makes
passive provider API requests only; it does not scan ports or probe the website.
VirusTotal warns that queried indicators may be added to its dataset, so do not
query sensitive or confidential domains.

## Setup

Use Python 3.10 or later:

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and replace the example values with your API credentials:

```dotenv
VT_API_KEY=your_virustotal_api_key
WHOISXML_API_KEY=your_whoisxml_api_key
SHODAN_API_KEY=your_shodan_api_key
CENSYS_API_ID=your_censys_api_id
CENSYS_API_SECRET=your_censys_api_secret
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

The script loads `.env` automatically. Keep real credentials in `.env`; `.gitignore`
excludes it from Git. Do not commit credentials or share completed `.env` files.

Run with a DNS hostname or website URL:

```sh
python analyze_website.py example.com --output example-report.xlsx
```

The workbook's **Comparison** sheet has one row per service. **Raw responses**
contains provider output for review. The script resolves the hostname to public
IP addresses for Shodan and AbuseIPDB and limits those lookups to five addresses.
Unavailable API keys and provider/API errors are shown in the workbook and on
the command line; the process exits nonzero if any provider did not succeed.

## Credentials

| Environment variable | Service |
| --- | --- |
| `VT_API_KEY` | VirusTotal |
| `WHOISXML_API_KEY` | WHOISXML WHOIS API |
| `SHODAN_API_KEY` | Shodan |
| `CENSYS_API_ID`, `CENSYS_API_SECRET` | Censys |
| `ABUSEIPDB_API_KEY` | AbuseIPDB |

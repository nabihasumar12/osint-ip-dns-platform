# Passive Website OSINT Comparison

A command-line Python tool that performs passive, API-based OSINT
lookups for an authorized DNS hostname and exports the results to an
Excel workbook.

The script queries five services:

-   **VirusTotal** --- domain reputation, analysis statistics,
    categories, and last analysis date.
-   **WHOISXML** --- domain registration details, registrar, dates,
    status, name servers, availability, and estimated age.
-   **ipinfo.io** --- organization/ASN-related information and
    geographic details for each resolved public IP address.
-   **crt.sh** --- certificate-transparency results, including
    discovered certificate names and issuers.
-   **AbuseIPDB** --- abuse confidence score, report count, and most
    recent report date for each resolved public IP address.

> **Authorization and privacy:** Use this tool only for a website you
> own or are authorized to assess. It makes provider API requests only;
> it does not scan ports or probe the website. VirusTotal notes that
> queried indicators may be added to its dataset, so do not submit
> sensitive or confidential domains.

## Features

-   Accepts a DNS hostname or a website URL as the target.
-   Normalizes the hostname (including IDN-to-ASCII conversion) and
    validates DNS hostname syntax.
-   Rejects bare IP addresses as targets.
-   Resolves the hostname and keeps only unique, globally routable
    public IP addresses.
-   Limits IP-based lookups to a maximum of **five** resolved public IP
    addresses.
-   Uses the provider APIs for domain and IP intelligence; `ipinfo.io`
    and `crt.sh` do not require API keys in this script.
-   Exports a comparison summary, raw provider responses, and report
    metadata to an `.xlsx` workbook.
-   Reports missing credentials and provider/API failures instead of
    silently treating them as successful results.

## Requirements

-   Python 3.10 or later
-   Dependencies listed in `requirements.txt`:
    -   `python-dotenv`
    -   `openpyxl`

## Setup

Create and activate a virtual environment, install dependencies, and
create your local environment file:

``` sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

On Windows PowerShell, activate the environment with:

``` powershell
.venv\Scripts\Activate.ps1
```

Edit `.env` and provide the credentials required by the authenticated
providers:

``` dotenv
VT_API_KEY=your_virustotal_api_key
WHOISXML_API_KEY=your_whoisxml_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

The script loads `.env` automatically. Keep real credentials in `.env`;
ensure `.env` is excluded from Git. Do not commit credentials or share
completed `.env` files.

### Credentials

  Environment variable   Service              Required
  ---------------------- -------------------- ----------
  `VT_API_KEY`           VirusTotal           Yes
  `WHOISXML_API_KEY`     WHOISXML WHOIS API   Yes
  `ABUSEIPDB_API_KEY`    AbuseIPDB            Yes
  ---                    ipinfo.io            No
  ---                    crt.sh               No

Shodan and Censys credentials are not used by the current script.

## Usage

Run the script with a DNS hostname or website URL:

``` sh
python analyze_website.py example.com
```

Specify a custom output path:

``` sh
python analyze_website.py https://example.com --output example-report.xlsx
```

The default output filename is `osint_comparison.xlsx`. The `-o` and
`--output` options are equivalent:

``` sh
python analyze_website.py example.com -o reports/example-report.xlsx
```

The target must contain a valid DNS hostname. A bare IP address is not
accepted. If the hostname does not resolve to any public IP addresses,
the IP-based services report that no public IPs were available.

## Excel workbook

The generated workbook contains three sheets:

  -----------------------------------------------------------------------
  Sheet                               Contents
  ----------------------------------- -----------------------------------
  **Comparison**                      One row per service, with the
                                      target, resolved public IPs,
                                      status, key findings, and any error
                                      message.

  **Raw responses**                   Provider response JSON for each
                                      successful domain or IP lookup.

  **Info**                            UTC generation timestamp, target,
                                      resolved public IPs, scope, and
                                      VirusTotal data-handling notice.
  -----------------------------------------------------------------------

Long response values written to cells are truncated at the script's
configured cell-length limit. The workbook applies header formatting,
filters, frozen header rows, wrapped text, and bounded column widths.

## Lookup behavior and status values

-   The hostname is resolved using the system DNS resolver.
-   Only globally routable IP addresses are retained, with duplicates
    removed.
-   At most five public IP addresses are queried by the IP-based
    services.
-   **VirusTotal** and **WHOISXML** are queried once for the hostname.
-   **ipinfo.io** and **AbuseIPDB** are queried for each retained public
    IP.
-   **crt.sh** is queried for certificate-transparency records
    associated with the domain.
-   The script uses a 20-second default HTTP timeout, a 100-second
    WHOISXML timeout, and a 90-second crt.sh timeout.
-   AbuseIPDB checks use a `maxAgeInDays` value of 90.

The workbook and console output may show these statuses:

  -----------------------------------------------------------------------
  Status                              Meaning
  ----------------------------------- -----------------------------------
  `success`                           The provider lookup completed
                                      successfully.

  `partial`                           At least one IP lookup succeeded
                                      and at least one failed.

  `error`                             The provider request failed, or all
                                      attempted IP lookups failed.

  `missing key`                       A required API credential is not
                                      configured.

  `no public IPs`                     No globally routable public IP
                                      addresses were resolved for an
                                      IP-based lookup.
  -----------------------------------------------------------------------

A provider error does not prevent the script from attempting the other
services. Missing keys and provider/API errors are recorded in the
workbook and printed to the command line.

## Exit codes

  -----------------------------------------------------------------------
  Exit code                           Meaning
  ----------------------------------- -----------------------------------
  `0`                                 All provider results have status
                                      `success`.

  `1`                                 The workbook was written, but one
                                      or more provider results were not
                                      fully successful.

  `2`                                 Invalid target input or a local
                                      input/output error prevented normal
                                      completion.
  -----------------------------------------------------------------------

For example, missing API keys generally result in an exit code of `1`
after the workbook is generated, so the workbook can still be reviewed.

## Troubleshooting

-   **`Set ...` / `missing key`:** Add the named credential(s) to
    `.env`, then run the script again.
-   **`no public IPs`:** Check that the hostname resolves through your
    system's DNS and has globally routable address records.
-   **`HTTP ...` or `Connection failed`:** Check network access, API
    credentials, provider availability, and account/API limits.
-   **Invalid hostname:** Pass a DNS hostname or URL, not a bare IP
    address.
-   **Workbook not created:** Check that the output directory exists and
    that you have permission to write to it.

## Security notes

-   Keep `.env` out of version control.
-   Never paste API keys into source code or commit them.
-   Do not use the tool against domains without authorization.
-   Do not query sensitive or confidential domains with VirusTotal,
    because queried indicators may be added to its dataset.
-   The tool performs passive provider lookups only; it does not perform
    port scanning or active website probing.

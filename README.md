# SecureOps macOS Security Audit

A read-only macOS security configuration auditor intended for defensive security assessments, learning, and small-business security baselining.

## What v0.1 checks

- FileVault disk encryption
- macOS application firewall
- Firewall stealth mode
- Gatekeeper assessment status
- System Integrity Protection (SIP)
- Automatic software/security update preferences
- Automatic screen-lock settings
- MDM/device-management enrollment status
- Local administrator membership (informational)

The tool does **not** change any settings.

## Requirements

- macOS
- Python 3.9+
- No third-party Python packages

## Run without installing

```bash
cd macos-security-audit
python3 -m secureops_audit
```

Reports are written to `./reports/` as JSON and Markdown.

To print the summary without writing files:

```bash
python3 -m secureops_audit --no-report
```

## Install locally in a virtual environment

```bash
cd macos-security-audit
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
secureops-audit
```

## Run tests

```bash
python3 -m unittest discover -s tests -v
```

## Scoring model in v0.1

| Control | Weight |
|---|---:|
| FileVault | 20 |
| Firewall | 10 |
| Stealth mode | 5 |
| Gatekeeper | 10 |
| SIP | 20 |
| Automatic updates | 15 |
| Screen lock | 10 |
| MDM enrollment | 10 |
| Local admin review | Informational |

Total possible score: 100. Checks that cannot be evaluated are excluded from the security-score denominator and instead reduce the separate **audit coverage** percentage.

This scoring model is an initial business-security baseline, **not a compliance certification**. It will be refined as the project adds explicit mappings to recognized guidance.

## Privacy design

v0.1 intentionally does not collect:

- serial numbers
- Apple IDs
- browser history
- documents or file contents
- passwords or tokens
- Wi-Fi passwords
- recovery keys

Reports can still contain the computer hostname, current username, and local administrator account names. Review a report before sharing it publicly.

## Important limitations

This is a point-in-time configuration review. A passing result does not mean a Mac is compromise-free, compliant, or immune to attack. Managed configuration profiles can also affect settings in ways that require deeper MDM/profile correlation.

Only run security assessment software on systems you own or are authorized to assess.

## Roadmap

### v0.2
- Configuration file for policy thresholds
- Better managed-profile detection
- Update recency / pending update checks
- Sharing and remote-access checks
- Automatic NIST CSF 2.0 mapping

### v0.3
- HTML executive report
- Organization branding
- Fleet report aggregation
- Signed/notarized standalone macOS build

### v1.0
- Stable control catalog
- Unit/integration test coverage
- Versioned baseline policies
- Business assessment mode

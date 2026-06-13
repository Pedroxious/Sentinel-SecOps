# Sentinel-SecOps

An Automated Threat Intelligence and Vulnerability Management Platform.

This repository tracks the latest Common Vulnerabilities and Exposures (CVEs) from the National Vulnerability Database (NVD) and cross-references them with industry-leading intelligence feeds including FIRST EPSS, CISA KEV, ThreatFox, and GitHub Security Advisories. 

The analysis is enhanced by AI models (Google Gemini 2.0) to provide structured impact analysis and mitigation recommendations.

## Project Architecture

- **Threat Intel Feeds**: Direct API ingestion from NVD, CISA, FIRST, and abuse.ch.
- **AI Processing**: Google Gemini transforms raw CVE descriptions into actionable insights.
- **Reporting Engine**: Automated pipeline built in Python. Reports are dynamically generated as professional PDF documents (`fpdf2`) and backed up to a minimalistic HTML dashboard interface.
- **Data Persistence**: A comprehensive CSV database (`dashboards/historico.csv`) tracks all processed vulnerabilities.
- **Automation**: Fully managed via GitHub Actions.

## Current Network Status

<!-- STATUS_START -->
**Last Update:** 2026-06-13 08:09 (BRT)

**Network Status:** SECURE - No Critical Alerts

**Critical CVEs Today:** 0

**[Download Latest PDF Report](pdf_reports/Report_2026-06-13_08-09.pdf)**

**[View Minimal HTML Dashboard](index.html)**

<!-- STATUS_END -->

## Installation and Execution

1. Clone the repository:
```bash
git clone https://github.com/Pedroxious/Sentinel-SecOps.git
cd Sentinel-SecOps
```

2. Install dependencies:
```bash
pip install -r requirements.txt
# Alternatively, install the main packages directly:
pip install requests google-generativeai fpdf2
```

3. Configure Environment Variables:
```bash
export GEMINI_API_KEY="your-gemini-key"
export NVD_API_KEY="your-nvd-key"
```

4. Execute the pipeline:
```bash
python scraper.py
```

## Generated Artifacts

- **PDF Reports**: Stored in `pdf_reports/`, these documents provide formal and detailed breakdowns of the most critical daily vulnerabilities.
- **CSV Database**: Found at `dashboards/historico.csv`, useful for integrating with SIEMs or BI tools.
- **HTML Dashboard**: A minimal web representation stored at `index.html`.

---
*Developed and maintained by Pedroxious.*

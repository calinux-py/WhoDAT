# WhoDAT - InfoSec Analyzer for Nerds

WhoDAT is a cybersecurity tool for nerds. It provides an analysis of emails, URLs, headers, IP addresses, and file attachments to detect potential threats. WhoDAT uses integrations with services like VirusTotal, Google Safe Browsing, OpenAI, and Hybrid Analysis. 

## Features

### 🌐 Domain Analyzer
Analyze URLs, email addresses, and IP addresses to reveal their threat level:
- **Email Analysis**: Verifies if email domains are free, disposable, or associated with suspicious activity.
- **URL Analysis**: Scans URLs to detect malware, phishing attempts, and suspicious redirects.
- **IP Address Analysis**: Checks if an IP address has been associated with previous malicious activity.
- **WHOIS Data**: Retrieves WHOIS information for domains to confirm registration dates, geographical origins, and other key details.

### 📨 Header Analyzer
Uncover security issues hidden in email headers:
- **IP Address Analysis**: Extracts originating IPs and determines their geographic and ISP origins. IP addresses from outside the US are flagged (I'm American - edit the code to change noob).
- **SPF, DKIM, and DMARC**: Validates authentication records to detect spoofing attempts.
- **Intermediary Hop Analysis**: Identifies intermediate servers through header inspection.

### 🔍 Sentiment Analyzer
Detect phishing and other sus language in email content:
- **Content Analysis**: Scans for urgency cues, suspicious language, and embedded links.
- **OpenAI Integration**: Uses AI to provide a classification score and risk assessment based on content indicators.

### 📎 Attachment Analyzer
Ensure attachments are safe before opening:
- **File Scanning**: Uploads files to VirusTotal and Hybrid Analysis to see if malicious or sus.
- **Real-Time Reports**: Displays detailed findings from VirusTotal and Hybrid Analysis, including detection by antivirus engines and potential threat levels.

## Getting Started

### Prerequisites
Ensure you have Python 3.6+ installed. Install dependencies via:

```powershell
pip install -r requirements.txt
```

### API Keys
WhoDAT requires API keys from several services. Add your keys in config/config.ini under the relevant sections:

- VirusTotal
- Google Safe Browsing
- URLScan
- OpenAI
- Hybrid Analysis

### Usage
Run the Application: Start WhoDAT from the command line with:
```powershell
python whodat.py
```

Select Analysis Type: Choose a tab for the type of analysis you want to perform:
1) Domain Analyzer: Enter email or URL for analysis.
2) Header Analyzer: Paste email headers for validation.
3) Sentiment Analyzer: Paste email content to assess phishing risk.
4) Attachment Analyzer: Upload files for malware analysis.
Interpret Results: Results are presented with color-coded risk indicators, making it easy to assess threat levels at a glance.

## File Overview

### File	Description
- config.py	Manages API keys and retrieves credentials from a configuration file.
- gui.py	Implements the PyQt5-based GUI, providing a structured interface for each analysis type.
- utils.py	Utility functions for URL defanging, email obfuscation, and data formatting.
- whodat.py	Main application entry point, initializing the GUI.
- analysis.py	Core analysis logic, with background threads handling various tasks such as WHOIS checks, header parsing.
- api.py	Manages API requests to external services (VirusTotal, URLScan, Safe Browsing, OpenAI) and processes responses.
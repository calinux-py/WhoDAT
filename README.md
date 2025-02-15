![Banner Image](https://github.com/calinux-py/WhoDAT/blob/main/config/WhoDatBanner.png?raw=true)
# [<img src="https://github.com/calinux-py/WhoDAT/blob/main/whodat.png?raw=true" alt="WhoDAT Logo" width="3%">](https://github.com/calinux-py/WhoDAT/tree/main) WhoDAT - InfoSec Analyzer for Nerds

WhoDAT is a GUI-based cybersecurity tool for nerds. 

Analyze emails, URLs, headers, IPs, and attachments for threats--using free APIs like VirusTotal, Google Safe Browsing, URLScan, and Hybrid Analysis.

![Windows](https://img.shields.io/badge/platform-Windows-blue) ![Python](https://img.shields.io/badge/language-Python-darkgreen) ![OpenAI](https://img.shields.io/badge/OpenAI-412991?logo=openai&logoColor=white) ![VirusTotal](https://img.shields.io/badge/VirusTotal-0078D4?logo=virustotal&logoColor=white) ![Hybrid Analysis](https://img.shields.io/badge/Hybrid%20Analysis-004080?logo=hybridanalysis&logoColor=white) ![Google Safe Browsing](https://img.shields.io/badge/Google%20Safe%20Browsing-34A853?logo=google&logoColor=white) ![URLScan](https://img.shields.io/badge/URLScan-FFA500)

[<img src="https://github.com/calinux-py/WhoDAT/blob/main/config/pocimg.png?raw=true" alt="WhoDAT" width="75%">](https://github.com/calinux-py/WhoDAT/blob/main/config/pocimg.png?raw=true)

[Download the portable executable version here!](https://github.com/calinux-py/WhoDAT/releases/download/whodatv1.4/whodat.exe)

## Features

### 🌐 Domain Analyzer
Analyze URLs, email addresses, and IP addresses to reveal their threat level:
- **Website Analysis**: Search if a website is a known malicious site and take a secure screenshot using URLScan.io.
- **Email Analysis**: Verifies if email domains are free, disposable, or associated with suspicious activity.
- **URL Analysis**: Scans URLs to detect malware, phishing attempts, and suspicious redirects.
- **IP Address Analysis**: Checks if an IP address has been associated with previous malicious activity.
- **WHOIS Data**: Retrieves WHOIS information for domains to confirm registration dates, geographical origins, and other key details.
- **DMARC Analysis**: Check if an email has been potentially spoofed.

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
- **QR Code Scanning**: Scan QR codes and automatically process the embedded link for malicious activity.

---

## Getting Started

### Prerequisites
Ensure you have Python 3.6+ installed. Install dependencies via:

```powershell
pip install -r requirements.txt
```

### API Keys

*API Keys are NOT required but will limit the usefulness considerably. They are free. Don't be lazy. You can skip the OpenAI API if you don't want AI analysis.*

WhoDAT uses API keys from several services. All are FREE (except openai but its like a penny). Add your keys in config/config.ini under the relevant sections:

- [VirusTotal](https://docs.virustotal.com/reference/overview)
- [Google Safe Browsing](https://console.cloud.google.com/apis/api/safebrowsing.googleapis.com)
- [URLScan](https://urlscan.io/docs/api/)
- [OpenAI](https://platform.openai.com/docs/overview)
- [Hybrid Analysis](https://hybrid-analysis.com/docs/api/v2)

`NOTE: config/config.ini MUST be in the same directory as whodat.py/whodat.exe.`
```
WhoDAT(Python)/
├── whodat.py
├── utils.py
├── gui.py
├── analysis.py
├── api.py
├── config.py
└── config/
    └── config.ini

WhoDAT(Portable Executable)/
├── whodat.exe
└── config/
    └── config.ini
```

---

### Usage
[Download the Python script](https://github.com/calinux-py/WhoDAT/archive/refs/heads/main.zip) or [download the portable executable version](https://github.com/calinux-py/WhoDAT/releases/download/whodatv1.4/whodat.exe).

Start the .exe or run whodat.py using Python.
```
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

[<img src="https://github.com/calinux-py/WhoDAT/blob/main/config/poc.gif?raw=true" alt="WhoDAT" width="75%">](https://github.com/calinux-py/WhoDAT/blob/main/config/poc.gif?raw=true)

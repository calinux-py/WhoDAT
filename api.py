import base64
import json
import time
import requests
from utils import normalize_url, get_url_id
from config import (
    get_virustotal_api_key,
    get_safe_browsing_api_key,
    get_urlscan_api_key,
    get_openai_api_key,
    get_hybrid_analysis_api_key
)

def get_virustotal_report(url, api_key):
    if not api_key:
        print("Skipping VirusTotal because no API key found in config/config.ini...")
        return None

    url_id = get_url_id(url)
    headers = {'x-apikey': api_key}
    vt_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
    response = requests.get(vt_url, headers=headers)

    if response.status_code in (401, 403):
        print("Skipping VirusTotal because no API key found in config/config.ini...")
        return None

    if response.status_code == 200:
        return response.json()

    if response.status_code == 404:
        vt_submit_url = 'https://www.virustotal.com/api/v3/urls'
        submit_response = requests.post(vt_submit_url, headers=headers, data={'url': url})

        if submit_response.status_code in (401, 403):
            print("Skipping VirusTotal because no API key found in config/config.ini...")
            return None

        if submit_response.status_code in (200, 202):
            analysis_id = submit_response.json()['data']['id']
            analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
            for _ in range(10):
                time.sleep(2)
                analysis_response = requests.get(analysis_url, headers=headers)
                if analysis_response.status_code == 200:
                    status = analysis_response.json()['data']['attributes']['status']
                    if status == 'completed':
                        report_response = requests.get(vt_url, headers=headers)
                        if report_response.status_code == 200:
                            return report_response.json()
                        else:
                            break
            return None
    return None

def get_virustotal_ip_report(ip_address, api_key):
    if not api_key:
        print("Skipping VirusTotal IP Report because no API key found in config/config.ini...")
        return None

    headers = {'x-apikey': api_key}
    vt_url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    response = requests.get(vt_url, headers=headers)

    if response.status_code in (401, 403):
        print("Skipping VirusTotal IP Report because no API key found in config/config.ini...")
        return None

    if response.status_code == 200:
        return response.json()
    return None

def get_urlscan_report(url, api_key):
    if not api_key:
        print("Skipping URLScan because no API key found in config/config.ini...")
        return None

    headers = {
        'API-Key': api_key,
        'Content-Type': 'application/json'
    }
    payload = {
        "url": url,
        "visibility": "unlisted"  # options: Public, Private, Unlisted
    }
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=payload)

    if response.status_code in (401, 403):
        print("Skipping URLScan because no API key found in config/config.ini...")
        return None

    if response.status_code == 200:
        scan_id = response.json().get('uuid')
        result_url = f"https://urlscan.io/api/v1/result/{scan_id}/"
        for _ in range(10):
            time.sleep(2)
            result_response = requests.get(result_url, headers=headers)
            if result_response.status_code == 200:
                result = result_response.json()
                verdict = result.get("verdicts", {}).get("overall", "unknown")
                screenshot_url = result.get("task", {}).get("screenshotURL", None)
                if screenshot_url:
                    try:
                        screenshot_response = requests.get(screenshot_url, timeout=10)
                        if screenshot_response.status_code == 200:
                            screenshot_data = screenshot_response.content
                            screenshot_base64 = base64.b64encode(screenshot_data).decode('utf-8')
                            return {
                                "verdict": verdict,
                                "screenshot": screenshot_base64,
                                "screenshot_url": screenshot_url
                            }
                        else:
                            return {"verdict": verdict, "screenshot": None, "screenshot_url": screenshot_url}
                    except Exception as e:
                        print(f"Error fetching screenshot: {e}")
                        return {"verdict": verdict, "screenshot": None, "screenshot_url": screenshot_url}
                else:
                    return {"verdict": verdict, "screenshot": None, "screenshot_url": None}
    return None

def check_url_safe_browsing(url, api_key):
    if not api_key:
        print("Skipping Safe Browsing because no API key found in config/config.ini...")
        return None, "Safe Browsing API key missing."

    api_endpoint = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'
    payload = {
        "client": {
            "clientId": "WhoDAT-InfoSec-Analyzer",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    try:
        response = requests.post(api_endpoint, json=payload, timeout=10)

        if response.status_code in (401, 403):
            print("Skipping Safe Browsing because no API key found in config/config.ini...")
            return None, "Safe Browsing API key invalid."

        if response.status_code == 200:
            result = response.json()
            if "matches" in result:
                threats = [match['threatType'] for match in result['matches']]
                return False, threats
            else:
                return True, []
        else:
            return None, f"Safe Browsing API Error: {response.status_code}"
    except Exception as e:
        return None, f"Safe Browsing API Exception: {e}"

def get_openai_analysis(report):
    api_key = get_openai_api_key()
    if not api_key:
        print("Skipping OpenAI because no API key found in config/config.ini...")
        return None, "OpenAI API key not provided."

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}',
    }
    prompt = f"""Analyze the following security report and determine if the link or email is malicious. Do not repeat the report, simply provide a report summary and score. Classifications: Malicious (Risk score: 10-9), probably malicious (Risk score: 8-7), suspicious (Risk score: 6-4), or safe (Risk score: 3-1). Provide an overall risk score between 1-10. Bullet point your reason behind this decision and be detailed. Do NOT include hyperlinks. Note: Not all services or reports are perfect. VirusTotal IP Scans are NOT perfect since IP address owners can change. If VirusTotal IP Scan or Redirect IPs are the ONLY items listed as malicious, score this as a 6 or less. If Google Safe Browsing marks it as malicious, its malicious. If 5+ VirusTotal Report services mark it has malicious, score this higher. If the website is blocked by safebrowse.io, score this as a 10. Include Classification and Risk Score. Free Email domains should increase risk score. When analyzing email content, consider checking for indicators such as urgency, misspellings, and embedded links. These factors can contribute to a higher risk score. EXTREMELY IMPORTANT: You MUST format your output in HTML but do NOT use codeblocks!!

{report}"""
    data = {
        "model": "chatgpt-4o-latest",
        "messages": [
            {"role": "system", "content": "You are a security analyst. You MUST provide a Risk Score, Classification, and bullet point analysis in HTML format WITHOUT code blocks. Do NOT use Markdown"},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 800,
        "temperature": 0.8,
    }
    try:
        response = requests.post('https://api.openai.com/v1/chat/completions', headers=headers, json=data)

        if response.status_code in (401, 403):
            print("Skipping OpenAI because no API key found in config/config.ini...")
            return None, "OpenAI API key invalid."

        if response.status_code == 200:
            return response.json()['choices'][0]['message']['content'], None
        else:
            return None, f"Error communicating with OpenAI API: {response.status_code} - {response.text}"
    except Exception as e:
        return None, f"Exception during OpenAI API call: {e}"
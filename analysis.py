import re
import socket
import os
import time
import json
import requests
import urllib.parse
from datetime import datetime
from PyQt5.QtCore import QThread, pyqtSignal
from email.parser import Parser
from email.policy import default
from email.utils import parseaddr
import pytz
import tldextract
import whois
from dateutil import parser as date_parser

from config import (
    get_virustotal_api_key,
    get_safe_browsing_api_key,
    get_urlscan_api_key,
    get_openai_api_key,
    get_hybrid_analysis_api_key
)
from utils import (
    defang_url, defang_email, defang_domain,
    format_field
)
from api import (
    get_virustotal_report, get_virustotal_ip_report,
    get_urlscan_report, check_url_safe_browsing,
    get_openai_analysis
)

FREE_EMAIL_DOMAINS = {
    'gmail.com', 'yahoo.com', 'outlook.com', 'live.com', 'aol.com',
    'protonmail.com', 'zoho.com', 'mail.com', 'gmx.com', 'yandex.com',
    'mail.ru', 'inbox.com', 'fastmail.com', 'tutanota.com', 'hushmail.com',
    'aim.com', 'msn.com', 'hotmail.co.uk', 'icloud.com', 'gmx.net',
    'rediffmail.com', 'ymail.com', 'email.com', 'inbox.lv', 'outlook.co.uk',
    'hotmail.fr', 'rambler.ru', 'seznam.cz', 'libero.it', 'laposte.net',
    'virgilio.it', 'interia.pl', 'free.fr', 'freemail.nl', 'mail.bg',
    'mail.ee', 'mail.hu', 'mail.it', 'email.bg', 'email.ee', 'email.hu',
    'email.it', 'email.pl', 'email.nl', 'email.se', 'email.es', 'email.de',
    'email.fr', 'email.ca', 'email.co.za', 'outlook.de', 'outlook.fr',
    'outlook.it', 'outlook.es', 'outlook.ca', 'outlook.com.au', 'outlook.co.in',
    'outlook.co.jp', 'outlook.com.br', 'mailfence.com', 'disroot.org',
    'openmailbox.org', 'migadu.com', 'mail.vivaldi.net', 'outlook.com.mx'
}


class AnalyzerThread(QThread):
    output_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, email, link, vt_api_key, sb_api_key, openai_api_key):
        super().__init__()
        self.email = email
        self.link = link
        self.vt_api_key = vt_api_key
        self.sb_api_key = sb_api_key
        self.openai_api_key = openai_api_key
        self.report = ""

    def emit_output(self, text):
        plain_text = re.sub('<[^<]+?>', '', text)
        self.report += plain_text + '\n'
        self.output_signal.emit(text)

    def run(self):
        try:
            if self.email:
                self.emit_output(f"<br><b>Analyzing Email Address:</b> {defang_email(self.email)}")
                self.process_email_input()
            if self.link:
                self.emit_output(f"<br><b>Analyzing Link:</b> {defang_url(self.link)}")
                self.process_link_input()
            if not self.email and not self.link:
                self.error_signal.emit("No email or link provided.")
                self.emit_output("<i><span style='color:lightgrey;'>Skipping analysis because no input was provided.</span></i><br>")
            if self.openai_api_key and self.report.strip():
                self.emit_output("<i><span style='color:lightgrey;'>Sending report to AI for analysis...</span></i><br>")
                ai_response, ai_error = get_openai_analysis(self.report)
                if ai_error:
                    self.error_signal.emit(ai_error)
                    self.emit_output("<i><span style='color:lightgrey;'>Skipping AI Analysis due to an error.</span></i><br>")
                elif ai_response:
                    self.emit_output(f"<br><b>AI Analysis:</b><br>{ai_response}<br>")
        except Exception as e:
            self.error_signal.emit(f"An unexpected error occurred: {e}")
            self.emit_output("<i><span style='color:lightgrey;'>Skipping analysis due to an unexpected error.</span></i><br>")

    def fetch_and_process_whois(self, domain_name, domain_label):
        try:
            domain_info = whois.whois(domain_name)
            output = f"<br><b>WHOIS Information for {domain_label}:</b><br>"
            output += self.process_domain_whois(domain_name, domain_info)
            self.emit_output(output)
            if domain_label == "Email Domain" and self.email:
                response = requests.get(f"https://disify.com/api/email/{self.email}")
                if response.status_code == 200:
                    disify_data = response.json()
                    disposable_status = disify_data.get("disposable", "Unknown")
                    output = "Disposable Email: {}".format(
                        '<span style="color:red">YES</span>' if disposable_status else 'No') + "<br>"
                    self.emit_output(output)
                else:
                    self.error_signal.emit(f"Error checking disposable status for {self.email}: {response.status_code}")
                    self.emit_output("<i><span style='color:lightgrey;'>Skipping Disposable Email Check due to an error.</span></i><br>")
        except Exception as e:
            self.error_signal.emit(f"Error fetching WHOIS data for {domain_label} {defang_domain(domain_name)}: {e}")
            self.emit_output(f"<i><span style='color:lightgrey;'>Skipping WHOIS analysis for {domain_label} due to an error.</span></i><br>")

    def process_email_input(self):
        email_pattern = r'^[^@]+@([^@]+\.[^@]+)$'
        match = re.match(email_pattern, self.email)
        if not match:
            self.error_signal.emit("Invalid email address.")
            self.emit_output("<i><span style='color:lightgrey;'>Skipping Email Analysis due to an invalid email address.</span></i><br>")
            return
        domain = match.group(1)
        ext = tldextract.extract(domain)
        registered_domain = ext.registered_domain
        if not registered_domain:
            self.error_signal.emit("Could not extract registered domain from email.")
            self.emit_output("<i><span style='color:lightgrey;'>Skipping Email Analysis due to inability to extract domain.</span></i><br>")
            return

        self.fetch_and_process_whois(registered_domain, "Email Domain")
        if self.email and self.is_free_email(registered_domain):
            self.emit_output(f"Email Domain {registered_domain} is a <span style='color:red;'>FREE</span> email provider.<br>")

    def is_free_email(self, domain):
        return domain.lower() in FREE_EMAIL_DOMAINS

    def process_link_input(self):
        full_link = self.link
        if not full_link.startswith(('http://', 'https://')):
            full_link = 'http://' + full_link
        try:
            response = requests.get(full_link, allow_redirects=True, timeout=10)
        except Exception as e:
            self.error_signal.emit(f"Could not fetch the link: {e}")
            self.emit_output("<i><span style='color:lightgrey;'>Skipping Link Analysis due to an error fetching the URL.</span></i><br>")
            return

        parsed_start_url = urllib.parse.urlparse(full_link)
        start_domain = parsed_start_url.hostname
        ext = tldextract.extract(start_domain)
        start_registered_domain = ext.registered_domain

        if "safebrowse.io" not in full_link.lower():
            if start_registered_domain:
                self.fetch_and_process_whois(start_registered_domain, "Starting URL Domain")
                self.emit_output("<br><i><span style='color:lightgrey;'>Analyzing URL and Redirects...</span></i><br>")
            self.process_redirect_chain(response)
        else:
            self.emit_output("<span style='color:red;'>Skipping WHOIS and URLScan scanning because URL contains safebrowse.io</span><br>")

        final_url = response.url
        parsed_final_url = urllib.parse.urlparse(final_url)
        final_domain = parsed_final_url.hostname
        ext = tldextract.extract(final_domain)
        final_registered_domain = ext.registered_domain

        if "safebrowse.io" not in final_url.lower():
            if final_registered_domain:
                self.fetch_and_process_whois(final_registered_domain, "Final URL Domain")
        else:
            self.emit_output("<i><span style='color:lightgrey;'>Skipping WHOIS and UrlScan for Final URL because it contains safebrowse.io.</span></i>")

        self.emit_output("<br><i><span style='color:lightgrey;'>Generating VirusTotal Report...</span></i><br>")

        if self.vt_api_key:
            try:
                vt_report = get_virustotal_report(final_url, self.vt_api_key)
                if vt_report:
                    self.process_virustotal_report(vt_report)
                else:
                    self.error_signal.emit("Could not retrieve VirusTotal report. It is possible the website is taken down or blocked. Try analyzing manually on VirusTotal's website.")
                    self.emit_output("<i><span style='color:lightgrey;'>Skipping VirusTotal Report due to retrieval error.</span></i><br>")
            except Exception as e:
                self.error_signal.emit(f"An error occurred while retrieving the VirusTotal report: {e}")
                self.emit_output("<i><span style='color:lightgrey;'>Skipping VirusTotal Report due to an error.</span></i><br>")
        else:
            self.error_signal.emit("VirusTotal API key not provided.")
            self.emit_output("<i><span style='color:lightgrey;'>Skipping VirusTotal Report because API key is not provided.</span></i><br>")

    def process_virustotal_report(self, vt_report):
        output = "<br><b>VirusTotal Report:</b><br>"
        try:
            attributes = vt_report['data']['attributes']
            stats = attributes['last_analysis_stats']
            output += "Analysis Statistics:<br>"
            for key, value in stats.items():
                color = 'white'
                if key.lower() == 'malicious' and value > 0:
                    color = 'red'
                elif key.lower() == 'suspicious' and value > 0:
                    color = 'orange'
                elif key.lower() == 'harmless':
                    color = 'green'
                elif key.lower() == 'undetected':
                    color = 'gray'
                output += f"<span style='color:{color};'>{key.capitalize()}: {value}</span><br>"

            analysis_results = attributes.get('last_analysis_results', {})
            malicious_vendors = [vendor for vendor, result in analysis_results.items() if result.get('category') == 'malicious']
            suspicious_vendors = [vendor for vendor, result in analysis_results.items() if result.get('category') == 'suspicious']

            if malicious_vendors:
                output += "<br><b>Malicious Detections by:</b><br>" + ', '.join(malicious_vendors) + "<br>"
            if suspicious_vendors:
                output += "<br><b>Suspicious Detections by:</b><br>" + ', '.join(suspicious_vendors) + "<br>"
        except Exception as e:
            self.error_signal.emit(f"Error parsing VirusTotal report: {e}")
            self.emit_output("<i><span style='color:lightgrey;'>Skipping further processing of VirusTotal Report due to parsing error.</span></i><br>")
            return
        self.emit_output(output)

    def process_redirect_chain(self, response):
        chain = response.history + [response]
        output = "<br><b>Redirect Chain:</b><br>"
        urlscan_api_key = get_urlscan_api_key()

        for i, resp in enumerate(chain):
            url = resp.url
            parsed_url = urllib.parse.urlparse(url)
            hostname = parsed_url.hostname
            ip_address = socket.gethostbyname(hostname) if hostname else 'N/A'

            detection_status = 'Unknown'
            ip_color = 'white'
            if ip_address != 'N/A' and self.vt_api_key:
                ip_report = get_virustotal_ip_report(ip_address, self.vt_api_key)
                if ip_report:
                    stats = ip_report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    if malicious > 0 or suspicious > 0:
                        ip_color = 'red'
                        detection_status = "<span style='color:red;'>Malicious</span>"
                    else:
                        detection_status = "Clean"

            if self.sb_api_key:
                is_safe, sb_result = check_url_safe_browsing(url, self.sb_api_key)
                if is_safe is True:
                    sb_status = "<span style='color:white;'>No classification</span>"
                elif is_safe is False:
                    threats = ', '.join(sb_result)
                    sb_status = f"<span style='color:red;'>Unsafe ({threats})</span>"
                else:
                    sb_status = f"<span style='color:orange;'>Error ({sb_result})</span>"
            else:
                sb_status = "<span style='color:gray;'>Safe Browsing API Key Not Provided</span>"

            defanged_url = defang_url(url)
            output += f"{i + 1}: {defanged_url} (IP: <span style='color:{ip_color};'>{ip_address}</span>) - VirusTotal IP Scan: {detection_status} - Google Safe Browsing: {sb_status}<br>"

            if urlscan_api_key:
                try:
                    urlscan_report = get_urlscan_report(url, urlscan_api_key)
                    if urlscan_report:
                        verdict = "Malicious" if urlscan_report['verdict'] == "malicious" else "No classification"
                        output += "<br><b>URLScan Verdict:</b> " + verdict + "<br>"
                        if urlscan_report['screenshot']:
                            output += f"<b>URLScan Screenshot:</b><br><img src='data:image/png;base64,{urlscan_report['screenshot']}' width='700'><br>"
                            if urlscan_report.get('screenshot_url'):
                                output += f"<b>URLScan Screenshot URL:</b> {urlscan_report['screenshot_url']}<br>"
                        else:
                            output += "<b>URLScan Screenshot:</b> Not available. It is possible the URL is a download or your API limit for UrlScan has exceeded.<br>"
                except Exception as e:
                    self.error_signal.emit(f"Error fetching URLScan report for {defang_url(url)}: {e}")
                    self.emit_output("<i><span style='color:lightgrey;'>Skipping URLScan Verdict due to an error.</span></i><br>")
            output += "<br>"
        self.emit_output(output)

    def process_domain_whois(self, domain, domain_info):
        output = ""
        registration_date = domain_info.creation_date
        registrant_country = domain_info.country
        current_year = datetime.now().year

        def is_created_this_year(registration_date):
            dates = registration_date if isinstance(registration_date, list) else [registration_date]
            return any(date.year == current_year for date in dates if isinstance(date, datetime))

        def is_not_us_country(registrant_country):
            countries = registrant_country if isinstance(registrant_country, list) else [registrant_country]
            return any(country.strip().upper() != 'US' for country in countries if country)

        is_new_domain = is_created_this_year(registration_date)
        is_not_us = is_not_us_country(registrant_country)

        defanged_domain = defang_domain(domain)
        output += f"Domain: {defanged_domain}<br>"
        reg_date_str = format_field(registration_date)
        reg_date_color = 'red' if is_new_domain else 'white'
        output += f"<span style='color:{reg_date_color};'>Domain Registration Date: {reg_date_str}</span><br>"

        reg_country_str = format_field(registrant_country)
        reg_country_color = 'red' if is_not_us else 'white'
        output += f"<span style='color:{reg_country_color};'>Registrant Country: {reg_country_str}</span><br>"

        output += f"Domain Expiration Date: {format_field(domain_info.expiration_date)}<br>"
        output += f"Registrant Name: {format_field(domain_info.name)}<br>"
        output += f"Registrant Organization: {format_field(domain_info.org)}<br>"
        defanged_contact_email = defang_email(format_field(domain_info.emails))
        output += f"Contact Email: {defanged_contact_email}<br>"
        output += f"Registrar Information: {format_field(domain_info.registrar)}<br>"
        output += f"Name Servers: {format_field(domain_info.name_servers)}<br>"
        output += f"Domain Status: {format_field(domain_info.status)}<br>"
        output += f"Last Updated Date: {format_field(domain_info.updated_date)}<br>"

        return output

class HeaderAnalyzerThread(QThread):
    output_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, headers_text):
        super().__init__()
        self.headers_text = headers_text

    def run(self):
        try:
            parser = Parser(policy=default)
            msg = parser.parsestr(self.headers_text)
            from_header = msg['From']
            authentication_results = msg.get_all('Authentication-Results', [])
            received_headers = msg.get_all('Received', [])
            return_path = msg['Return-Path']
            subject = msg['Subject']
            date = msg['Date']
            output = ""

            originating_ip = self.extract_originating_ip(received_headers)
            country = self.get_ip_country(originating_ip)
            text_color = 'red' if country != 'US' else 'white'
            output += f"<br><b>Originating IP Address:</b> <span style='color:{text_color};'>{originating_ip}</span><br>"
            output += self.get_ip_location(originating_ip, country, text_color)
            output += f"<b>From Address:</b> {from_header}<br>"
            output += f"<b>Return-Path:</b> {return_path}<br>"
            output += f"<b>Subject:</b> {subject}<br>"
            date_pacific_str = self.convert_date_to_pacific(date)
            output += f"<b>Date:</b> {date_pacific_str}<br>"

            output += "<br><br><b>Received Headers:</b><br>"
            for i, header in enumerate(received_headers, 1):
                output += f"{i}: {header}<br><br>"

            intermediaries = []
            for header in received_headers:
                match = re.search(
                    r'from\s+([\w\.-]+|localhost)\s+\((?:[\w\.-]+\s+)?(?:\[)?(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+|IPv6:::1)(?:\])?\)',
                    header,
                    re.IGNORECASE
                )
                if match:
                    hostname, ip = match.groups()
                    intermediaries.append(f"[ + ] {hostname}: {ip}")

            output += "<br><b>Intermediary Addresses and IPs:</b><br>"
            for intermediary in intermediaries:
                output += f"{intermediary}<br>"

            output += self.analyze_spf(msg, authentication_results)
            output += self.analyze_dkim(msg, authentication_results)
            output += self.analyze_dmarc(authentication_results)

            self.output_signal.emit(output)
        except Exception as e:
            self.error_signal.emit(f"An error occurred while analyzing headers: {e}")
            self.output_signal.emit("<i><span style='color:lightgrey;'>Skipping Header Analysis due to an error.</span></i><br>")

    def extract_originating_ip(self, received_headers):
        for header in reversed(received_headers):
            matches = re.findall(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', header)
            if matches:
                return matches[0]
        return "N/A"

    def get_ip_country(self, ip):
        if ip == "N/A":
            return "Unknown"
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            data = response.json()
            return data.get("country", "Unknown")
        except:
            return "Unknown"

    def get_ip_location(self, ip, country, text_color):
        if ip == "N/A":
            return "<b>Originating Location:</b> Unknown<br>"
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            data = response.json()
            city = data.get("city", "Unknown")
            region = data.get("region", "Unknown")
            org = data.get("org", "Unknown")
            postal = data.get("postal", "Unknown")
            timezone = data.get("timezone", "Unknown")
            coordinates = data.get("loc", "Unknown")
            output = f"<b>Originating Country:</b> <span style='color:{text_color};'>{country}</span><br>"
            output += f"<b>City:</b> <span style='color:{text_color};'>{city}</span><br>"
            output += f"<b>Region:</b> <span style='color:{text_color};'>{region}</span><br>"
            output += f"<b>Organization:</b> <span style='color:{text_color};'>{org}</span><br>"
            output += f"<b>Postal Code:</b> <span style='color:{text_color};'>{postal}</span><br>"
            output += f"<b>Timezone:</b> <span style='color:{text_color};'>{timezone}</span><br>"
            output += f"<b>Coordinates:</b> <span style='color:{text_color};'>{coordinates}</span><br>"
            return output
        except:
            return "<b>Originating Location:</b> Unknown<br>"

    def convert_date_to_pacific(self, date_str):
        try:
            date_obj = date_parser.parse(date_str)
            pacific_tz = pytz.timezone('America/Los_Angeles')
            date_pacific = date_obj.astimezone(pacific_tz)
            hour = date_pacific.hour
            time_color = "red" if (21 <= hour or hour < 5) else "white"
            date_pacific_formatted = date_pacific.strftime('%I:%M %p, %d %b %Y')
            return f"<span style='color:{time_color};'>{date_pacific_formatted}</span>"
        except Exception:
            return date_str

    def analyze_spf(self, msg, authentication_results):
        spf_authenticated = "Failed"
        spf_alignment = "Failed"
        for auth_result in authentication_results:
            spf_match = re.search(r'spf=(\w+)', auth_result)
            if spf_match and spf_match.group(1).lower() == 'pass':
                spf_authenticated = "Passed"
            mailfrom_match = re.search(r'smtp\.mailfrom=([^;\s]+)', auth_result)
            if mailfrom_match:
                mailfrom_domain = mailfrom_match.group(1).split('@')[-1]
                from_address = parseaddr(msg['From'])[1]
                from_domain = from_address.split('@')[-1]
                spf_alignment = "Aligned" if mailfrom_domain.lower() == from_domain.lower() else "Not Aligned"
        spf_color = "red" if spf_authenticated != "Passed" or spf_alignment != "Aligned" else "white"
        output = f"<br><br><b>SPF Authenticated:</b> <span style='color:{spf_color};'>{spf_authenticated}</span><br>"
        output += f"<b>SPF Alignment:</b> <span style='color:{spf_color};'>{spf_alignment}</span><br>"
        return output

    def analyze_dkim(self, msg, authentication_results):
        dkim_authenticated = "Failed"
        dkim_alignment = "Failed"
        for auth_result in authentication_results:
            dkim_match = re.search(r'dkim=(\w+)', auth_result)
            if dkim_match and dkim_match.group(1).lower() == 'pass':
                dkim_authenticated = "Passed"
            headerd_match = re.search(r'header\.d=([^;\s]+)', auth_result)
            if headerd_match:
                headerd_domain = headerd_match.group(1)
                from_address = parseaddr(msg['From'])[1]
                from_domain = from_address.split('@')[-1]
                dkim_alignment = "Aligned" if headerd_domain.lower() == from_domain.lower() else "Not Aligned"
        dkim_color = "red" if dkim_authenticated != "Passed" or dkim_alignment != "Aligned" else "white"
        output = f"<b>DKIM Authenticated:</b> <span style='color:{dkim_color};'>{dkim_authenticated}</span><br>"
        output += f"<b>DKIM Alignment:</b> <span style='color:{dkim_color};'>{dkim_alignment}</span><br>"
        return output

    def analyze_dmarc(self, authentication_results):
        dmarc_compliant = "Failed"
        for auth_result in authentication_results:
            dmarc_match = re.search(r'dmarc=(\w+)', auth_result)
            if dmarc_match and dmarc_match.group(1).lower() == 'pass':
                dmarc_compliant = "Passed"
        dmarc_color = "red" if dmarc_compliant != "Passed" else "white"
        output = f"<b>DMARC Compliance:</b> <span style='color:{dmarc_color};'>{dmarc_compliant}</span><br>"
        return output

class SentimentAnalyzerThread(QThread):
    output_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, content, openai_api_key):
        super().__init__()
        self.content = content
        self.openai_api_key = openai_api_key

    def run(self):
        if not self.content.strip():
            return
        analysis, error = get_openai_analysis(self.content)
        if error:
            self.error_signal.emit(error)
        elif analysis:
            self.output_signal.emit(analysis + "<br>")

class AttachmentAnalyzerThread(QThread):
    output_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, file_path, vt_api_key, ha_api_key):
        super().__init__()
        self.file_path = file_path
        self.vt_api_key = vt_api_key
        self.ha_api_key = ha_api_key

    def run(self):
        if not self.file_path:
            self.error_signal.emit("No file selected.")
            return
        if not os.path.isfile(self.file_path):
            self.error_signal.emit("The specified file does not exist.")
            return

        self.output_signal.emit("<br><b>Attachment Analysis:</b><br>")
        self.output_signal.emit("<br><i><span style='color:lightgrey;'>Uploading file to VirusTotal and Hybrid Analysis for analysis...</span></i><br>")
        try:
            vt_thread = VirusTotalUploadThread(self.file_path, self.vt_api_key)
            ha_thread = HybridAnalysisUploadThread(self.file_path, self.ha_api_key)

            vt_thread.output_signal.connect(self.emit_output)
            vt_thread.error_signal.connect(self.error_signal.emit)
            ha_thread.output_signal.connect(self.emit_output)
            ha_thread.error_signal.connect(self.error_signal.emit)

            vt_thread.start()
            ha_thread.start()

            vt_thread.wait()
            ha_thread.wait()
        except Exception as e:
            self.error_signal.emit(f"Exception during file upload: {e}")

    def emit_output(self, text):
        self.output_signal.emit(text)

class VirusTotalUploadThread(QThread):
    output_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, file_path, vt_api_key):
        super().__init__()
        self.file_path = file_path
        self.vt_api_key = vt_api_key

    def run(self):
        try:
            headers = {'x-apikey': self.vt_api_key}
            with open(self.file_path, 'rb') as f:
                files = {'file': (os.path.basename(self.file_path), f)}
                response = requests.post('https://www.virustotal.com/api/v3/files', headers=headers, files=files)

            if response.status_code in (200, 201):
                analysis_id = response.json()['data']['id']
                analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
                self.output_signal.emit("<i><span style='color:lightgrey;'>File uploaded successfully to VirusTotal. Fetching analysis report...</span></i><br>")
                for _ in range(25):
                    time.sleep(6)
                    report_response = requests.get(analysis_url, headers=headers)
                    if report_response.status_code == 200:
                        status = report_response.json()['data']['attributes']['status']
                        if status == 'completed':
                            report = self.get_file_report(analysis_id)
                            if report:
                                self.process_virustotal_file_report(report)
                            else:
                                self.error_signal.emit("Could not retrieve VirusTotal report.")
                            return
                self.error_signal.emit("VirusTotal analysis timed out.")
            else:
                error_message = f"Error uploading file to VirusTotal: {response.status_code} - {response.text}"
                self.error_signal.emit(error_message)
        except Exception as e:
            self.error_signal.emit(f"Exception during VirusTotal file upload: {e}")

    def get_file_report(self, analysis_id):
        headers = {'x-apikey': self.vt_api_key}
        analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
        try:
            response = requests.get(analysis_url, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                self.error_signal.emit(f"Error fetching VirusTotal analysis report: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            self.error_signal.emit(f"Exception while fetching VirusTotal analysis report: {e}")
            return None

    def process_virustotal_file_report(self, vt_report):
        output = "<br><b>VirusTotal File Report:</b><br>"
        try:
            attributes = vt_report['data']['attributes']
            stats = attributes['stats']
            output += "Analysis Statistics:<br>"
            for key, value in stats.items():
                color = 'white'
                if key.lower() == 'malicious':
                    color = 'red'
                elif key.lower() == 'suspicious':
                    color = 'orange'
                elif key.lower() == 'harmless':
                    color = 'green'
                elif key.lower() == 'undetected':
                    color = 'gray'
                output += f"<span style='color:{color};'>{key.capitalize()}: {value}</span><br>"

            analysis_results = attributes.get('results', {})
            malicious_vendors = [vendor for vendor, result in analysis_results.items() if result.get('category') == 'malicious']
            suspicious_vendors = [vendor for vendor, result in analysis_results.items() if result.get('category') == 'suspicious']

            if malicious_vendors:
                output += "<br><b>Malicious Detections by:</b><br>" + ', '.join(malicious_vendors) + "<br>"
            if suspicious_vendors:
                output += "<br><b>Suspicious Detections by:</b><br>" + ', '.join(suspicious_vendors) + "<br>"
        except Exception as e:
            self.error_signal.emit(f"Error parsing VirusTotal file report: {e}")
            self.output_signal.emit("<i><span style='color:lightgrey;'>Skipping further processing of VirusTotal File Report due to parsing error.</span></i><br>")
            return
        self.output_signal.emit(output)

class HybridAnalysisUploadThread(QThread):
    output_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, file_path, ha_api_key):
        super().__init__()
        self.file_path = file_path
        self.ha_api_key = ha_api_key

    def run(self):
        try:
            headers = {"User-Agent": "FalconSandbox", "api-key": self.ha_api_key}
            upload_endpoint = "https://www.hybrid-analysis.com/api/v2/submit/file"
            overview_endpoint = "https://www.hybrid-analysis.com/api/v2/overview"

            with open(self.file_path, 'rb') as file:
                files = {"file": file}
                data = {"environment_id": 100}
                upload_response = requests.post(upload_endpoint, headers=headers, files=files, data=data)

            if upload_response.status_code in [200, 201]:
                upload_data = upload_response.json()
                hash_value = upload_data.get("sha256")
                self.output_signal.emit("<i><span style='color:lightgrey;'>File uploaded successfully to Hybrid Analysis. Fetching analysis report...</span></i><br>")

                if hash_value:
                    lookup_response = requests.get(f"{overview_endpoint}/{hash_value}", headers=headers)
                    if lookup_response.status_code == 200:
                        data = lookup_response.json()
                        if data:
                            verdict = data.get("verdict", "").lower()
                            threat_score = data.get("threat_score", 0)
                            verdict_color = 'red' if verdict == "malicious" else 'white'
                            try:
                                threat_score_value = float(threat_score)
                                score_color = 'red' if threat_score_value >= 70 else 'white'
                            except (ValueError, TypeError):
                                score_color = 'white'
                            output = "<br><b>Hybrid Analysis Report:</b><br>"
                            output += f"<b>File Name:</b> {data.get('last_file_name')}<br>"
                            output += f"<b>Threat Score:</b> <span style='color:{score_color};'>{threat_score}</span><br>"
                            output += f"<b>Verdict:</b> <span style='color:{verdict_color};'>{data.get('verdict')}</span><br>"
                            output += f"<b>Type:</b> {data.get('type')}<br>"
                            output += f"<b>Tags:</b> {', '.join(data.get('tags', []))}<br>"
                            self.output_signal.emit(output)
                        else:
                            self.output_signal.emit("No data found for the provided hash.")
                    else:
                        self.error_signal.emit(f"Error during Hybrid Analysis hash lookup: {lookup_response.status_code}, {lookup_response.text}")
                else:
                    self.error_signal.emit("Error: No hash returned from the Hybrid Analysis upload response.")
            else:
                self.error_signal.emit(f"Error during file upload to Hybrid Analysis: {upload_response.status_code}, {upload_response.text}")
        except Exception as e:
            self.error_signal.emit(f"Exception during Hybrid Analysis file upload: {e}")
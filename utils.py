# utils.py

import base64
import re
import urllib.parse
from datetime import datetime

def defang_url(url):
    return url.replace('http://', 'hxxp://').replace('https://', 'hxxps://').replace('.', '[.]')

def defang_email(email):
    return email.replace('@', '[@]').replace('.', '[.]')

def defang_domain(domain):
    return domain.replace('.', '[.]')

def defang_text(text):
    defanged = re.sub(r'http(s)?://', r'hxxp\1://', text)
    defanged = defanged.replace('.', '[.]').replace('@', '[@]')
    return defanged

def format_field(field):
    if field is None:
        return 'N/A'
    elif isinstance(field, list):
        return ', '.join([format_field(f) for f in field])
    elif isinstance(field, datetime):
        return field.strftime('%Y-%m-%d')
    else:
        return str(field)

def normalize_url(url):
    parsed = urllib.parse.urlparse(url)
    parsed = parsed._replace(fragment='')
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.encode('idna').decode('ascii').lower() if parsed.hostname else ''
    port = parsed.port
    if (scheme == 'http' and port == 80) or (scheme == 'https' and port == 443):
        netloc = hostname
    elif port:
        netloc = f"{hostname}:{port}"
    else:
        netloc = hostname
    path = re.sub(r'/{2,}', '/', parsed.path or '')
    query = parsed.query
    if query:
        query_params = urllib.parse.parse_qsl(query, keep_blank_values=True)
        query = urllib.parse.urlencode(sorted(query_params))
    else:
        query = ''
    normalized = urllib.parse.urlunparse((scheme, netloc, path, '', query, ''))
    return normalized

def get_url_id(url):
    normalized = normalize_url(url)
    url_bytes = normalized.encode('utf-8')
    url_id = base64.urlsafe_b64encode(url_bytes).decode('utf-8').strip('=')
    return url_id

# config.py

import configparser

def get_virustotal_api_key():
    config = configparser.ConfigParser()
    config.read('config/config.ini')
    return config.get('VirusTotal', 'api_key')

def get_safe_browsing_api_key():
    config = configparser.ConfigParser()
    config.read('config/config.ini')
    if config.has_section('GoogleSafeBrowsing'):
        return config.get('GoogleSafeBrowsing', 'api_key')
    return None

def get_urlscan_api_key():
    config = configparser.ConfigParser()
    config.read('config/config.ini')
    return config.get('Urlscan', 'api_key')

def get_openai_api_key():
    config = configparser.ConfigParser()
    config.read('config/config.ini')
    if config.has_section('OpenAI'):
        return config.get('OpenAI', 'api_key')
    return None

def get_hybrid_analysis_api_key():
    config = configparser.ConfigParser()
    config.read('config/config.ini')
    if config.has_section('HybridAnalysis'):
        return config.get('HybridAnalysis', 'api_key')
    return None

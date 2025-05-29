#!/usr/bin/env python3

import re
import sys
import json
import whois
import argparse
import requests
import tldextract
from datetime import datetime
from urllib.parse import urlparse
from colorama import Fore, Style, init
import os  # <-- Added import here

init(autoreset=True)

VT_API_KEY = ""  # Optional: Add your VirusTotal API key here

with open("suspicious_keywords.json") as f:
    phishing_keywords = json.load(f)["keywords"]

def is_ip_url(url):
    return bool(re.match(r"https?://(\d{1,3}\.){3}\d{1,3}", url))

def contains_phishing_keywords(url):
    return [word for word in phishing_keywords if word.lower() in url.lower()]

def get_whois_info(domain):
    try:
        info = whois.whois(domain)
        creation = str(info.creation_date)
        registrar = str(info.registrar)
        return {
            "creation_date": creation,
            "registrar": registrar,
        }
    except:
        return {
            "creation_date": "Unknown",
            "registrar": "Unknown",
        }

def check_virustotal(url):
    if not VT_API_KEY:
        return "VT_KEY_NOT_SET"
    headers = {"x-apikey": VT_API_KEY}
    params = {"url": url}
    try:
        res = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)
        if res.status_code == 200:
            scan_id = res.json()["data"]["id"]
            report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
            return report.json()
        return "VT_ERROR"
    except:
        return "VT_ERROR"

def analyze_url(url):
    result = {
        "url": url,
        "valid_scheme": url.startswith("https://"),
        "uses_ip": is_ip_url(url),
        "keywords": contains_phishing_keywords(url),
        "suspicious_tld": False,
        "domain": "",
        "whois": {},
        "vt_result": ""
    }

    parsed = tldextract.extract(url)
    result["domain"] = f"{parsed.domain}.{parsed.suffix}"
    result["suspicious_tld"] = parsed.suffix in ['tk', 'ml', 'ga', 'cf', 'gq']
    result["whois"] = get_whois_info(result["domain"])
    vt = check_virustotal(url)
    result["vt_result"] = vt if type(vt) == str else vt.get("data", {}).get("attributes", {}).get("stats", {})
    return result

def print_report(result):
    print(f"\n🔍 Scanning: {Fore.CYAN}{result['url']}{Style.RESET_ALL}")
    if result["valid_scheme"]:
        print(f"{Fore.GREEN}[+] Uses HTTPS")
    else:
        print(f"{Fore.YELLOW}[!] Does not use HTTPS")

    if result["uses_ip"]:
        print(f"{Fore.RED}[-] URL contains IP address")

    if result["suspicious_tld"]:
        print(f"{Fore.RED}[-] Suspicious TLD detected: {result['domain']}")

    if result["keywords"]:
        print(f"{Fore.RED}[-] Phishing terms found: {', '.join(result['keywords'])}")
    else:
        print(f"{Fore.GREEN}[+] No known phishing terms found")

    print(f"{Fore.CYAN}[WHOIS] Domain Created: {result['whois']['creation_date']} | Registrar: {result['whois']['registrar']}")
    
    if isinstance(result["vt_result"], dict):
        print(f"{Fore.MAGENTA}[VirusTotal] Malicious: {result['vt_result'].get('malicious', '?')} | Suspicious: {result['vt_result'].get('suspicious', '?')}")
    elif result["vt_result"] == "VT_KEY_NOT_SET":
        print(f"{Fore.YELLOW}[VT] API key not set. Skipping VirusTotal check.")

def save_report(result):
    if not os.path.exists('reports'):
        os.makedirs('reports')  # Create reports folder if missing
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/report_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(result, f, indent=4)
    print(f"{Fore.BLUE}[+] Report saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description="PhishSniper - Suspicious Link Analyzer")
    parser.add_argument("-u", "--url", help="Single URL to scan")
    parser.add_argument("-f", "--file", help="File containing list of URLs to scan")
    args = parser.parse_args()

    if args.url:
        result = analyze_url(args.url)
        print_report(result)
        save_report(result)

    elif args.file:
        with open(args.file) as f:
            urls = f.read().splitlines()
        for url in urls:
            result = analyze_url(url)
            print_report(result)
            save_report(result)
    else:
        print("❌ Please provide either --url or --file")

if __name__ == "__main__":
    main()






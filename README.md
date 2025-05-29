 🛡️ PhishSniper - Suspicious Link Analyzer (CLI Tool)

PhishSniper is a powerful and simple command-line tool built for cybersecurity professionals and enthusiasts. It analyzes suspicious URLs for phishing indicators, scans for common malicious traits, performs WHOIS lookups, and optionally integrates with the VirusTotal API to get reputation results.


 🔍 Features

- 🔗 Analyze single or multiple URLs
- 🧠 Detect phishing keywords in URLs
- 🌐 WHOIS Lookup for domain information
- 📦 VirusTotal integration (optional via API key)
- ⚠️ Identifies:
  - IP-based URLs
  - Suspicious top-level domains (`.tk`, `.ml`, etc.)
  - Missing HTTPS
- 📁 Saves detailed reports in JSON format
- 🎯 Works great for threat hunting and red teamers

 📁 Project Structure

phishsniper/
├── phishsniper.py # Main script
├── suspicious_keywords.json # List of phishing terms
├── urls.txt # For batch URL scanning
└── reports/ # Stores JSON scan reports


 🧰 Requirements

Install dependencies with:
pip install -r requirements.txt

Required Python modules:
requests
tldextract
whois
colorama

🔑 VirusTotal Integration (Optional)
To enable VirusTotal scanning:
1.Get a free API key from VirusTotal.
2.Export it as an environment variable:
export VT_API_KEY="your_api_key_here"

🚀 Usage : 
1. Scan a Single URL:
   
python3 phishsniper.py -u "http://example.com"

2. Batch Scan Multiple URLs
Create a file urls.txt with one URL per line:
http://malicious-site.tk
https://secure-login.evil.com

python3 phishsniper.py -f urls.txt

📤 Reports
All scan results are saved in the reports/ folder with timestamped filenames.

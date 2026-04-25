# Phishing URL Detector

A command-line tool that analyzes URLs for phishing indicators using a weighted heuristic scoring system. It checks for brand impersonation, suspicious TLDs, domain entropy, IP-based URLs, unicode spoofing, and more — then returns a risk verdict of **Safe**, **Suspicious**, or **High Risk**.

## How It Works

Each URL is broken down into its components and run through a set of detection checks. Each check carries a weight, and the scores are summed to produce a final verdict:

| Signal | Weight |
|---|---|
| Brand impersonation (e.g. `paypa1.com`) | 1.00 |
| IP address in URL | 0.90 |
| Unicode/punycode spoofing | 0.80 |
| Suspicious TLD (`.xyz`, `.tk`, `.zip`, ...) | 0.75 |
| Special characters in hostname | 0.70 |
| High domain entropy (random-looking name) | 0.60 |
| Excessive subdomains | 0.50 |
| Newly registered domain (<180 days) | 0.45 |
| Excessive dots in hostname | 0.40 |
| Long hostname | 0.30 |
| Excessive slashes in URL | 0.20 |

## Installation

```bash
git clone https://github.com/jwd06/Phishing-URL-Detector.git
cd Phishing-URL-Detector
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 main.py scan "<url>"
```

Always wrap the URL in quotes to avoid shell interpretation of special characters.

**Examples:**

```bash
python3 main.py scan "https://www.google.com"
python3 main.py scan "http://www.paypa1.com"
python3 main.py scan "http://example.xyz"
```

## Example Output

```
╭────────────────────────────────────────────────────────────── PHISH ──────────────────────────────────────────────╮
│                                                                                                                   │
│  .______    __    __   __       _______. __    __                                                                 │
│  |   _  \  |  |  |  | |  |     /       ||  |  |  |                                                                │
│  |  |_)  | |  |__|  | |  |    |   (----`|  |__|  |                                                                │
│  |   ___/  |   __   | |  |     \   \    |   __   |                                                                │
│  |  |      |  |  |  | |  | .----)   |   |  |  |  |                                                                │
│  | _|      |__|  |__| |__| |_______/    |__|  |__|                                                                │
│                                                                                                                   │
╰────────────────────────────────────────── v1.0.0  |  Jawad Hossain  |  github.com/jwd06 ──────────────────────────╯
╭──────────────────────────────────────────────────────────   HIGH RISK   ──────────────────────────────────────────╮
│                                                                                                                   │
│  Score: 1.00                                                                                                      │
│                                                                                                                   │
│  Triggers:                                                                                                        │
│    • brand_impersonation: paypal                                                                                  │
│                                                                                                                   │
│  Domain Age: unavailable                                                                                          │
│                                                                                                                   │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## Requirements

- Python 3.10+
- Dependencies listed in `requirements.txt`

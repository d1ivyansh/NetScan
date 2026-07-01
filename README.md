# NetScan — Network, Service, OS & CVE Vulnerability Scanner

A single-file Python tool that scans a host (or small subnet) for open ports,
identifies running services and their versions, guesses the operating
system, and looks up known CVEs for each detected service via the NVD

**This is a detection/reporting tool only. It does not exploit anything.**


## Install

1. Prerequisites

Python 3.7+
(Optional, recommended) nmap for better accuracy

2. Get the code
git clone https://github.com/d1vyansh/netscan.git
cd netscan
(or just cd into the extracted folder if you're not using GitHub yet)

3. (Recommended/optional) Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # macOS/Linux
.venv\Scripts\activate           # Windows

4. Install dependencies
   pip3 install -r requirements.txt

6. (Optional) Install nmap for better scans
sudo apt install nmap      # Debian/Ubuntu
brew install nmap          # macOS
Windows: download from nmap.org.

7. Run a scan
 Basic scan, top 20 ports, with CVE lookups
python3 netscan.py 192.168.1.10

# Top 100 ports
python3 netscan.py scanme.nmap.org --ports top100

# Custom port range or list
python3 netscan.py 10.0.0.5 --ports 1-1024
python3 netscan.py 10.0.0.5 --ports 22,80,443,3306

# All ports (slow)
python3 netscan.py 10.0.0.5 --ports all

# Save JSON + HTML reports
python3 netscan.py 10.0.0.5 --json report.json --html report.html

# Skip CVE lookups (faster, offline)
python3 netscan.py 10.0.0.5 --no-cve

# Use an NVD API key (faster CVE lookups)
python3 netscan.py 10.0.0.5 --nvd-api-key YOUR_KEY

# Scan a small subnet (max /24)
python3 netscan.py 10.0.0.0/29 --ports top20

# For OS detection via nmap -O (needs root)
sudo python3 netscan.py 10.0.0.5
Reminder: only scan hosts you own or are authorized to test — the script will prompt you to confirm this unless you pass --yes.

pip install -r requirements.txt


Optional but recommended — install `nmap` for much more accurate service
and OS fingerprinting (the script auto-detects and uses it if present,
otherwise it falls back to a pure-Python socket scanner):


sudo apt install nmap       # Debian / Ubuntu
brew install nmap           # macOS


OS fingerprinting via `nmap -O` requires root/administrator privileges
(`sudo python3 netscan.py ...`). Without root it still does port + service
detection, plus a rough TTL-based OS guess.

## Usage

```bash
# Basic scan of the most common 20 ports, with CVE lookups
python3 netscan.py 192.168.1.10

# Scan top 100 ports
python3 netscan.py scanme.nmap.org --ports top100

# Custom port range/list
python3 netscan.py 10.0.0.5 --ports 1-1024
python3 netscan.py 10.0.0.5 --ports 22,80,443,3306

# Full port range (slow)
python3 netscan.py 10.0.0.5 --ports all

# Save JSON + HTML reports
python3 netscan.py 10.0.0.5 --json report.json --html report.html

# Skip CVE lookups (faster, fully offline scan)
python3 netscan.py 10.0.0.5 --no-cve

# Use an NVD API key for faster/less rate-limited CVE lookups
# (get one free at https://nvd.nist.gov/developers/request-an-api-key)
python3 netscan.py 10.0.0.5 --nvd-api-key YOUR_KEY

# Scan a small subnet (max /24)
python3 netscan.py 10.0.0.0/29 --ports top20

# Force a specific engine
python3 netscan.py 10.0.0.5 --engine nmap
python3 netscan.py 10.0.0.5 --engine socket

# Skip the interactive authorization prompt (for scripting/CI)
python3 netscan.py 10.0.0.5 --yes
```


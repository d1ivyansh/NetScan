#!/usr/bin/env python3
"""
NetScan — Network, Service, OS & CVE Vulnerability Scanner
=============================================================

A defensive security reconnaissance tool. Given a target (hostname/IP or a
list of them), it will:

  1. Resolve and ping the target
  2. Scan TCP ports (fast multithreaded connect scan, or nmap if installed)
  3. Detect running services + versions (banner grabbing, or nmap -sV)
  4. Guess the operating system (TTL heuristic, or nmap -O if run as root)
  5. Look up known CVEs for each detected service/version via the NVD API
  6. Report CVSS scores / severities and produce console, JSON, and HTML output

LEGAL / ETHICAL NOTICE
-----------------------
Only scan systems you own or have explicit written authorization to test.
Unauthorized port scanning and vulnerability probing may be illegal under
laws such as the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse
Act, or equivalent legislation elsewhere. This tool performs detection and
reporting ONLY — it does not exploit, brute-force, or attack anything.

Install:
    pip install requests

Optional (greatly improves accuracy of service/OS detection):
    sudo apt install nmap        # Debian/Ubuntu
    brew install nmap            # macOS

Usage examples:
    python3 netscan.py 192.168.1.10
    python3 netscan.py scanme.nmap.org --ports top100
    python3 netscan.py 10.0.0.5 --ports 1-1024 --json out.json --html out.html
    python3 netscan.py example.com --no-cve            # skip CVE lookups
    python3 netscan.py 10.0.0.0/24 --ports top20        # scan a subnet
    python3 netscan.py 10.0.0.5 --nvd-api-key YOUR_KEY  # faster CVE lookups

    # Full URLs are parsed automatically — scheme + custom port are extracted
    # and that port is scanned/connected to even if it's not in --ports:
    python3 netscan.py https://pentest-ground.com:4280
    python3 netscan.py http://10.0.0.5:8080 https://10.0.0.5:8443  # multiple targets, each its own port
    python3 netscan.py example.com:9443                            # host:port shorthand also works
"""

import argparse
import ipaddress
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("Missing dependency 'requests'. Install with: pip install requests")
    sys.exit(1)

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# port -> default service guess (used when no banner can be read)
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 587: "smtp-submission", 631: "ipp",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2375: "docker", 27017: "mongodb",
    3000: "http-alt", 3268: "ldap-gc", 3306: "mysql", 3389: "rdp",
    5000: "http-alt", 5432: "postgresql", 5900: "vnc", 5984: "couchdb",
    6379: "redis", 6443: "kubernetes-api", 7001: "weblogic",
    8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9090: "prometheus", 9200: "elasticsearch", 9300: "elasticsearch-cluster",
    11211: "memcached", 27018: "mongodb", 50000: "sap",
}

TOP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
                143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

TOP_100_PORTS = sorted(set(TOP_20_PORTS + [
    20, 26, 37, 79, 81, 88, 106, 113, 119, 144, 179, 199, 254, 255, 280,
    311, 366, 389, 427, 444, 458, 465, 514, 515, 543, 544, 548, 554, 587,
    631, 646, 873, 990, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720,
    1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3001, 3128, 3268,
    3300, 3389, 3986, 4000, 4001, 4045, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 6000, 6001, 6646, 7000,
    7070, 7937, 7938, 8000, 8002, 8008, 8009, 8010, 8031, 8443, 8888,
    9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]))

CVE_REQUEST_DELAY_NO_KEY = 6.5   # seconds; NVD allows ~5 req / 30s without a key
CVE_REQUEST_DELAY_KEY = 0.7      # NVD allows ~50 req / 30s with a key


# --------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------

@dataclass
class CVEResult:
    cve_id: str
    score: float
    severity: str
    vector: str
    description: str
    published: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    cpe: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class ScanReport:
    target: str
    ip: str = ""
    hostname: str = ""
    scan_start: str = ""
    scan_end: str = ""
    duration_seconds: float = 0.0
    os_guess: str = ""
    os_accuracy: str = ""
    scan_engine: str = "socket"  # 'socket' or 'nmap'
    open_ports: list = field(default_factory=list)         # list[PortResult]
    vulnerabilities: dict = field(default_factory=dict)    # port(str) -> list[CVEResult]

    def to_dict(self):
        return {
            **{k: v for k, v in asdict(self).items() if k not in ("open_ports", "vulnerabilities")},
            "open_ports": [p.to_dict() if isinstance(p, PortResult) else p for p in self.open_ports],
            "vulnerabilities": {
                port: [c.to_dict() if isinstance(c, CVEResult) else c for c in cves]
                for port, cves in self.vulnerabilities.items()
            },
        }


# --------------------------------------------------------------------------
# Port / service / OS scanning
# --------------------------------------------------------------------------

class NetworkScanner:
    def __init__(self, target, ports=None, timeout=1.2, threads=200,
                 use_nmap="auto", verbose=True, https_ports=None, http_ports=None):
        self.target = target
        self.ports = ports or TOP_20_PORTS
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        # Ports we should probe as HTTPS/HTTP even if they aren't in the
        # hardcoded COMMON_PORTS list — populated from URL targets like
        # https://pentest-ground.com:4280, where 4280 isn't a "standard" port.
        self.https_ports = set(https_ports or []) | {443, 8443}
        self.http_ports = set(http_ports or []) | {80, 8080, 8000, 8008, 8888, 3000, 5000, 9000}
        self.nmap_path = shutil.which("nmap")
        if use_nmap == "auto":
            self.use_nmap = self.nmap_path is not None
        elif use_nmap is True:
            if not self.nmap_path:
                raise RuntimeError("nmap was requested but is not installed/on PATH")
            self.use_nmap = True
        else:
            self.use_nmap = False

    def log(self, msg):
        if self.verbose:
            print(f"[*] {msg}", file=sys.stderr)

    def resolve(self):
        try:
            ip = socket.gethostbyname(self.target)
        except socket.gaierror as e:
            raise RuntimeError(f"Could not resolve target '{self.target}': {e}")
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            hostname = ""
        return ip, hostname

    # ---- socket-based fallback scan (no nmap required) -------------------

    def _connect_scan_port(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((ip, port))
                if result != 0:
                    return None
                banner = self._grab_banner(s, port, ip)
        except (socket.timeout, OSError):
            return None
        service, product, version = self._parse_banner(port, banner)
        if service in ("", "unknown"):
            # Even on a non-standard port, if the URL told us the scheme
            # (e.g. https://pentest-ground.com:4280), label it accordingly.
            if port in self.https_ports:
                service = "https"
            elif port in self.http_ports:
                service = "http"
        return PortResult(port=port, state="open", service=service,
                           product=product, version=version, banner=banner[:200])

    def _grab_banner(self, sock, port, ip):
        """Try to read a service banner; for HTTP(S)-like ports, send a probe.

        Uses self.http_ports / self.https_ports (which include both the
        common well-known ports AND any explicit port pulled from a URL
        target, e.g. 4280 from https://pentest-ground.com:4280) rather than
        a fixed tuple, so non-standard ports are still probed correctly.
        """
        try:
            sock.settimeout(self.timeout)
            if port in self.https_ports:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                        req = f"HEAD / HTTP/1.0\r\nHost: {self.target}\r\n\r\n".encode()
                        ssock.sendall(req)
                        data = ssock.recv(2048)
                        cert_info = ""
                        try:
                            cert = ssock.getpeercert(binary_form=False)
                            if cert:
                                cert_info = f" [TLS cert: {cert.get('subject', '')}]"
                        except Exception:
                            pass
                        return data.decode(errors="ignore") + cert_info
                except (ssl.SSLError, OSError):
                    # Wasn't actually TLS on this port — fall through to plain probe
                    return ""
            if port in self.http_ports:
                req = f"HEAD / HTTP/1.0\r\nHost: {self.target}\r\n\r\n".encode()
                sock.sendall(req)
                data = sock.recv(2048)
                return data.decode(errors="ignore")
            # default: many services (SSH, FTP, SMTP) announce themselves first
            data = sock.recv(1024)
            return data.decode(errors="ignore")
        except Exception:
            return ""

    @staticmethod
    def _parse_banner(port, banner):
        service = COMMON_PORTS.get(port, "unknown")
        product, version = "", ""
        if not banner:
            return service, product, version

        patterns = [
            (r"SSH-[\d.]+-(OpenSSH)[_-]([\w.]+)", "openssh"),
            (r"Server:\s*nginx/?([\w.]*)", "nginx"),
            (r"Server:\s*Apache/?([\w.]*)", "apache"),
            (r"Server:\s*Microsoft-IIS/?([\w.]*)", "iis"),
            (r"220.*?ProFTPD\s+([\w.]+)", "proftpd"),
            (r"220.*?vsFTPd\s+([\w.]+)", "vsftpd"),
            (r"220.*?Postfix", "postfix"),
            (r"\+OK.*?Dovecot", "dovecot"),
            (r"MySQL.*?([\d.]+)", "mysql"),
            (r"Redis", "redis"),
        ]
        for pat, name in patterns:
            m = re.search(pat, banner, re.IGNORECASE)
            if m:
                product = name
                version = m.group(1) if m.groups() and m.lastindex and len(m.groups()) >= 1 else ""
                version = version if version and version[0].isdigit() else ""
                break

        if not product:
            m = re.search(r"Server:\s*([^\r\n]+)", banner, re.IGNORECASE)
            if m:
                product = m.group(1).strip()
            else:
                m = re.search(r"^(SSH-[\d.]+-[^\r\n]+)", banner)
                if m:
                    product = m.group(1).strip()

        return service, product, version

    def socket_scan(self):
        ip, hostname = self.resolve()
        self.log(f"Resolved {self.target} -> {ip}  (rDNS: {hostname or 'n/a'})")
        self.log(f"Scanning {len(self.ports)} ports with {self.threads} threads...")
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._connect_scan_port, ip, p): p for p in self.ports}
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    open_ports.append(res)
                    self.log(f"  open: {res.port}/tcp  {res.service}  {res.product} {res.version}".rstrip())
        open_ports.sort(key=lambda r: r.port)
        os_guess, os_acc = self._ttl_os_guess(ip)
        return ip, hostname, open_ports, os_guess, os_acc

    def _ttl_os_guess(self, ip):
        """Very rough OS guess from ICMP TTL. No root/raw-socket needed: shells out to `ping`."""
        try:
            if sys.platform.startswith("win"):
                cmd = ["ping", "-n", "1", "-w", "1500", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "2", ip]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
            m = re.search(r"ttl[=:](\d+)", out, re.IGNORECASE)
            if not m:
                return "unknown", "low (no ICMP reply)"
            ttl = int(m.group(1))
            if ttl <= 64:
                return "Linux/Unix (or macOS)", f"heuristic, TTL={ttl}"
            elif ttl <= 128:
                return "Windows", f"heuristic, TTL={ttl}"
            else:
                return "Network device (router/switch)", f"heuristic, TTL={ttl}"
        except Exception:
            return "unknown", "n/a"

    # ---- nmap-backed scan (preferred when available) ----------------------

    def nmap_scan(self, want_os=True):
        ip, hostname = self.resolve()
        port_spec = ",".join(str(p) for p in self.ports)
        args = ["nmap", "-Pn", "-sV", "-p", port_spec, "-oX", "-", self.target]
        # OS detection (-O) needs root privileges; only add it if we can use it
        can_root = (hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0)
        if want_os and can_root:
            args.insert(1, "-O")
        self.log(f"Running: {' '.join(args)}")
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=300)
        except FileNotFoundError:
            raise RuntimeError("nmap not found on PATH")
        except subprocess.TimeoutExpired:
            raise RuntimeError("nmap scan timed out")
        if proc.returncode != 0 and not proc.stdout:
            raise RuntimeError(f"nmap failed: {proc.stderr.strip()}")

        return self._parse_nmap_xml(proc.stdout, ip, hostname, want_os, can_root,
                                     self.https_ports, self.http_ports)

    @staticmethod
    def _parse_nmap_xml(xml_text, ip, hostname, want_os, had_root, https_ports=(), http_ports=()):
        root = ET.fromstring(xml_text)
        host = root.find("host")
        open_ports = []
        os_guess, os_acc = "unknown", "n/a"

        if host is not None:
            ports_el = host.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    port_num = int(port_el.get("portid"))
                    proto = port_el.get("protocol", "tcp")
                    svc = port_el.find("service")
                    service = svc.get("name", "") if svc is not None else ""
                    product = svc.get("product", "") if svc is not None else ""
                    version = svc.get("version", "") if svc is not None else ""
                    extra = svc.get("extrainfo", "") if svc is not None else ""
                    tunnel = svc.get("tunnel", "") if svc is not None else ""
                    cpe_el = svc.find("cpe") if svc is not None else None
                    cpe = cpe_el.text if cpe_el is not None else ""
                    banner = " ".join(filter(None, [product, version, extra]))
                    if tunnel == "ssl" and service and not service.startswith("https") \
                            and not service.startswith("ssl"):
                        # nmap reports e.g. name="http" tunnel="ssl" for TLS on a
                        # non-standard port (like 4280) — surface that clearly.
                        service = f"https ({service} over TLS)"
                    if not service:
                        # Fall back to the URL-derived scheme hint (e.g. for
                        # https://host:4280, nmap's own probe is usually right,
                        # but if it comes back empty, use what we already know).
                        if port_num in https_ports:
                            service = "https"
                        elif port_num in http_ports:
                            service = "http"
                    open_ports.append(PortResult(port=port_num, protocol=proto, state="open",
                                                  service=service, product=product,
                                                  version=version, banner=banner, cpe=cpe or ""))

            os_el = host.find("os")
            if os_el is not None:
                match = os_el.find("osmatch")
                if match is not None:
                    os_guess = match.get("name", "unknown")
                    os_acc = f"{match.get('accuracy', '?')}% confidence (nmap -O)"
            if os_guess == "unknown":
                if want_os and not had_root:
                    os_acc = "OS detection (-O) requires root/administrator privileges; skipped"
                else:
                    os_acc = "no match"

        open_ports.sort(key=lambda r: r.port)
        return ip, hostname, open_ports, os_guess, os_acc

    # ---- top-level entry point --------------------------------------------

    def scan(self):
        start = datetime.now(timezone.utc)
        if self.use_nmap:
            try:
                self.log("Using nmap engine")
                ip, hostname, open_ports, os_guess, os_acc = self.nmap_scan()
                engine = "nmap"
            except Exception as e:
                self.log(f"nmap engine failed ({e}); falling back to socket scan")
                ip, hostname, open_ports, os_guess, os_acc = self.socket_scan()
                engine = "socket"
        else:
            ip, hostname, open_ports, os_guess, os_acc = self.socket_scan()
            engine = "socket"
        end = datetime.now(timezone.utc)

        report = ScanReport(
            target=self.target, ip=ip, hostname=hostname,
            scan_start=start.isoformat(), scan_end=end.isoformat(),
            duration_seconds=round((end - start).total_seconds(), 2),
            os_guess=os_guess, os_accuracy=os_acc, scan_engine=engine,
            open_ports=open_ports,
        )
        return report


# --------------------------------------------------------------------------
# CVE lookup against the NVD (National Vulnerability Database) REST API
# --------------------------------------------------------------------------

class CVELookup:
    def __init__(self, api_key=None, max_results=5, verbose=True):
        self.api_key = api_key
        self.max_results = max_results
        self.delay = CVE_REQUEST_DELAY_KEY if api_key else CVE_REQUEST_DELAY_NO_KEY
        self.verbose = verbose
        self._last_request = 0.0

    def log(self, msg):
        if self.verbose:
            print(f"[*] {msg}", file=sys.stderr)

    def _throttle(self):
        elapsed = time.time() - self._last_request
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_request = time.time()

    def search(self, product, version="", cpe=""):
        """Search NVD for CVEs matching a product (+ version), or an exact CPE
        string if one is available (e.g. from nmap's service detection) —
        CPE matching is far more precise than free-text keyword search."""
        if cpe:
            results = self._search_by_cpe(cpe)
            if results:
                return results
            # fall through to keyword search if the CPE had no direct matches

        if not product or product == "unknown":
            return []
        keyword = f"{product} {version}".strip()
        return self._search_by_keyword(keyword)

    def _search_by_cpe(self, cpe):
        params = {"cpeName": cpe, "resultsPerPage": self.max_results}
        headers = {"apiKey": self.api_key} if self.api_key else {}
        self._throttle()
        try:
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
        except requests.RequestException as e:
            self.log(f"CVE lookup failed for CPE '{cpe}': {e}")
            return []
        if resp.status_code == 403:
            self.log("NVD API rate-limited (403). Consider using --nvd-api-key, or re-run later.")
            return []
        if resp.status_code != 200:
            self.log(f"NVD API returned {resp.status_code} for CPE '{cpe}'")
            return []
        try:
            data = resp.json()
        except ValueError:
            return []
        return self._parse_nvd_response(data)

    def _search_by_keyword(self, keyword):
        params = {"keywordSearch": keyword, "resultsPerPage": self.max_results}
        headers = {"apiKey": self.api_key} if self.api_key else {}

        self._throttle()
        try:
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
        except requests.RequestException as e:
            self.log(f"CVE lookup failed for '{keyword}': {e}")
            return []

        if resp.status_code == 403:
            self.log("NVD API rate-limited (403). Consider using --nvd-api-key, "
                      "or re-run later.")
            return []
        if resp.status_code != 200:
            self.log(f"NVD API returned {resp.status_code} for '{keyword}'")
            return []

        try:
            data = resp.json()
        except ValueError:
            return []
        return self._parse_nvd_response(data)

    def _parse_nvd_response(self, data):
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            score, severity, vector = self._extract_cvss(cve.get("metrics", {}))
            published = cve.get("published", "")
            results.append(CVEResult(cve_id=cve_id, score=score, severity=severity,
                                      vector=vector, description=desc[:300],
                                      published=published))
        results.sort(key=lambda c: c.score, reverse=True)
        return results

    @staticmethod
    def _extract_cvss(metrics):
        # Prefer CVSS v3.1, then v3.0, then v2
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                cvss = entries[0].get("cvssData", {})
                score = cvss.get("baseScore", 0.0)
                severity = cvss.get("baseSeverity", entries[0].get("baseSeverity", ""))
                vector = cvss.get("vectorString", "")
                if not severity:
                    severity = severity_from_score(score)
                return float(score), severity, vector
        return 0.0, "UNKNOWN", ""


def severity_from_score(score):
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


# --------------------------------------------------------------------------
# Output / reporting
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}


def print_report(report: ScanReport):
    print("\n" + "=" * 72)
    print(f" NetScan Report — {report.target} ({report.ip})")
    print("=" * 72)
    print(f" Hostname (rDNS) : {report.hostname or 'n/a'}")
    print(f" Scan engine     : {report.scan_engine}")
    print(f" Duration        : {report.duration_seconds}s")
    print(f" OS guess        : {report.os_guess}  [{report.os_accuracy}]")
    print(f" Open ports      : {len(report.open_ports)}")
    print("-" * 72)

    if not report.open_ports:
        print(" No open ports found in the scanned range.")
    for p in report.open_ports:
        svc = f"{p.service}"
        if p.product:
            svc += f"  ({p.product} {p.version})".rstrip(") ").rstrip() + (")" if p.product else "")
        print(f"  {p.port:>6}/{p.protocol:<4} open   {svc}")
        cves = report.vulnerabilities.get(str(p.port), [])
        if cves:
            for c in sorted(cves, key=lambda c: SEVERITY_ORDER.get(c.severity, 9)):
                print(f"           └─ {c.cve_id}  CVSS {c.score:>4} [{c.severity:<8}]  {c.description[:90]}...")
        elif p.product:
            print(f"           └─ no CVEs found for '{p.product} {p.version}'")
    print("=" * 72)

    # summary
    all_cves = [c for cves in report.vulnerabilities.values() for c in cves]
    if all_cves:
        counts = {}
        for c in all_cves:
            counts[c.severity] = counts.get(c.severity, 0) + 1
        summary = "  ".join(f"{k}: {v}" for k, v in sorted(counts.items(),
                             key=lambda kv: SEVERITY_ORDER.get(kv[0], 9)))
        print(f" Vulnerability summary: {summary}  (total: {len(all_cves)})")
    else:
        print(" Vulnerability summary: none found / no CVE lookup performed")
    print()


def save_json(report: ScanReport, path):
    with open(path, "w") as f:
        json.dump(report.to_dict(), f, indent=2)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NetScan Report — {target}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; background:#0f1117; color:#e6e6e6; margin:0; padding:32px; }}
  h1 {{ font-size:22px; }}
  .meta {{ color:#9aa0a6; margin-bottom:24px; }}
  table {{ width:100%; border-collapse:collapse; margin-bottom:24px; }}
  th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #2a2d35; font-size:14px; }}
  th {{ color:#9aa0a6; font-weight:600; }}
  .CRITICAL {{ color:#ff4d4f; font-weight:700; }}
  .HIGH {{ color:#ff8c42; font-weight:700; }}
  .MEDIUM {{ color:#ffd23f; }}
  .LOW {{ color:#8bd17c; }}
  .NONE, .UNKNOWN {{ color:#9aa0a6; }}
  .port-row td {{ background:#171a21; }}
  .cve-row td {{ background:#11131a; font-size:13px; color:#c7c9cf; }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:10px; background:#1f232c; font-size:12px; }}
</style>
</head>
<body>
  <h1>NetScan Report — {target} ({ip})</h1>
  <div class="meta">
    Hostname: {hostname} &nbsp;|&nbsp; Engine: {engine} &nbsp;|&nbsp;
    OS guess: {os_guess} ({os_acc}) &nbsp;|&nbsp; Duration: {duration}s &nbsp;|&nbsp;
    Generated: {generated}
  </div>
  <table>
    <tr><th>Port</th><th>Service</th><th>Product / Version</th><th>CVE</th><th>CVSS</th><th>Severity</th></tr>
    {rows}
  </table>
</body>
</html>
"""


def save_html(report: ScanReport, path):
    rows = []
    for p in report.open_ports:
        cves = report.vulnerabilities.get(str(p.port), [])
        if not cves:
            rows.append(
                f'<tr class="port-row"><td>{p.port}/{p.protocol}</td><td>{p.service}</td>'
                f'<td>{p.product} {p.version}</td><td colspan="3">no known CVEs found</td></tr>'
            )
            continue
        first = True
        for c in sorted(cves, key=lambda c: SEVERITY_ORDER.get(c.severity, 9)):
            if first:
                rows.append(
                    f'<tr class="port-row"><td rowspan="{len(cves)}">{p.port}/{p.protocol}</td>'
                    f'<td rowspan="{len(cves)}">{p.service}</td>'
                    f'<td rowspan="{len(cves)}">{p.product} {p.version}</td>'
                    f'<td>{c.cve_id}</td><td>{c.score}</td>'
                    f'<td class="{c.severity}">{c.severity}</td></tr>'
                )
                first = False
            else:
                rows.append(
                    f'<tr class="cve-row"><td>{c.cve_id}</td><td>{c.score}</td>'
                    f'<td class="{c.severity}">{c.severity}</td></tr>'
                )

    html = HTML_TEMPLATE.format(
        target=report.target, ip=report.ip, hostname=report.hostname or "n/a",
        engine=report.scan_engine, os_guess=report.os_guess, os_acc=report.os_accuracy,
        duration=report.duration_seconds,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        rows="\n".join(rows) if rows else "<tr><td colspan='6'>No open ports found</td></tr>",
    )
    with open(path, "w") as f:
        f.write(html)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_ports_arg(arg):
    if arg == "top20":
        return TOP_20_PORTS
    if arg == "top100":
        return TOP_100_PORTS
    if arg == "all":
        return list(range(1, 65536))
    ports = []
    for chunk in arg.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            a, b = chunk.split("-")
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(chunk))
    return sorted(set(ports))


def parse_target_spec(raw):
    """
    Accepts a plain host/IP, a 'host:port' shorthand, or a full URL such as
    'https://pentest-ground.com:4280' or 'http://10.0.0.5:8080/some/path'.

    Returns (host, explicit_port_or_None, scheme_or_None).

    Examples:
        'pentest-ground.com'                  -> ('pentest-ground.com', None, None)
        'pentest-ground.com:4280'              -> ('pentest-ground.com', 4280, None)
        'https://pentest-ground.com:4280'      -> ('pentest-ground.com', 4280, 'https')
        'http://10.0.0.5'                      -> ('10.0.0.5', 80, 'http')
        'https://10.0.0.5'                     -> ('10.0.0.5', 443, 'https')
        '10.0.0.5'                             -> ('10.0.0.5', None, None)
    """
    raw = raw.strip()

    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname
        if not host:
            raise ValueError(f"Could not parse host from URL: {raw}")
        scheme = parsed.scheme.lower()
        port = parsed.port
        if port is None:
            port = 443 if scheme == "https" else 80 if scheme == "http" else None
        return host, port, scheme

    # IPv6 literal in brackets, e.g. [::1]:8080 — leave host as-is, just split port
    if raw.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", raw)
        if m:
            return m.group(1), (int(m.group(2)) if m.group(2) else None), None

    # bare 'host:port' shorthand (exactly one colon, numeric port)
    if raw.count(":") == 1:
        host, _, port_str = raw.partition(":")
        if port_str.isdigit() and host:
            return host, int(port_str), None

    return raw, None, None


def expand_targets(host):
    """Support a single host, or a CIDR range (e.g. 10.0.0.0/29) for small subnets."""
    try:
        net = ipaddress.ip_network(host, strict=False)
        if net.num_addresses > 1:
            if net.num_addresses > 256:
                raise SystemExit("Refusing to scan a network larger than /24 in one run.")
            return [str(ip) for ip in net.hosts()]
    except ValueError:
        pass
    return [host]


def main():
    ap = argparse.ArgumentParser(
        description="NetScan — port/service/OS scanner with CVE lookup (authorized testing only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("targets", nargs="+",
                     help="One or more targets: hostname, IP, small CIDR range (e.g. 10.0.0.0/29), "
                          "'host:port', or a full URL like 'https://pentest-ground.com:4280'. "
                          "When a target specifies a port (via URL or host:port), that port is "
                          "always connected to/scanned, even if it isn't in --ports.")
    ap.add_argument("--ports", default="top20",
                     help="Ports to scan: 'top20' (default), 'top100', 'all', or e.g. '22,80,443' or '1-1024'. "
                          "Any explicit port parsed from a target URL is added on top of this.")
    ap.add_argument("--timeout", type=float, default=1.2, help="Per-port connect timeout in seconds (socket engine)")
    ap.add_argument("--threads", type=int, default=200, help="Thread pool size for socket engine")
    ap.add_argument("--engine", choices=["auto", "nmap", "socket"], default="auto",
                     help="Scan engine: auto-detect (default), force nmap, or force pure-Python socket scan")
    ap.add_argument("--no-cve", action="store_true", help="Skip CVE/NVD lookups (faster, no internet needed for that step)")
    ap.add_argument("--nvd-api-key", default=None, help="NVD API key for higher rate limits (optional)")
    ap.add_argument("--max-cves", type=int, default=5, help="Max CVEs to fetch per service (default 5)")
    ap.add_argument("--json", metavar="PATH", help="Write JSON report to this path")
    ap.add_argument("--html", metavar="PATH", help="Write HTML report to this path")
    ap.add_argument("--quiet", action="store_true", help="Suppress progress logging on stderr")
    ap.add_argument("--yes", action="store_true",
                     help="Confirm you are authorized to scan this target (skips interactive prompt)")
    args = ap.parse_args()

    # Parse every target spec up front (URL / host:port / plain host) so we know
    # the real hostnames before asking for authorization confirmation.
    parsed_specs = []  # list of (raw, host, explicit_port, scheme)
    for raw in args.targets:
        try:
            host, explicit_port, scheme = parse_target_spec(raw)
        except ValueError as e:
            print(f"[!] Skipping invalid target '{raw}': {e}", file=sys.stderr)
            continue
        parsed_specs.append((raw, host, explicit_port, scheme))

    if not parsed_specs:
        print("[!] No valid targets given.", file=sys.stderr)
        sys.exit(1)

    print("=" * 72, file=sys.stderr)
    print(" NetScan — only scan systems you own or are explicitly authorized to test.", file=sys.stderr)
    print("=" * 72, file=sys.stderr)
    if not args.yes:
        names = ", ".join(raw for raw, *_ in parsed_specs)
        try:
            confirm = input(f"Confirm you are authorized to scan: {names} [y/N]: ").strip().lower()
        except EOFError:
            confirm = ""
        if confirm != "y":
            print("Aborted.", file=sys.stderr)
            sys.exit(1)

    base_ports = parse_ports_arg(args.ports)
    verbose = not args.quiet

    cve_lookup = None if args.no_cve else CVELookup(api_key=args.nvd_api_key,
                                                      max_results=args.max_cves,
                                                      verbose=verbose)

    engine_choice = (True if args.engine == "nmap" else
                      False if args.engine == "socket" else "auto")

    all_reports = []
    for raw, host, explicit_port, scheme in parsed_specs:
        # Each target gets the shared --ports list, PLUS its own explicit port
        # (from a URL like :4280 or a host:port spec) merged in and marked so
        # banner-grabbing knows to treat it as HTTP/HTTPS regardless of port number.
        ports = list(base_ports)
        https_ports, http_ports = [], []
        if explicit_port is not None:
            if explicit_port not in ports:
                ports = sorted(set(ports) | {explicit_port})
            if scheme == "https":
                https_ports.append(explicit_port)
            elif scheme == "http":
                http_ports.append(explicit_port)
            if verbose:
                label = f" ({scheme})" if scheme else ""
                print(f"[*] {raw}: connecting on explicit port {explicit_port}{label}", file=sys.stderr)

        for t in expand_targets(host):
            scanner = NetworkScanner(t, ports=ports, timeout=args.timeout,
                                      threads=args.threads, use_nmap=engine_choice,
                                      verbose=verbose, https_ports=https_ports,
                                      http_ports=http_ports)
            try:
                report = scanner.scan()
            except RuntimeError as e:
                print(f"[!] {t}: {e}", file=sys.stderr)
                continue

            if cve_lookup:
                for p in report.open_ports:
                    product = p.product or p.service
                    if not product or product == "unknown":
                        continue
                    if verbose:
                        hint = p.cpe if p.cpe else f"{product} {p.version}"
                        print(f"[*] Looking up CVEs for '{hint}'...", file=sys.stderr)
                    cves = cve_lookup.search(product, p.version, cpe=p.cpe)
                    if cves:
                        report.vulnerabilities[str(p.port)] = cves

            print_report(report)
            all_reports.append(report)

    if args.json:
        if len(all_reports) == 1:
            save_json(all_reports[0], args.json)
        else:
            with open(args.json, "w") as f:
                json.dump([r.to_dict() for r in all_reports], f, indent=2)
        print(f"[+] JSON report saved to {args.json}", file=sys.stderr)

    if args.html:
        if len(all_reports) == 1:
            save_html(all_reports[0], args.html)
            print(f"[+] HTML report saved to {args.html}", file=sys.stderr)
        else:
            print("[!] --html currently supports a single target only; skipping.", file=sys.stderr)


if __name__ == "__main__":
    main()

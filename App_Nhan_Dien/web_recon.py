#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         WEB RECON - Trích Xuất Đặc Trưng Kỹ Thuật          ║
║              Website Technical Feature Extractor             ║
║                  Tối ưu cho Kali Linux                       ║
╚══════════════════════════════════════════════════════════════╝

Tác giả: Web Recon Tool
Phụ thuộc: requests, beautifulsoup4, colorama (pip install ...)
Kali Linux: nmap, whois, dig, curl sẽ được dùng tự động nếu có
"""

import sys
import os
import socket
import ssl
import json
import re
import time
import subprocess
import urllib.parse
import http.client
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# ─── Kiểm tra & import thư viện tuỳ chọn ───────────────────────────────────
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class _Dummy:
        def __getattr__(self, _): return ""
    Fore = Back = Style = _Dummy()


# ═══════════════════════════════════════════════════════════════════════════════
#  MÀU SẮC & HIỂN THỊ
# ═══════════════════════════════════════════════════════════════════════════════

def c(text, color="", bold=False):
    if not HAS_COLOR:
        return text
    b = Style.BRIGHT if bold else ""
    return f"{b}{color}{text}{Style.RESET_ALL}"

def print_banner():
    banner = f"""
{c('╔══════════════════════════════════════════════════════════════════════╗', Fore.CYAN, True)}
{c('║', Fore.CYAN, True)}  {c('██╗    ██╗███████╗██████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗', Fore.GREEN, True)}  {c('║', Fore.CYAN, True)}
{c('║', Fore.CYAN, True)}  {c('██║    ██║██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══╝ ████╗', Fore.GREEN, True)}  {c('║', Fore.CYAN, True)}
{c('║', Fore.CYAN, True)}  {c('██║ █╗ ██║█████╗  ██████╔╝    ██████╔╝█████╗  ██║     ██║  ██╗██╔██╗', Fore.GREEN, True)} {c('║', Fore.CYAN, True)}
{c('║', Fore.CYAN, True)}  {c('██║███╗██║██╔══╝  ██╔══██╗    ██╔══██╗██╔══╝  ██║     ██║   ██║  ██╗', Fore.GREEN, True)} {c('║', Fore.CYAN, True)}
{c('║', Fore.CYAN, True)}  {c('╚███╔███╔╝███████╗██████╔╝    ██║  ██║███████╗╚██████╗╚██████╔╝██████╗', Fore.GREEN, True)}{c('║', Fore.CYAN, True)}
{c('╠══════════════════════════════════════════════════════════════════════╣', Fore.CYAN, True)}
{c('║', Fore.CYAN, True)}  {c('🔍 Trích Xuất Đặc Trưng Kỹ Thuật Website | Kali Linux Edition', Fore.YELLOW, True)}      {c('║', Fore.CYAN, True)}
{c('╚══════════════════════════════════════════════════════════════════════╝', Fore.CYAN, True)}
"""
    print(banner)

def section(title, icon="▶"):
    width = 65
    line = "─" * width
    print(f"\n{c(line, Fore.BLUE)}")
    print(f"{c(icon, Fore.YELLOW, True)}  {c(title, Fore.WHITE, True)}")
    print(f"{c(line, Fore.BLUE)}")

def result(label, value, status="ok"):
    colors = {"ok": Fore.GREEN, "warn": Fore.YELLOW, "err": Fore.RED, "info": Fore.CYAN}
    icons  = {"ok": "✔", "warn": "⚠", "err": "✘", "info": "ℹ"}
    col = colors.get(status, Fore.WHITE)
    ico = icons.get(status, "•")
    label_str = c(f"{label:<28}", Fore.WHITE)
    val_str   = c(str(value), col)
    print(f"  {c(ico, col)}  {label_str} {val_str}")

def subitem(text, bullet="  ·"):
    print(f"     {c(bullet, Fore.BLUE)} {c(text, Fore.CYAN)}")


# ═══════════════════════════════════════════════════════════════════════════════
#  TIỆN ÍCH
# ═══════════════════════════════════════════════════════════════════════════════

def run_cmd(cmd: List[str], timeout=10) -> Tuple[str, str, int]:
    """Chạy lệnh hệ thống, trả về (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, errors='replace')
        return proc.stdout, proc.stderr, proc.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
        return "", str(e), -1

def tool_available(name: str) -> bool:
    out, _, rc = run_cmd(["which", name])
    return rc == 0 and bool(out.strip())

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def extract_host(url: str) -> str:
    return urllib.parse.urlparse(url).hostname or url


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 1: THÔNG TIN CƠ BẢN & HTTP HEADERS
# ═══════════════════════════════════════════════════════════════════════════════

def get_http_info(url: str, results: dict):
    section("HTTP / HTTPS - Headers & Phản Hồi", "🌐")
    data = {}

    if HAS_REQUESTS:
        try:
            start = time.time()
            resp = requests.get(url, timeout=10, verify=False,
                                allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 WebRecon/1.0"})
            elapsed = round((time.time() - start) * 1000, 2)

            data["status_code"]    = resp.status_code
            data["response_time_ms"] = elapsed
            data["final_url"]      = resp.url
            data["headers"]        = dict(resp.headers)
            data["content_length"] = len(resp.content)
            data["encoding"]       = resp.encoding

            st = "ok" if resp.status_code < 400 else "warn"
            result("Status Code", f"{resp.status_code} {resp.reason}", st)
            result("Thời gian phản hồi", f"{elapsed} ms",
                   "ok" if elapsed < 1000 else "warn")
            result("URL cuối (sau redirect)", resp.url, "info")
            result("Kích thước nội dung", f"{len(resp.content):,} bytes", "info")
            result("Encoding", resp.encoding or "Không xác định", "info")

            print(f"\n  {c('📋 HTTP Headers:', Fore.YELLOW, True)}")
            security_headers = {
                "Strict-Transport-Security": ("HSTS", "ok"),
                "Content-Security-Policy":   ("CSP",  "ok"),
                "X-Frame-Options":           ("Clickjacking Protection", "ok"),
                "X-Content-Type-Options":    ("MIME Sniffing Protection", "ok"),
                "X-XSS-Protection":          ("XSS Protection", "ok"),
                "Referrer-Policy":           ("Referrer Policy", "ok"),
                "Permissions-Policy":        ("Permissions Policy", "ok"),
            }
            missing_sec = []
            for h, v in resp.headers.items():
                subitem(f"{c(h, Fore.WHITE, True)}: {v}")
                if h in security_headers:
                    security_headers.pop(h, None)
            for h in security_headers:
                missing_sec.append(h)

            data["missing_security_headers"] = missing_sec

        except requests.exceptions.SSLError as e:
            result("SSL Error", str(e)[:80], "err")
        except requests.exceptions.ConnectionError as e:
            result("Kết nối thất bại", str(e)[:80], "err")
        except Exception as e:
            result("Lỗi HTTP", str(e)[:80], "err")
    else:
        result("requests", "Chưa cài đặt – dùng curl", "warn")
        out, err, rc = run_cmd(["curl", "-sI", "--max-time", "10", url])
        if rc == 0:
            print(c(out, Fore.CYAN))
            data["curl_headers"] = out
        else:
            result("curl", err[:80], "err")

    results["http"] = data


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 2: BẢO MẬT HEADERS
# ═══════════════════════════════════════════════════════════════════════════════

def check_security_headers(results: dict):
    section("Kiểm Tra Security Headers", "🛡️")
    headers = results.get("http", {}).get("headers", {})
    missing = results.get("http", {}).get("missing_security_headers", [])

    checks = {
        "Strict-Transport-Security": "HSTS - Bắt buộc HTTPS",
        "Content-Security-Policy":   "CSP - Ngăn XSS/injection",
        "X-Frame-Options":           "Clickjacking Protection",
        "X-Content-Type-Options":    "MIME Sniffing Protection",
        "X-XSS-Protection":          "XSS Filter (legacy)",
        "Referrer-Policy":           "Kiểm soát Referrer",
        "Permissions-Policy":        "Giới hạn Browser API",
    }

    score = 0
    for hdr, desc in checks.items():
        if hdr in headers:
            result(desc, f"✔ {headers[hdr][:50]}", "ok")
            score += 1
        else:
            result(desc, "✘ THIẾU", "err")

    grade = "A" if score >= 6 else "B" if score >= 4 else "C" if score >= 2 else "F"
    grade_color = {"A": Fore.GREEN, "B": Fore.YELLOW, "C": Fore.YELLOW, "F": Fore.RED}
    print(f"\n  {c('Điểm Security Headers:', Fore.WHITE, True)} "
          f"{c(f'{score}/{len(checks)} — Grade {grade}', grade_color.get(grade, Fore.WHITE), True)}")
    results["security_score"] = {"score": score, "max": len(checks), "grade": grade}


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 3: SSL / TLS CERTIFICATE
# ═══════════════════════════════════════════════════════════════════════════════

def get_ssl_info(host: str, results: dict):
    section("Chứng Chỉ SSL / TLS", "🔒")
    data = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

        data["tls_version"] = version
        data["cipher"]      = cipher
        data["cert"]        = cert

        result("TLS Version", version, "ok" if "TLS 1.3" in version or "TLS 1.2" in version else "warn")
        result("Cipher Suite", f"{cipher[0]} ({cipher[2]}-bit)", "ok")

        # Subject
        subj = dict(x[0] for x in cert.get("subject", []))
        result("Chủ thể (CN)", subj.get("commonName", "N/A"), "info")
        result("Tổ chức", subj.get("organizationName", "N/A"), "info")

        # Issuer
        issuer = dict(x[0] for x in cert.get("issuer", []))
        result("Nhà phát hành", issuer.get("organizationName", "N/A"), "info")

        # Validity
        not_before = cert.get("notBefore", "")
        not_after  = cert.get("notAfter",  "")
        result("Hiệu lực từ", not_before, "info")
        result("Hết hạn",     not_after,  "info")

        # Expiry check
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp - datetime.utcnow()).days
            st = "ok" if days_left > 30 else "warn" if days_left > 0 else "err"
            result("Còn lại", f"{days_left} ngày", st)
        except Exception:
            pass

        # SANs
        sans = cert.get("subjectAltName", [])
        result("Subject Alt Names", f"{len(sans)} entries", "info")
        for _, v in sans[:5]:
            subitem(v)
        if len(sans) > 5:
            subitem(f"... và {len(sans)-5} SANs khác")

    except ssl.SSLError as e:
        result("SSL Error", str(e)[:80], "err")
    except socket.timeout:
        result("Timeout", "Kết nối SSL hết thời gian", "err")
    except ConnectionRefusedError:
        result("Port 443", "Từ chối kết nối (không có HTTPS?)", "err")
    except Exception as e:
        result("Lỗi SSL", str(e)[:80], "err")

    results["ssl"] = data


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 4: DNS RECORDS
# ═══════════════════════════════════════════════════════════════════════════════

def get_dns_info(host: str, results: dict):
    section("DNS Records", "🌍")
    data = {}

    # Dùng dig nếu có (Kali Linux)
    if tool_available("dig"):
        result("Công cụ DNS", "dig (Kali Linux)", "ok")
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            out, _, rc = run_cmd(["dig", "+short", rtype, host], timeout=8)
            if rc == 0 and out.strip():
                records = [l.strip() for l in out.strip().splitlines() if l.strip()]
                data[rtype] = records
                result(f"Record {rtype}", f"{len(records)} bản ghi", "ok")
                for r in records[:3]:
                    subitem(r)
                if len(records) > 3:
                    subitem(f"... và {len(records)-3} bản ghi khác")
            else:
                result(f"Record {rtype}", "Không có", "info")
    else:
        # Fallback: socket DNS
        result("Công cụ DNS", "socket (dig không có)", "warn")
        try:
            addrs = socket.getaddrinfo(host, None)
            ipv4 = list({a[4][0] for a in addrs if a[0] == socket.AF_INET})
            ipv6 = list({a[4][0] for a in addrs if a[0] == socket.AF_INET6})
            data["A"] = ipv4
            data["AAAA"] = ipv6
            result("IPv4 (A)", ", ".join(ipv4) if ipv4 else "Không có",
                   "ok" if ipv4 else "warn")
            result("IPv6 (AAAA)", ", ".join(ipv6) if ipv6 else "Không có",
                   "ok" if ipv6 else "info")
        except socket.gaierror as e:
            result("DNS Lookup", str(e), "err")

    # Reverse DNS
    ip = None
    try:
        ip = socket.gethostbyname(host)
        rev = socket.gethostbyaddr(ip)[0]
        data["reverse_dns"] = rev
        result("IP Chính", ip, "info")
        result("Reverse DNS", rev, "info")
    except Exception:
        if ip:
            result("IP Chính", ip, "info")

    results["dns"] = data


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 5: WHOIS
# ═══════════════════════════════════════════════════════════════════════════════

def get_whois_info(host: str, results: dict):
    section("WHOIS - Thông Tin Tên Miền", "📋")
    data = {}

    if tool_available("whois"):
        out, err, rc = run_cmd(["whois", host], timeout=15)
        if rc == 0 and out:
            # Trích các trường quan trọng
            patterns = {
                "Registrar":         r"Registrar:\s*(.+)",
                "Creation Date":     r"Creation Date:\s*(.+)",
                "Updated Date":      r"Updated Date:\s*(.+)",
                "Expiry Date":       r"Registry Expiry Date:\s*(.+)|Expir.*Date:\s*(.+)",
                "Name Servers":      r"Name Server:\s*(.+)",
                "DNSSEC":            r"DNSSEC:\s*(.+)",
                "Registrant Org":    r"Registrant Organization:\s*(.+)",
                "Registrant Country":r"Registrant Country:\s*(.+)",
            }
            for field, pattern in patterns.items():
                matches = re.findall(pattern, out, re.IGNORECASE)
                if matches:
                    val = matches[0] if isinstance(matches[0], str) else next((m for m in matches[0] if m), "")
                    if field == "Name Servers":
                        vals = [m if isinstance(m, str) else m[0] for m in matches]
                        data[field] = vals
                        result(field, f"{len(vals)} server(s)", "info")
                        for ns in vals[:3]:
                            subitem(ns.strip())
                    else:
                        data[field] = val.strip()
                        result(field, val.strip()[:60], "info")
                else:
                    result(field, "Không tìm thấy", "info")
            data["raw"] = out
        else:
            result("whois", "Không lấy được dữ liệu", "warn")
    else:
        result("whois", "Không có lệnh whois (chỉ có trên Kali Linux)", "warn")
        result("Gợi ý", "Cài bằng: sudo apt install whois", "info")

    results["whois"] = data


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 6: NHẬN DIỆN CÔNG NGHỆ
# ═══════════════════════════════════════════════════════════════════════════════

TECH_SIGNATURES = {
    # CMS
    "WordPress":        {"headers": [], "body": ["wp-content", "wp-includes", "wordpress"], "cookies": ["wordpress_"]},
    "Joomla":           {"headers": [], "body": ["/components/com_", "joomla"], "cookies": ["joomla_"]},
    "Drupal":           {"headers": ["X-Generator: Drupal"], "body": ["drupal.js", "/sites/default/"], "cookies": ["DRUPAL_UID"]},
    "Magento":          {"headers": [], "body": ["Mage.Cookies", "magento"], "cookies": ["PHPSESSID", "mage-"]},
    "Shopify":          {"headers": [], "body": ["cdn.shopify.com", "shopify"], "cookies": ["_shopify_"]},
    "Wix":              {"headers": [], "body": ["wix.com", "X-Wix-"], "cookies": []},
    "Squarespace":      {"headers": [], "body": ["squarespace.com", "static.squarespace"], "cookies": []},
    "Ghost":            {"headers": ["X-Ghost-Cache-Status"], "body": ["ghost.io"], "cookies": []},
    # Frameworks / Languages
    "Laravel":          {"headers": [], "body": [], "cookies": ["laravel_session", "XSRF-TOKEN"]},
    "Django":           {"headers": [], "body": [], "cookies": ["csrftoken", "sessionid"]},
    "Ruby on Rails":    {"headers": ["X-Runtime"], "body": [], "cookies": ["_session_id"]},
    "ASP.NET":          {"headers": ["X-AspNet-Version", "X-Powered-By: ASP.NET"], "body": ["__VIEWSTATE"], "cookies": ["ASP.NET_SessionId"]},
    "Next.js":          {"headers": ["X-Powered-By: Next.js"], "body": ["__NEXT_DATA__", "_next/static"], "cookies": []},
    "Nuxt.js":          {"headers": [], "body": ["__NUXT__", "_nuxt/"], "cookies": []},
    "React":            {"headers": [], "body": ["react.js", "react.min.js", "__react"], "cookies": []},
    "Vue.js":           {"headers": [], "body": ["vue.js", "vue.min.js", "__vue__"], "cookies": []},
    "Angular":          {"headers": [], "body": ["angular.js", "ng-version", "angular.min.js"], "cookies": []},
    # Servers
    "Nginx":            {"headers": ["Server: nginx"], "body": [], "cookies": []},
    "Apache":           {"headers": ["Server: Apache"], "body": [], "cookies": []},
    "IIS":              {"headers": ["Server: Microsoft-IIS"], "body": [], "cookies": []},
    "Cloudflare":       {"headers": ["CF-Ray", "Server: cloudflare"], "body": [], "cookies": ["__cflb", "__cf_bm"]},
    "AWS CloudFront":   {"headers": ["X-Amz-Cf-Id", "Via: 1.1 cloudfront"], "body": [], "cookies": []},
    "Varnish":          {"headers": ["X-Varnish", "Via: varnish"], "body": [], "cookies": []},
    # Analytics & CDN
    "Google Analytics": {"headers": [], "body": ["google-analytics.com/analytics.js", "gtag("], "cookies": ["_ga", "_gid"]},
    "jQuery":           {"headers": [], "body": ["jquery.min.js", "jquery-"], "cookies": []},
    "Bootstrap":        {"headers": [], "body": ["bootstrap.min.css", "bootstrap.min.js"], "cookies": []},
    # WAF
    "mod_security":     {"headers": ["Server: Apache/.*mod_security"], "body": [], "cookies": []},
    "Sucuri":           {"headers": ["X-Sucuri-ID", "X-Sucuri-Cache"], "body": [], "cookies": []},
    "Imperva":          {"headers": ["X-Iinfo"], "body": [], "cookies": ["visid_incap_"]},
    "Akamai":           {"headers": ["X-Akamai-Transformed", "X-Check-Cacheable"], "body": [], "cookies": []},
}

def detect_technologies(url: str, results: dict):
    section("Nhận Diện Công Nghệ (Fingerprinting)", "🧬")
    detected = []

    if not HAS_REQUESTS:
        result("Nhận diện", "Cần cài requests", "warn")
        return

    try:
        resp = requests.get(url, timeout=10, verify=False,
                            headers={"User-Agent": "Mozilla/5.0 WebRecon/1.0"})
        body    = resp.text.lower()
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        cookies = {k.lower(): v.lower() for k, v in resp.cookies.items()}

        for tech, sigs in TECH_SIGNATURES.items():
            found = False
            for h_sig in sigs.get("headers", []):
                k, _, v = h_sig.partition(": ")
                if v:
                    if headers.get(k.lower(), "").startswith(v.lower()):
                        found = True; break
                else:
                    if k.lower() in headers:
                        found = True; break
            if not found:
                for b_sig in sigs.get("body", []):
                    if b_sig.lower() in body:
                        found = True; break
            if not found:
                for c_sig in sigs.get("cookies", []):
                    for ck in cookies:
                        if c_sig.lower() in ck:
                            found = True; break
                    if found:
                        break
            if found:
                detected.append(tech)

        # Server header raw
        server = resp.headers.get("Server", "")
        x_pow  = resp.headers.get("X-Powered-By", "")
        if server:
            result("Server Header", server, "info")
        if x_pow:
            result("X-Powered-By", x_pow, "info")

        # Generator meta
        if HAS_BS4:
            soup = BeautifulSoup(resp.text, "html.parser")
            gen = soup.find("meta", {"name": re.compile("generator", re.I)})
            if gen and gen.get("content"):
                result("Meta Generator", gen["content"], "info")
                if gen["content"] not in detected:
                    detected.append(f"[meta] {gen['content']}")

        if detected:
            result("Đã phát hiện", f"{len(detected)} công nghệ", "ok")
            for t in detected:
                subitem(t)
        else:
            result("Công nghệ", "Không nhận diện được", "warn")

        results["technologies"] = detected

    except Exception as e:
        result("Lỗi fingerprint", str(e)[:80], "err")


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 7: QUÉT CỔNG (NMAP)
# ═══════════════════════════════════════════════════════════════════════════════

def port_scan(host: str, results: dict):
    section("Quét Cổng (Port Scan)", "🔌")
    data = {}

    if tool_available("nmap"):
        result("Công cụ", "nmap (Kali Linux) ✔", "ok")
        print(f"  {c('⏳ Đang quét top 100 cổng phổ biến...', Fore.YELLOW)}")
        out, err, rc = run_cmd(
            ["nmap", "-sV", "--top-ports", "100", "--open",
             "-T4", "--script=banner", host],
            timeout=60
        )
        if rc == 0 and out:
            # Parse nmap output
            open_ports = []
            for line in out.splitlines():
                m = re.match(r'\s*(\d+)/(\w+)\s+open\s+(.+)', line)
                if m:
                    port, proto, service = m.groups()
                    open_ports.append({"port": port, "proto": proto, "service": service.strip()})
                    st = "ok" if int(port) in [80,443] else "info"
                    result(f"Port {port}/{proto}", service.strip()[:50], st)

            data["open_ports"] = open_ports
            data["nmap_raw"]   = out
            if not open_ports:
                result("Kết quả", "Không có cổng mở nào được tìm thấy", "warn")
        else:
            result("nmap", err[:80] if err else "Lỗi không xác định", "err")
    else:
        result("nmap", "Không có – dùng socket scan thay thế", "warn")
        print(f"  {c('⏳ Quét cổng phổ biến bằng socket...', Fore.YELLOW)}")
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
        }
        open_ports = []
        for port, svc in common_ports.items():
            try:
                with socket.create_connection((host, port), timeout=1):
                    open_ports.append({"port": str(port), "proto": "tcp", "service": svc})
                    result(f"Port {port}/tcp", f"{svc} ✔ MỞ", "ok")
            except Exception:
                pass
        if not open_ports:
            result("Cổng mở", "Không phát hiện cổng mở nào", "warn")
        data["open_ports"] = open_ports
        result("Gợi ý", "Cài nmap: sudo apt install nmap", "info")

    results["ports"] = data


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 8: ROBOTS.TXT & SITEMAP
# ═══════════════════════════════════════════════════════════════════════════════

def get_robots_sitemap(url: str, results: dict):
    section("Robots.txt & Sitemap", "🤖")
    base = url.rstrip("/")
    data = {}

    for path, name in [("/robots.txt", "robots.txt"), ("/sitemap.xml", "sitemap.xml"),
                       ("/sitemap_index.xml", "sitemap_index.xml")]:
        target = base + path
        try:
            if HAS_REQUESTS:
                r = requests.get(target, timeout=8, verify=False,
                                 headers={"User-Agent": "Mozilla/5.0 WebRecon/1.0"})
                if r.status_code == 200:
                    result(name, f"✔ Tìm thấy ({len(r.content):,} bytes)", "ok")
                    data[name] = {"found": True, "size": len(r.content)}
                    if name == "robots.txt":
                        # Trích Disallow và Allow
                        disallows = re.findall(r"Disallow:\s*(.+)", r.text)
                        allows    = re.findall(r"Allow:\s*(.+)",    r.text)
                        sitemaps  = re.findall(r"Sitemap:\s*(.+)",  r.text)
                        if disallows:
                            result("  Disallow entries", str(len(disallows)), "info")
                            for d in disallows[:5]:
                                subitem(d.strip())
                        if sitemaps:
                            result("  Sitemap links", str(len(sitemaps)), "info")
                            for s in sitemaps[:3]:
                                subitem(s.strip())
                        data["robots_disallow"] = disallows
                    elif "sitemap" in name:
                        urls_in_sitemap = re.findall(r"<loc>(.+?)</loc>", r.text)
                        result("  URLs trong sitemap", str(len(urls_in_sitemap)), "info")
                        data["sitemap_urls_count"] = len(urls_in_sitemap)
                else:
                    result(name, f"✘ HTTP {r.status_code}", "warn")
                    data[name] = {"found": False}
        except Exception as e:
            result(name, str(e)[:60], "err")

    results["robots_sitemap"] = data


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 9: META & NỘI DUNG TRANG
# ═══════════════════════════════════════════════════════════════════════════════

def get_page_meta(url: str, results: dict):
    section("Meta Tags & Nội Dung Trang", "📄")
    data = {}

    if not HAS_REQUESTS:
        result("Bỏ qua", "Cần cài requests", "warn")
        return

    try:
        resp = requests.get(url, timeout=10, verify=False,
                            headers={"User-Agent": "Mozilla/5.0 WebRecon/1.0"})
        if HAS_BS4:
            soup = BeautifulSoup(resp.text, "html.parser")

            title = soup.find("title")
            desc  = soup.find("meta", {"name": re.compile(r"^description$", re.I)})
            kw    = soup.find("meta", {"name": re.compile(r"^keywords$",    re.I)})
            robots_m = soup.find("meta", {"name": re.compile(r"^robots$",   re.I)})
            canon = soup.find("link", {"rel": re.compile(r"canonical", re.I)})
            lang  = soup.find("html")

            result("Title", (title.text.strip() if title else "Không có")[:70], "info")
            result("Description", (desc["content"][:80] if desc and desc.get("content") else "Không có"), "info")
            result("Keywords",    (kw["content"][:80]   if kw   and kw.get("content")   else "Không có"), "info")
            result("Robots Meta", (robots_m["content"]  if robots_m and robots_m.get("content") else "Không có"), "info")
            result("Canonical",   (canon["href"][:80]   if canon and canon.get("href")   else "Không có"), "info")
            result("Ngôn ngữ",    (lang.get("lang", "Không có") if lang else "Không có"), "info")

            # Open Graph
            og_tags = soup.find_all("meta", property=re.compile(r"^og:", re.I))
            if og_tags:
                result("Open Graph tags", str(len(og_tags)), "ok")
                for og in og_tags[:5]:
                    subitem(f"{og.get('property','')}: {str(og.get('content',''))[:60]}")

            # Twitter Card
            tw_tags = soup.find_all("meta", {"name": re.compile(r"^twitter:", re.I)})
            result("Twitter Card tags", str(len(tw_tags)) if tw_tags else "Không có",
                   "ok" if tw_tags else "info")

            # Links & Forms
            links = soup.find_all("a", href=True)
            forms = soup.find_all("form")
            scripts = soup.find_all("script", src=True)
            styles  = soup.find_all("link", rel=re.compile("stylesheet", re.I))

            result("Số links (<a>)",    str(len(links)),   "info")
            result("Số forms",          str(len(forms)),   "info" if forms else "ok")
            result("Số JS files",       str(len(scripts)), "info")
            result("Số CSS files",      str(len(styles)),  "info")

            data.update({
                "title": title.text.strip() if title else None,
                "description": desc["content"] if desc and desc.get("content") else None,
                "lang": lang.get("lang") if lang else None,
                "links_count": len(links),
                "forms_count": len(forms),
                "scripts_count": len(scripts),
            })
        else:
            # Fallback regex
            title_m = re.search(r"<title[^>]*>(.+?)</title>", resp.text, re.I | re.S)
            result("Title", title_m.group(1).strip()[:70] if title_m else "Không có", "info")

    except Exception as e:
        result("Lỗi phân tích trang", str(e)[:80], "err")

    results["page_meta"] = data


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 10: SUBDOMAIN DISCOVERY (chỉ với Kali tools)
# ═══════════════════════════════════════════════════════════════════════════════

def discover_subdomains(host: str, results: dict):
    section("Subdomain Discovery", "🔎")
    data = {}
    found = []

    # Dùng Certificate Transparency (crt.sh) nếu có requests
    if HAS_REQUESTS:
        try:
            r = requests.get(f"https://crt.sh/?q=%.{host}&output=json",
                             timeout=15, verify=False)
            if r.status_code == 200:
                entries = r.json()
                subs = set()
                for e in entries:
                    names = e.get("name_value", "").split("\n")
                    for n in names:
                        n = n.strip().lstrip("*.")
                        if n.endswith(host) and n != host:
                            subs.add(n)
                found = sorted(subs)
                data["crt_sh"] = found
                result("crt.sh (Cert Transparency)", f"{len(found)} subdomains", "ok")
                for s in found[:10]:
                    subitem(s)
                if len(found) > 10:
                    subitem(f"... và {len(found)-10} subdomains khác")
                if not found:
                    result("crt.sh", "Không tìm thấy subdomain", "info")
        except Exception as e:
            result("crt.sh", str(e)[:60], "warn")

    # Brute-force nhẹ bằng DNS
    common_subs = ["www", "mail", "ftp", "cpanel", "webmail", "admin",
                   "blog", "api", "dev", "staging", "test", "cdn",
                   "shop", "app", "m", "mobile", "secure", "vpn"]
    found_brute = []
    print(f"  {c('⏳ DNS brute-force với danh sách phổ biến...', Fore.YELLOW)}")
    for sub in common_subs:
        try:
            fqdn = f"{sub}.{host}"
            socket.gethostbyname(fqdn)
            found_brute.append(fqdn)
            subitem(f"✔ {fqdn}")
        except socket.gaierror:
            pass

    data["brute_force"] = found_brute
    result("Brute-force DNS", f"{len(found_brute)} tìm thấy", "ok" if found_brute else "info")
    results["subdomains"] = data


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 11: KIỂM TRA REDIRECT & COOKIE
# ═══════════════════════════════════════════════════════════════════════════════

def check_redirects_cookies(url: str, results: dict):
    section("Redirects & Cookies", "🍪")
    data = {}

    if not HAS_REQUESTS:
        return

    try:
        resp = requests.get(url, timeout=10, verify=False, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 WebRecon/1.0"})

        # Redirect chain
        if resp.history:
            result("Redirect chain", f"{len(resp.history)} bước", "info")
            for r in resp.history:
                subitem(f"[{r.status_code}] {r.url} → {r.headers.get('Location','?')}")
        else:
            result("Redirect", "Không có redirect", "ok")

        # HTTP → HTTPS redirect?
        if url.startswith("http://"):
            try:
                r2 = requests.get(url, timeout=8, verify=False, allow_redirects=False)
                if r2.status_code in (301, 302, 307, 308):
                    loc = r2.headers.get("Location", "")
                    result("HTTP→HTTPS Redirect", f"✔ {r2.status_code} → {loc[:50]}", "ok")
                else:
                    result("HTTP→HTTPS Redirect", "✘ Không có", "warn")
            except Exception:
                pass

        # Cookies
        if resp.cookies:
            result("Cookies", f"{len(resp.cookies)} cookie(s)", "info")
            for ck in resp.cookies:
                flags = []
                if ck.secure:    flags.append("Secure")
                if ck.has_nonstandard_attr("HttpOnly"): flags.append("HttpOnly")
                if ck.has_nonstandard_attr("SameSite"): flags.append("SameSite")
                flag_str = ", ".join(flags) if flags else "⚠ Không có flags"
                subitem(f"{ck.name}: {flag_str}")
                data[ck.name] = {"secure": ck.secure, "flags": flags}
        else:
            result("Cookies", "Không có cookie", "info")

    except Exception as e:
        result("Lỗi", str(e)[:80], "err")

    results["cookies"] = data


# ═══════════════════════════════════════════════════════════════════════════════
#  TÓM TẮT & XUẤT KẾT QUẢ
# ═══════════════════════════════════════════════════════════════════════════════

def print_summary(url: str, results: dict, elapsed: float):
    section("TÓM TẮT KẾT QUẢ", "📊")

    print(f"\n  {c('🌐 Target:', Fore.WHITE, True)} {c(url, Fore.CYAN, True)}")
    print(f"  {c('⏱  Thời gian quét:', Fore.WHITE, True)} {c(f'{elapsed:.2f} giây', Fore.CYAN, True)}")
    print(f"  {c('📅 Thời điểm:', Fore.WHITE, True)} {c(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), Fore.CYAN, True)}")

    sc = results.get("security_score", {})
    if sc:
        grade = sc.get("grade", "?")
        score = sc.get("score", 0)
        mx    = sc.get("max", 7)
        gc    = Fore.GREEN if grade == "A" else Fore.YELLOW if grade in "BC" else Fore.RED
        print(f"\n  {c('🛡  Security Grade:', Fore.WHITE, True)} {c(f'{grade}  ({score}/{mx} headers)', gc, True)}")

    techs = results.get("technologies", [])
    if techs:
        print(f"\n  {c('🧬 Công nghệ phát hiện:', Fore.WHITE, True)}")
        for t in techs:
            subitem(t)

    ports = results.get("ports", {}).get("open_ports", [])
    if ports:
        print(f"\n  {c('🔌 Cổng mở:', Fore.WHITE, True)}")
        for p in ports:
            subitem(f"Port {p['port']}/{p['proto']} — {p['service']}")

    subs = results.get("subdomains", {}).get("brute_force", [])
    ct_subs = results.get("subdomains", {}).get("crt_sh", [])
    total_subs = len(set(subs + ct_subs))
    if total_subs:
        print(f"\n  {c('🔎 Subdomains tìm thấy:', Fore.WHITE, True)} {c(str(total_subs), Fore.GREEN, True)}")

    print()

def save_report(url: str, results: dict, output_file: Optional[str] = None):
    if not output_file:
        host = extract_host(url).replace(".", "_")
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"webrecon_{host}_{ts}.json"

    report = {
        "target":    url,
        "scan_time": datetime.now().isoformat(),
        "results":   results
    }
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    return output_file


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print_banner()

    # ─── Kiểm tra phụ thuộc ────────────────────────────────────────────────
    print(f"{c('⚙  Kiểm tra môi trường:', Fore.YELLOW, True)}")
    deps = [
        ("Python requests", HAS_REQUESTS, "pip install requests"),
        ("BeautifulSoup4",  HAS_BS4,      "pip install beautifulsoup4"),
        ("Colorama",        HAS_COLOR,    "pip install colorama"),
        ("nmap (Kali)",     tool_available("nmap"),  "sudo apt install nmap"),
        ("dig (Kali)",      tool_available("dig"),   "sudo apt install dnsutils"),
        ("whois (Kali)",    tool_available("whois"), "sudo apt install whois"),
    ]
    for name, ok, install in deps:
        status = c("✔ Có", Fore.GREEN) if ok else c(f"✘ Thiếu ({install})", Fore.YELLOW)
        print(f"  {name:<25} {status}")
    print()

    # ─── Nhập URL ──────────────────────────────────────────────────────────
    if len(sys.argv) > 1:
        raw_url = sys.argv[1]
    else:
        raw_url = input(c("  🎯 Nhập URL mục tiêu (vd: example.com): ", Fore.CYAN, True)).strip()

    if not raw_url:
        print(c("  ✘ Vui lòng nhập URL!", Fore.RED, True))
        sys.exit(1)

    url  = normalize_url(raw_url)
    host = extract_host(url)

    # ─── Tùy chọn quét ─────────────────────────────────────────────────────
    save_json = True
    skip_ports = False
    if len(sys.argv) > 2:
        args = sys.argv[2:]
        if "--no-ports" in args: skip_ports = True
        if "--no-save"  in args: save_json  = False
    else:
        print(f"\n  {c('Tùy chọn:', Fore.YELLOW, True)}")
        print(f"  {c('[1]', Fore.CYAN)} Quét đầy đủ (bao gồm port scan)")
        print(f"  {c('[2]', Fore.CYAN)} Quét nhanh (không port scan)")
        choice = input(c("  Chọn [1/2, mặc định=1]: ", Fore.CYAN)).strip()
        if choice == "2":
            skip_ports = True

    print(f"\n  {c('🚀 Bắt đầu quét:', Fore.GREEN, True)} {c(url, Fore.WHITE, True)}")
    print(f"  {c('Host:', Fore.WHITE)} {c(host, Fore.CYAN)}\n")

    results = {}
    start   = time.time()

    # ─── Chạy tất cả modules ───────────────────────────────────────────────
    get_http_info(url, results)
    check_security_headers(results)
    get_ssl_info(host, results)
    get_dns_info(host, results)
    get_whois_info(host, results)
    detect_technologies(url, results)
    get_page_meta(url, results)
    get_robots_sitemap(url, results)
    check_redirects_cookies(url, results)
    discover_subdomains(host, results)
    if not skip_ports:
        port_scan(host, results)

    elapsed = time.time() - start
    print_summary(url, results, elapsed)

    # ─── Lưu báo cáo ───────────────────────────────────────────────────────
    if save_json:
        out_file = save_report(url, results)
        print(f"  {c('💾 Báo cáo JSON đã lưu:', Fore.GREEN, True)} {c(out_file, Fore.WHITE, True)}\n")

    width = 65
    print(c("═" * width, Fore.CYAN, True))
    print(c("  ✅ Quét hoàn tất!", Fore.GREEN, True))
    print(c("═" * width, Fore.CYAN, True))
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{c('  ⏹  Đã dừng bởi người dùng.', Fore.YELLOW, True)}\n")
        sys.exit(0)

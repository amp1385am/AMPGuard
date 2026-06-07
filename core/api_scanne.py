import requests, json, time
from urllib.parse import urljoin

class APIScanner:
    def __init__(self, base_url, endpoints, session=None, delay=0.2):
        self.base_url = base_url.rstrip('/')
        self.endpoints = endpoints   # لیست رشته‌های "METHOD /path"
        self.session = session or requests.Session()
        self.delay = delay
        self.vulnerabilities = []
        self.vuln_set = set()

    def add_vuln(self, vuln_type, url, severity, detail=""):
        key = f"{vuln_type}:{url}"
        if key in self.vuln_set: return
        self.vuln_set.add(key)
        self.vulnerabilities.append({
            "type": vuln_type, "url": url, "severity": severity, "detail": detail
        })

    def scan(self, log_callback):
        for ep in self.endpoints:
            parts = ep.strip().split(maxsplit=1)
            if len(parts) != 2:
                continue
            method, path = parts[0].upper(), parts[1]
            full_url = urljoin(self.base_url + "/", path.lstrip('/'))
            log_callback(f"[API] {method} {full_url}")

            # تست SQLi در پارامترهای GET یا body JSON
            self.test_sqli(method, full_url, log_callback)
            self.test_xss(method, full_url, log_callback)
            # می‌توان اضافه کرد: IDOR, SSRF
        return self.vulnerabilities

    def test_sqli(self, method, url, log_callback):
        # مشابه time-based در scanner قبلی ولی برای JSON
        # ساده: ارسال payload در پارامترها
        payload = "' OR SLEEP(5)--"
        if method == "GET":
            resp = self.session.get(url, params={"id": payload}, timeout=5)
            # بررسی تأخیر (نیاز به زمان‌سنجی) – به دلیل پیچیدگی، فعلاً error‑based ساده
            if resp and "mysql" in resp.text.lower():
                self.add_vuln("SQL Injection", url, "Critical", f"GET param id={payload}")
        # مشابه برای POST با JSON
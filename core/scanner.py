import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os
import time


class WebScanner:

    def __init__(self, target, session=None, delay=0.2):
        self.base_target = target
        self.target = target
        self.session = session if session is not None else requests.Session()
        self.delay = delay

        self.vulnerabilities = []
        self.vuln_set = set()

        self.visited_urls = set()
        self.urls_to_scan = set()
        self.urls_to_scan.add(target)

        self.max_depth = 2
        self.max_urls = 50

        self.vuln_callback = None

    # ══════════════════════════════════════════════════════════════════════
    #  SAFE REQUESTS (با رعایت Rate Limiting)
    # ══════════════════════════════════════════════════════════════════════

    def safe_get(self, url, params=None, headers=None):
        time.sleep(self.delay)
        try:
            response = self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=5
            )
            print(f"[HTTP] {url} -> {response.status_code}")
            return response
        except Exception as e:
            print(f"[HTTP ERROR] {url} -> {e}")
            return None

    def safe_post(self, url, data=None, headers=None):
        time.sleep(self.delay)
        try:
            response = self.session.post(
                url,
                data=data,
                headers=headers,
                timeout=5
            )
            print(f"[HTTP POST] {url} -> {response.status_code}")
            return response
        except Exception as e:
            print(f"[HTTP POST ERROR] {url} -> {e}")
            return None

    # ══════════════════════════════════════════════════════════════════════
    #  ADD VULNERABILITY
    # ══════════════════════════════════════════════════════════════════════

    def add_vuln(self, vuln_type, url, severity, log_callback, detail=""):
        key = f"{vuln_type}:{url}"
        if key in self.vuln_set:
            return
        self.vuln_set.add(key)

        vuln = {
            "type": vuln_type,
            "url": url,
            "severity": severity,
            "detail": detail
        }
        self.vulnerabilities.append(vuln)

        if self.vuln_callback:
            self.vuln_callback(vuln)

        if log_callback:
            log_callback(f"[VULN] {vuln_type} -> {url}")

    # ══════════════════════════════════════════════════════════════════════
    #  MAIN SCAN (با فیلتر صفحات خطا)
    # ══════════════════════════════════════════════════════════════════════

    def run_scan(self, log_callback=None):
        if log_callback:
            log_callback("[INFO] Starting crawler...")

        self.crawl(self.base_target, log_callback)

        all_urls = list(self.urls_to_scan)
        if log_callback:
            log_callback(f"[INFO] URLs collected: {len(all_urls)}")

        for url in all_urls:
            self.target = url
            if log_callback:
                log_callback(f"[SCAN] {url}")

            # ── بررسی وضعیت صفحه ───────────────────────────
            pre_resp = self.safe_get(url)
            if not pre_resp or pre_resp.status_code >= 400:
                code = pre_resp.status_code if pre_resp else "No response"
                if log_callback:
                    log_callback(f"[SKIP] HTTP {code} – skipping security tests")
                continue

            self.check_headers(log_callback)
            self.check_xss(log_callback)
            self.check_sqli(log_callback)
            self.check_lfi(log_callback)
            self.check_ssrf(log_callback)
            self.check_csrf(log_callback)

        self.target = self.base_target
        self.directory_bruteforce(log_callback)

        return self.vulnerabilities

    # ══════════════════════════════════════════════════════════════════════
    #  HEADERS CHECK
    # ══════════════════════════════════════════════════════════════════════

    def check_headers(self, log_callback):
        response = self.safe_get(self.target)
        if not response:
            return

        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security"
        ]

        for header in security_headers:
            if log_callback:
                log_callback(f"[HEADER] {header} => {response.headers.get(header)}")
            if header not in response.headers:
                self.add_vuln(
                    "Missing Security Header",
                    self.target,
                    "Medium",
                    log_callback,
                    detail=f"Missing: {header}"
                )

    # ══════════════════════════════════════════════════════════════════════
    #  XSS (بدون تغییر)
    # ══════════════════════════════════════════════════════════════════════

    def check_xss(self, log_callback):
        payload = "<script>alert(1)</script>"

        response = self.safe_get(self.target, params={"q": payload})
        if response and payload in response.text:
            self.add_vuln("Reflected XSS", self.target, "High", log_callback, detail="via GET ?q=")

        response = self.safe_post(self.target, data={"q": payload, "search": payload})
        if response and payload in response.text:
            self.add_vuln("Reflected XSS", self.target, "High", log_callback, detail="via POST body")

        response = self.safe_get(self.target, headers={"User-Agent": payload, "Referer": payload})
        if response and payload in response.text:
            self.add_vuln("Reflected XSS", self.target, "High", log_callback, detail="via HTTP header")

    # ══════════════════════════════════════════════════════════════════════
    #  SQL INJECTION – TIME‑BASED CONFIRMATORY
    # ══════════════════════════════════════════════════════════════════════

    def check_sqli(self, log_callback):
        if log_callback:
            log_callback(f"[INFO] Testing SQL Injection (time-based) on {self.target}")

        time_payloads = [
            ("' OR SLEEP(5)--", 5),
            ("' WAITFOR DELAY '0:0:5'--", 5),
            ("' OR pg_sleep(5)--", 5),
            ("' OR sleep(5) and '1'='1", 5),
        ]

        # زمان درخواست عادی
        start_normal = time.time()
        normal_resp = self.safe_get(self.target)
        normal_time = time.time() - start_normal if normal_resp else 0

        # GET
        for payload, delay_sec in time_payloads:
            start = time.time()
            resp = self.safe_get(self.target, params={"id": payload})
            elapsed = time.time() - start
            if resp and elapsed >= (normal_time + delay_sec - 1):
                self.add_vuln(
                    "SQL Injection",
                    self.target,
                    "Critical",
                    log_callback,
                    detail=f"Time-based blind SQLi via GET ?id={payload} (delay {elapsed:.1f}s)"
                )
                return

        # POST
        for payload, delay_sec in time_payloads:
            start = time.time()
            resp = self.safe_post(self.target, data={"id": payload, "user": payload})
            elapsed = time.time() - start
            if resp and elapsed >= (normal_time + delay_sec - 1):
                self.add_vuln(
                    "SQL Injection",
                    self.target,
                    "Critical",
                    log_callback,
                    detail=f"Time-based blind SQLi via POST with payload {payload} (delay {elapsed:.1f}s)"
                )
                return

    # ══════════════════════════════════════════════════════════════════════
    #  LFI / PATH TRAVERSAL
    # ══════════════════════════════════════════════════════════════════════

    def check_lfi(self, log_callback):
        if log_callback:
            log_callback(f"[INFO] LFI check: {self.target}")

        payloads = [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "../../../windows/system32/drivers/etc/hosts",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        ]

        lfi_params = ["file", "page", "path", "template", "view", "include", "doc", "document", "load"]
        lfi_signatures = ["root:x:", "root:0:0", "[fonts]", "localhost", "# Copyright", "SYSTEM"]

        for param in lfi_params:
            for payload in payloads:
                response = self.safe_get(self.target, params={param: payload})
                if response:
                    for sig in lfi_signatures:
                        if sig in response.text:
                            self.add_vuln(
                                "LFI / Path Traversal",
                                self.target,
                                "Critical",
                                log_callback,
                                detail=f"GET ?{param}={payload} → matched '{sig}'"
                            )
                            break
                response = self.safe_post(self.target, data={param: payload})
                if response:
                    for sig in lfi_signatures:
                        if sig in response.text:
                            self.add_vuln(
                                "LFI / Path Traversal",
                                self.target,
                                "Critical",
                                log_callback,
                                detail=f"POST {param}={payload} → matched '{sig}'"
                            )
                            break

    # ══════════════════════════════════════════════════════════════════════
    #  SSRF (بدون تغییر)
    # ══════════════════════════════════════════════════════════════════════

    def check_ssrf(self, log_callback):
        if log_callback:
            log_callback(f"[INFO] SSRF check: {self.target}")

        ssrf_payloads = [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://0.0.0.0/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://192.168.0.1/",
            "http://10.0.0.1/",
        ]

        ssrf_params = ["url", "uri", "link", "src", "source", "redirect",
                       "next", "target", "dest", "destination", "callback",
                       "fetch", "proxy", "image", "file", "load"]

        ssrf_signatures = [
            "ami-id", "instance-id", "local-ipv4",
            "computeMetadata", "project-id",
            "root:x:", "localhost",
            "169.254", "metadata",
        ]

        for param in ssrf_params:
            for payload in ssrf_payloads:
                response = self.safe_get(self.target, params={param: payload})
                if response:
                    for sig in ssrf_signatures:
                        if sig in response.text:
                            self.add_vuln(
                                "SSRF",
                                self.target,
                                "Critical",
                                log_callback,
                                detail=f"GET ?{param}={payload} → matched '{sig}'"
                            )
                            break
                response = self.safe_post(self.target, data={param: payload})
                if response:
                    for sig in ssrf_signatures:
                        if sig in response.text:
                            self.add_vuln(
                                "SSRF",
                                self.target,
                                "Critical",
                                log_callback,
                                detail=f"POST {param}={payload} → matched '{sig}'"
                            )
                            break
                for header_name in ["Referer", "X-Forwarded-Host", "X-Original-URL"]:
                    response = self.safe_get(self.target, headers={header_name: payload})
                    if response:
                        for sig in ssrf_signatures:
                            if sig in response.text:
                                self.add_vuln(
                                    "SSRF",
                                    self.target,
                                    "Critical",
                                    log_callback,
                                    detail=f"Header {header_name}: {payload}"
                                )
                                break

    # ══════════════════════════════════════════════════════════════════════
    #  CSRF DETECTION
    # ══════════════════════════════════════════════════════════════════════

    def check_csrf(self, log_callback):
        if log_callback:
            log_callback(f"[INFO] CSRF check: {self.target}")

        response = self.safe_get(self.target)
        if not response:
            return

        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            method = form.get("method", "get").lower()
            if method != "post":
                continue

            inputs = form.find_all("input")
            input_names = [i.get("name", "").lower() for i in inputs]

            csrf_tokens = [
                n for n in input_names
                if any(kw in n for kw in ["csrf", "token", "_token", "authenticity", "nonce"])
            ]

            action = form.get("action") or self.target
            form_url = urljoin(self.target, action)

            if not csrf_tokens:
                self.add_vuln(
                    "Missing CSRF Token",
                    form_url,
                    "High",
                    log_callback,
                    detail=f"POST form has no CSRF token (inputs: {input_names})"
                )
            else:
                if log_callback:
                    log_callback(f"[INFO] CSRF token found in form: {csrf_tokens}")

    # ══════════════════════════════════════════════════════════════════════
    #  CRAWLER (با فیلتر صفحات خطا)
    # ══════════════════════════════════════════════════════════════════════

    def crawl(self, url, log_callback, depth=0):
        if depth > self.max_depth:
            return
        if len(self.urls_to_scan) >= self.max_urls:
            return
        if url in self.visited_urls:
            return

        self.visited_urls.add(url)

        if log_callback:
            log_callback(f"[CRAWLER] {url}")

        response = self.safe_get(url)
        if not response or response.status_code >= 400:
            if log_callback:
                code = response.status_code if response else "error"
                log_callback(f"[CRAWLER] Skipping {url} (HTTP {code})")
            return

        soup = BeautifulSoup(response.text, "html.parser")
        links = soup.find_all("a")

        if log_callback:
            log_callback(f"[DEBUG] Found {len(links)} links on {url}")

        for link in links:
            href = link.get("href")
            if not href:
                continue

            absolute = urljoin(url, href)
            parsed_root = urlparse(self.base_target)
            parsed_link = urlparse(absolute)

            if parsed_root.netloc != parsed_link.netloc:
                continue

            clean_url = parsed_link.scheme + "://" + parsed_link.netloc + parsed_link.path

            if clean_url not in self.visited_urls:
                self.urls_to_scan.add(clean_url)
                if log_callback:
                    log_callback(f"[FOUND] {clean_url}")
                self.crawl(clean_url, log_callback, depth + 1)

        self.extract_forms(url, soup, log_callback)

    def extract_forms(self, url, soup, log_callback):
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = []
            for inp in form.find_all("input"):
                name = inp.get("name")
                if name:
                    inputs.append(name)

            form_info = {
                "url": url,
                "action": action,
                "method": method,
                "inputs": inputs
            }
            if log_callback:
                log_callback(f"[FORM] {action}")
            self.test_forms_xss(form_info, log_callback)

    def test_forms_xss(self, form_info, log_callback):
        payload = "<script>alert(1)</script>"
        target_url = urljoin(form_info["url"], form_info["action"] or "")
        data = {name: payload for name in form_info["inputs"]}
        try:
            if form_info["method"] == "post":
                response = self.session.post(target_url, data=data, timeout=5)
            else:
                response = self.session.get(target_url, params=data, timeout=5)
            if payload in response.text:
                self.add_vuln("Form XSS", target_url, "High", log_callback)
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════════
    #  DIRECTORY BRUTEFORCE
    # ══════════════════════════════════════════════════════════════════════

    def directory_bruteforce(self, log_callback):
        wordlist_path = "wordlists/common.txt"
        if not os.path.exists(wordlist_path):
            return

        if log_callback:
            log_callback("[INFO] Directory scan started")

        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            paths = f.read().splitlines()[:100]

        for path in paths:
            url = urljoin(self.base_target + "/", path)
            response = self.safe_get(url)
            if not response:
                continue
            if response.status_code in [200, 301, 302, 403]:
                self.add_vuln(
                    "Interesting Endpoint",
                    url,
                    "Low",
                    log_callback,
                    detail=f"HTTP {response.status_code}"
                )
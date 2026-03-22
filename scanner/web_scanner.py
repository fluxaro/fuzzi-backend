"""
Fuzzi Web Scanner
Probes a target URL and extracts ALL security + quality factor scores.
Covers: security headers, auth, directories, errors, debug, access control,
        cloud config, SSL/TLS, input validation, third-party risk,
        SEO, readability, design consistency, performance risk.
"""
import logging
import re
import socket
import ssl
import time
from html.parser import HTMLParser
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)
TIMEOUT = 12

SECURITY_HEADERS = {
    "content-security-policy": 2.0,   # weight
    "strict-transport-security": 2.0,
    "x-frame-options": 1.0,
    "x-content-type-options": 1.0,
    "referrer-policy": 1.0,
    "permissions-policy": 1.0,
    "x-xss-protection": 0.5,
    "cross-origin-opener-policy": 1.0,
    "cross-origin-resource-policy": 1.0,
    "cross-origin-embedder-policy": 1.0,
}


# ---------------------------------------------------------------------------
# HTML text extractor
# ---------------------------------------------------------------------------

class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text_parts = []
        self.title = ""
        self.meta_desc = ""
        self.meta_keywords = ""
        self.h1_tags = []
        self.h2_tags = []
        self.img_alts_missing = 0
        self.img_total = 0
        self.links = []
        self.forms = 0
        self.inputs = []
        self._in_title = False
        self._in_h1 = False
        self._in_h2 = False
        self._skip = False

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag in ('script', 'style', 'noscript'):
            self._skip = True
        if tag == 'title':
            self._in_title = True
        if tag == 'h1':
            self._in_h1 = True
        if tag == 'h2':
            self._in_h2 = True
        if tag == 'meta':
            name = attrs_dict.get('name', '').lower()
            if name == 'description':
                self.meta_desc = attrs_dict.get('content', '')
            elif name == 'keywords':
                self.meta_keywords = attrs_dict.get('content', '')
        if tag == 'img':
            self.img_total += 1
            if not attrs_dict.get('alt'):
                self.img_alts_missing += 1
        if tag == 'a':
            href = attrs_dict.get('href', '')
            if href:
                self.links.append(href)
        if tag == 'form':
            self.forms += 1
        if tag == 'input':
            self.inputs.append(attrs_dict)

    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'noscript'):
            self._skip = False
        if tag == 'title':
            self._in_title = False
        if tag == 'h1':
            self._in_h1 = False
        if tag == 'h2':
            self._in_h2 = False

    def handle_data(self, data):
        if self._skip:
            return
        text = data.strip()
        if not text:
            return
        if self._in_title:
            self.title += text
        elif self._in_h1:
            self.h1_tags.append(text)
        elif self._in_h2:
            self.h2_tags.append(text)
        else:
            self.text_parts.append(text)

    @property
    def full_text(self):
        return ' '.join(self.text_parts)


def extract_html_features(html: str) -> dict:
    parser = _TextExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    return {
        "title": parser.title.strip(),
        "meta_description": parser.meta_desc,
        "meta_keywords": parser.meta_keywords,
        "h1_tags": parser.h1_tags,
        "h2_tags": parser.h2_tags,
        "img_total": parser.img_total,
        "img_alts_missing": parser.img_alts_missing,
        "links": parser.links[:50],
        "forms": parser.forms,
        "inputs": parser.inputs[:20],
        "full_text": parser.full_text[:5000],
        "word_count": len(parser.full_text.split()),
    }


# ---------------------------------------------------------------------------
# Security probes
# ---------------------------------------------------------------------------

def probe_security_headers(response: requests.Response) -> tuple:
    headers = {k.lower(): v for k, v in response.headers.items()}
    present, missing, details = [], [], {}
    total_weight = sum(SECURITY_HEADERS.values())
    missing_weight = 0.0

    for header, weight in SECURITY_HEADERS.items():
        label = header.replace('-', ' ').title()
        if header in headers:
            present.append(label)
            details[label] = {"present": True, "value": headers[header][:200]}
        else:
            missing.append(label)
            details[label] = {"present": False, "value": None}
            missing_weight += weight

    score = missing_weight / total_weight
    return round(min(score, 1.0), 4), {
        "present": present, "missing": missing,
        "header_details": details,
        "total_checked": len(SECURITY_HEADERS),
        "total_present": len(present),
    }


def probe_ssl_tls(url: str) -> tuple:
    parsed = urlparse(url)
    issues, score = [], 0.0

    if parsed.scheme != "https":
        return 1.0, {"issues": ["Site not served over HTTPS — all traffic is unencrypted"], "ssl_valid": False}

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=parsed.hostname) as s:
            s.settimeout(5)
            s.connect((parsed.hostname, parsed.port or 443))
            cert = s.getpeercert()
            cipher = s.cipher()

        # Check cipher strength
        cipher_name = cipher[0] if cipher else ""
        if any(weak in cipher_name.upper() for weak in ["RC4", "DES", "NULL", "EXPORT", "MD5"]):
            issues.append(f"Weak cipher in use: {cipher_name}")
            score += 0.4

        # Check cert expiry
        import datetime
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp - datetime.datetime.utcnow()).days
                if days_left < 30:
                    issues.append(f"SSL certificate expires in {days_left} days")
                    score += 0.3
                elif days_left < 90:
                    issues.append(f"SSL certificate expires soon ({days_left} days)")
                    score += 0.1
            except Exception:
                pass

        return round(min(score, 1.0), 4), {"issues": issues, "ssl_valid": True, "cipher": cipher_name}

    except ssl.SSLError as e:
        return 0.9, {"issues": [f"SSL error: {e}"], "ssl_valid": False}
    except Exception as e:
        return 0.5, {"issues": [f"Could not verify SSL: {e}"], "ssl_valid": False}


def probe_authentication_config(response: requests.Response, url: str) -> tuple:
    headers = {k.lower(): v for k, v in response.headers.items()}
    issues, score = [], 0.0

    if not url.startswith("https://"):
        issues.append("Site not served over HTTPS")
        score += 0.35

    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        if "secure" not in set_cookie.lower():
            issues.append("Session cookie missing Secure flag")
            score += 0.2
        if "httponly" not in set_cookie.lower():
            issues.append("Session cookie missing HttpOnly flag")
            score += 0.15
        if "samesite" not in set_cookie.lower():
            issues.append("Session cookie missing SameSite attribute")
            score += 0.1

    www_auth = headers.get("www-authenticate", "")
    if "basic" in www_auth.lower():
        issues.append("HTTP Basic Authentication in use (plaintext credentials)")
        score += 0.25

    return round(min(score, 1.0), 4), {"issues": issues, "status_code": response.status_code}


def probe_directory_permissions(response: requests.Response, base_url: str, session: requests.Session) -> tuple:
    issues, score, exposed, checked = [], 0.0, [], []
    sensitive_paths = [
        "/.git/", "/.env", "/config/", "/backup/", "/admin/",
        "/phpinfo.php", "/server-status", "/wp-config.php",
        "/.htaccess", "/web.config", "/robots.txt", "/.DS_Store",
        "/api/v1/", "/swagger/", "/api-docs/",
    ]

    for path in sensitive_paths:
        try:
            r = session.get(base_url.rstrip("/") + path, timeout=5, allow_redirects=False)
            checked.append(path)
            if r.status_code == 200:
                exposed.append(path)
                score += 0.1
                issues.append(f"Sensitive path accessible: {path}")
        except Exception:
            pass

    body = response.text[:5000].lower()
    if "index of /" in body or "parent directory" in body:
        issues.append("Directory listing enabled on root")
        score += 0.3

    return round(min(score, 1.0), 4), {"exposed_paths": exposed, "checked_paths": checked, "issues": issues}


def probe_error_handling(response: requests.Response, base_url: str, session: requests.Session) -> tuple:
    issues, score = [], 0.0
    error_patterns = [
        r"traceback \(most recent call", r"exception in thread", r"stack trace:",
        r"syntax error", r"mysql_fetch", r"ORA-\d{5}", r"Microsoft OLE DB",
        r"Warning: include\(", r"Fatal error:", r"Parse error:",
        r"undefined variable", r"SQLSTATE\[",
    ]
    body = response.text[:10000]
    for pattern in error_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            issues.append(f"Verbose error pattern: {pattern}")
            score += 0.15

    try:
        err_r = session.get(base_url.rstrip("/") + "/fuzzi_nonexistent_404_test", timeout=5)
        for pattern in error_patterns:
            if re.search(pattern, err_r.text[:5000], re.IGNORECASE):
                issues.append(f"Error page leaks info: {pattern}")
                score += 0.1
                break
    except Exception:
        pass

    return round(min(score, 1.0), 4), {"issues": issues}


def probe_debug_mode(response: requests.Response) -> tuple:
    issues, score = [], 0.0
    headers = {k.lower(): v for k, v in response.headers.items()}
    body = response.text[:10000].lower()

    for key in ("x-debug-token", "x-debug-token-link", "x-powered-by", "server"):
        if key in headers:
            issues.append(f"Header reveals info: {key}: {headers[key]}")
            score += 0.1

    for indicator in ["django.debug", "werkzeug debugger", "debug mode", "xdebug", "debug=true", "traceback"]:
        if indicator in body:
            issues.append(f"Debug indicator in body: {indicator}")
            score += 0.2

    return round(min(score, 1.0), 4), {"issues": issues}


def probe_access_control(response: requests.Response) -> tuple:
    issues, score = [], 0.0
    headers = {k.lower(): v for k, v in response.headers.items()}

    acao = headers.get("access-control-allow-origin", "")
    if acao == "*":
        issues.append("CORS wildcard (*) allows any origin")
        score += 0.4
    elif acao:
        issues.append(f"CORS allows origin: {acao}")
        score += 0.1

    acac = headers.get("access-control-allow-credentials", "")
    if acac.lower() == "true" and acao == "*":
        issues.append("CORS wildcard with credentials=true (critical)")
        score += 0.4

    if "x-frame-options" not in headers:
        issues.append("Missing X-Frame-Options (clickjacking risk)")
        score += 0.15

    if "x-content-type-options" not in headers:
        issues.append("Missing X-Content-Type-Options")
        score += 0.1

    return round(min(score, 1.0), 4), {"issues": issues, "cors_origin": acao}


def probe_cloud_config(response: requests.Response) -> tuple:
    issues, score = [], 0.0
    body = response.text[:5000]
    headers = {k.lower(): v for k, v in response.headers.items()}

    for leak in ["amazonaws.com", "s3.amazonaws.com", "AKIA", "aws_access_key",
                 "storage.googleapis.com", "blob.core.windows.net"]:
        if leak in body:
            issues.append(f"Cloud reference in response: {leak}")
            score += 0.15

    if "listbucketresult" in body.lower():
        issues.append("S3 bucket listing exposed")
        score += 0.5

    server = headers.get("server", "").lower()
    if any(x in server for x in ["aws", "gcp", "azure", "cloudfront"]):
        issues.append(f"Cloud server header exposed: {server}")
        score += 0.1

    return round(min(score, 1.0), 4), {"issues": issues}


def probe_input_validation(html_features: dict, response: requests.Response) -> tuple:
    issues, score = [], 0.0
    inputs = html_features.get("inputs", [])
    forms = html_features.get("forms", 0)

    if forms > 0:
        unprotected = 0
        for inp in inputs:
            itype = inp.get("type", "text").lower()
            if itype in ("text", "search", "email", "url", "tel", "number"):
                if not inp.get("pattern") and not inp.get("maxlength"):
                    unprotected += 1

        if unprotected > 0:
            ratio = unprotected / max(len(inputs), 1)
            score += ratio * 0.5
            issues.append(f"{unprotected} input(s) lack pattern/maxlength validation")

        # Check for CSRF token in forms
        has_csrf = any(
            inp.get("name", "").lower() in ("csrftoken", "_token", "csrf", "__requestverificationtoken")
            for inp in inputs
        )
        if not has_csrf and forms > 0:
            issues.append("No CSRF token detected in forms")
            score += 0.3

    return round(min(score, 1.0), 4), {"issues": issues, "forms": forms, "inputs_checked": len(inputs)}


def probe_third_party_risk(html: str) -> tuple:
    issues, score = [], 0.0
    third_party_patterns = [
        (r'src=["\']https?://(?!(?:www\.)?(?:your-domain))[^"\']+\.js', "External JS"),
        (r'href=["\']https?://fonts\.googleapis\.com', "Google Fonts"),
        (r'src=["\']https?://(?:cdn|ajax)\.googleapis\.com', "Google CDN"),
        (r'src=["\']https?://[^"\']*facebook[^"\']*', "Facebook SDK"),
        (r'src=["\']https?://[^"\']*twitter[^"\']*', "Twitter SDK"),
        (r'src=["\']https?://[^"\']*analytics[^"\']*', "Analytics script"),
        (r'src=["\']https?://[^"\']*gtag[^"\']*', "Google Tag"),
    ]
    found = []
    for pattern, label in third_party_patterns:
        if re.search(pattern, html, re.IGNORECASE):
            found.append(label)
            score += 0.08

    if found:
        issues.append(f"Third-party resources detected: {', '.join(found)}")

    return round(min(score, 1.0), 4), {"issues": issues, "third_party_resources": found}


# ---------------------------------------------------------------------------
# Quality probes (SEO, Readability, Design, Performance)
# ---------------------------------------------------------------------------

def probe_seo(html_features: dict, response: requests.Response) -> tuple:
    issues, score = [], 0.0
    headers = {k.lower(): v for k, v in response.headers.items()}

    if not html_features.get("title"):
        issues.append("Missing <title> tag")
        score += 0.25
    elif len(html_features["title"]) > 70:
        issues.append("Title tag too long (>70 chars)")
        score += 0.1

    if not html_features.get("meta_description"):
        issues.append("Missing meta description")
        score += 0.2
    elif len(html_features["meta_description"]) > 160:
        issues.append("Meta description too long (>160 chars)")
        score += 0.05

    if not html_features.get("h1_tags"):
        issues.append("No H1 tag found")
        score += 0.2
    elif len(html_features["h1_tags"]) > 1:
        issues.append(f"Multiple H1 tags ({len(html_features['h1_tags'])})")
        score += 0.1

    img_total = html_features.get("img_total", 0)
    img_missing_alt = html_features.get("img_alts_missing", 0)
    if img_total > 0 and img_missing_alt > 0:
        ratio = img_missing_alt / img_total
        score += ratio * 0.2
        issues.append(f"{img_missing_alt}/{img_total} images missing alt text")

    # Check robots meta
    body = response.text[:5000].lower()
    if 'name="robots"' in body and 'noindex' in body:
        issues.append("Page has noindex meta tag")
        score += 0.15

    return round(min(score, 1.0), 4), {"issues": issues, "title": html_features.get("title", ""), "h1_count": len(html_features.get("h1_tags", []))}


def probe_readability(html_features: dict) -> tuple:
    issues, score = [], 0.0
    text = html_features.get("full_text", "")
    word_count = html_features.get("word_count", 0)

    if word_count < 100:
        issues.append(f"Very little text content ({word_count} words)")
        score += 0.3

    # Average sentence length
    sentences = re.split(r'[.!?]+', text)
    sentences = [s.strip() for s in sentences if len(s.strip()) > 10]
    if sentences:
        avg_words = sum(len(s.split()) for s in sentences) / len(sentences)
        if avg_words > 30:
            issues.append(f"Long average sentence length ({avg_words:.0f} words)")
            score += 0.2
        elif avg_words > 20:
            score += 0.1

    # Paragraph density (h2 tags as proxy)
    h2_count = len(html_features.get("h2_tags", []))
    if word_count > 500 and h2_count == 0:
        issues.append("Long content with no subheadings (H2)")
        score += 0.15

    return round(min(score, 1.0), 4), {"issues": issues, "word_count": word_count, "sentence_count": len(sentences)}


def probe_design_consistency(html: str, response: requests.Response) -> tuple:
    issues, score = [], 0.0

    # Multiple conflicting font families
    font_families = re.findall(r'font-family\s*:\s*([^;}"\']+)', html, re.IGNORECASE)
    unique_fonts = set(f.strip().lower() for f in font_families)
    if len(unique_fonts) > 4:
        issues.append(f"Too many font families ({len(unique_fonts)})")
        score += 0.2

    # Inline styles (design inconsistency indicator)
    inline_styles = len(re.findall(r'style\s*=\s*["\']', html))
    if inline_styles > 20:
        issues.append(f"Heavy use of inline styles ({inline_styles} instances)")
        score += 0.15

    # Multiple stylesheets
    stylesheets = re.findall(r'<link[^>]+rel=["\']stylesheet["\'][^>]*>', html, re.IGNORECASE)
    if len(stylesheets) > 8:
        issues.append(f"Many external stylesheets ({len(stylesheets)})")
        score += 0.1

    # Viewport meta
    if 'name="viewport"' not in html.lower():
        issues.append("Missing viewport meta tag (not mobile-friendly)")
        score += 0.25

    return round(min(score, 1.0), 4), {"issues": issues, "inline_styles": inline_styles, "stylesheets": len(stylesheets)}


def probe_performance_risk(html: str, response: requests.Response) -> tuple:
    issues, score = [], 0.0
    headers = {k.lower(): v for k, v in response.headers.items()}

    # No caching headers
    if "cache-control" not in headers and "expires" not in headers:
        issues.append("No caching headers (Cache-Control / Expires)")
        score += 0.2

    # No compression
    content_encoding = headers.get("content-encoding", "")
    if not content_encoding:
        issues.append("No content compression (gzip/br not detected)")
        score += 0.15

    # Large number of scripts
    scripts = re.findall(r'<script[^>]*src=["\'][^"\']+["\']', html, re.IGNORECASE)
    if len(scripts) > 15:
        issues.append(f"Many external scripts ({len(scripts)}) — high load time risk")
        score += 0.2
    elif len(scripts) > 8:
        score += 0.1

    # Large number of images without lazy loading
    imgs = re.findall(r'<img[^>]*>', html, re.IGNORECASE)
    lazy_imgs = [i for i in imgs if 'loading="lazy"' in i.lower() or "lazy" in i.lower()]
    if len(imgs) > 5 and len(lazy_imgs) == 0:
        issues.append(f"{len(imgs)} images without lazy loading")
        score += 0.15

    # Response time proxy (content-length)
    content_length = int(headers.get("content-length", 0))
    if content_length > 500_000:
        issues.append(f"Large page size ({content_length // 1024}KB)")
        score += 0.2

    return round(min(score, 1.0), 4), {"issues": issues, "scripts_count": len(scripts), "images_count": len(imgs)}


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

def scan_target(url: str, options: dict = None) -> dict:
    """
    Full scan of a target URL.
    Returns factor scores (0-1 risk) + raw details for all 14 dimensions.
    """
    options = options or {}
    result = {
        "url": url,
        "scan_time": time.time(),
        "reachable": False,
        "status_code": None,
        "ssl_valid": False,
        "factors": {},
        "raw_details": {},
        "html_features": {},
        "errors": [],
    }

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Fuzzi-Security-Scanner/2.0 (Web Security Auditor)",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })

    # SSL probe (independent of HTTP request)
    ssl_score, ssl_details = probe_ssl_tls(url)
    result["ssl_valid"] = ssl_details.get("ssl_valid", False)

    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    try:
        response = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        result["reachable"] = True
        result["status_code"] = response.status_code
        html = response.text

        # Extract HTML features once
        html_features = extract_html_features(html)
        result["html_features"] = html_features

        # Run all probes
        sh_score,    sh_det    = probe_security_headers(response)
        auth_score,  auth_det  = probe_authentication_config(response, url)
        dir_score,   dir_det   = probe_directory_permissions(response, base_url, session)
        err_score,   err_det   = probe_error_handling(response, base_url, session)
        dbg_score,   dbg_det   = probe_debug_mode(response)
        ac_score,    ac_det    = probe_access_control(response)
        cloud_score, cloud_det = probe_cloud_config(response)
        iv_score,    iv_det    = probe_input_validation(html_features, response)
        tp_score,    tp_det    = probe_third_party_risk(html)
        seo_score,   seo_det   = probe_seo(html_features, response)
        read_score,  read_det  = probe_readability(html_features)
        des_score,   des_det   = probe_design_consistency(html, response)
        perf_score,  perf_det  = probe_performance_risk(html, response)

        result["factors"] = {
            "security_headers":      sh_score,
            "authentication_config": auth_score,
            "directory_permissions": dir_score,
            "error_handling":        err_score,
            "debug_mode":            dbg_score,
            "access_control":        ac_score,
            "cloud_config":          cloud_score,
            "ssl_tls_config":        ssl_score,
            "input_validation":      iv_score,
            "third_party_risk":      tp_score,
            "seo_score":             seo_score,
            "readability_score":     read_score,
            "design_consistency":    des_score,
            "performance_risk":      perf_score,
        }
        result["raw_details"] = {
            "security_headers":      sh_det,
            "authentication_config": auth_det,
            "directory_permissions": dir_det,
            "error_handling":        err_det,
            "debug_mode":            dbg_det,
            "access_control":        ac_det,
            "cloud_config":          cloud_det,
            "ssl_tls_config":        ssl_details,
            "input_validation":      iv_det,
            "third_party_risk":      tp_det,
            "seo_score":             seo_det,
            "readability_score":     read_det,
            "design_consistency":    des_det,
            "performance_risk":      perf_det,
        }

    except RequestException as e:
        result["errors"].append(f"Request failed: {e}")
        logger.error("Scan failed for %s: %s", url, e)
        result["factors"] = {k: 0.8 for k in [
            "security_headers", "authentication_config", "directory_permissions",
            "error_handling", "debug_mode", "access_control", "cloud_config",
            "ssl_tls_config", "input_validation", "third_party_risk",
            "seo_score", "readability_score", "design_consistency", "performance_risk",
        ]}

    return result

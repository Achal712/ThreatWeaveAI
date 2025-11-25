#!/usr/bin/env python3
"""
modules/eml_parser.py — Improved EML parser for full URL extraction and attachment extraction.
"""
from __future__ import annotations

import re
import html
import base64
import quopri
import hashlib
from typing import List, Dict, Any, Optional
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup

# Regex robust enough to catch complex tracking URLs
URL_RE = re.compile(
    r'((?:https?://|http://|www\.)[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+)',
    re.IGNORECASE
)

# do not extract cid function
def _is_cid_url(u: str) -> bool:
    """
    Return True if the URL-like string is an inline/cid reference that should not be
    treated as an external URL (e.g., "cid:1234", "content-id:...").
    """
    if not u:
        return False
    u = str(u).strip().lower()
    # common inline schemes: cid:, content-id:, data: (data: URIs are sometimes inline too)
    if u.startswith("cid:") or u.startswith("content-id:"):
        return True
    # Optionally treat data: URIs as inline (image embedded inlined as base64). We avoid extracting those.
    if u.startswith("data:"):
        return True
    if not u:
        return False
    u = str(u).strip().lower()
    # common inline schemes or mailto
    if u.startswith("cid:") or u.startswith("content-id:"):
        return True
    if u.startswith("data:"):
        return True
    if u.startswith("mailto:"):
        return True
    return False

def _decode_text(payload: Optional[str]) -> str:
    """Decode text from quoted-printable or base64 safely."""
    if not payload:
        return ""
    text = payload

    # Quoted-printable signatures
    if "=3D" in text or "=\r\n" in text or "=\n" in text:
        try:
            text = quopri.decodestring(text).decode("utf-8", errors="ignore")
        except Exception:
            pass

    # Try base64 block decode if it looks like base64
    try:
        s = text.strip()
        if s and re.fullmatch(r"[A-Za-z0-9+/=\r\n]+", s) and len(s) % 4 == 0:
            decoded = base64.b64decode(s)
            # only accept if mostly printable
            dec_str = decoded.decode("utf-8", errors="ignore")
            printable_ratio = sum(1 for c in dec_str if c.isprintable()) / max(1, len(dec_str))
            if printable_ratio > 0.8:
                text = dec_str
    except Exception:
        pass

    return text


def extract_urls_from_html(html_data: str) -> List[str]:
    """Extract URLs from HTML content (tags + fallback regex). Skip inline/cid/data URIs."""
    if not html_data:
        return []

    decoded_html = _decode_text(html_data)
    decoded_html = decoded_html.replace("=\r\n", "").replace("=\n", "")
    decoded_html = html.unescape(decoded_html)

    soup = BeautifulSoup(decoded_html, "html.parser")
    urls = set()

    # tags with href/src/action - but skip cid/data/content-id entries
    for tag in soup.find_all(["a", "link"], href=True):
        href = tag.get("href")
        if href and not _is_cid_url(href):
            urls.add(href)
    for tag in soup.find_all(["img", "script", "iframe"], src=True):
        src = tag.get("src")
        if src and not _is_cid_url(src):
            urls.add(src)
    for tag in soup.find_all("form", action=True):
        action = tag.get("action")
        if action and not _is_cid_url(action):
            urls.add(action)

    # fallback regex scan
    for m in re.findall(URL_RE, decoded_html):
        if m and not _is_cid_url(m):
            urls.add(m)

    # normalize
    clean_urls = []
    for u in urls:
        if not u:
            continue
        u = html.unescape(str(u)).strip().replace("\r", "").replace("\n", "")
        u = u.replace("=3D", "=")
        if u.startswith("www."):
            u = "http://" + u
        clean_urls.append(u)
    return list(dict.fromkeys(clean_urls))


def extract_urls_from_text(text: str) -> List[str]:
    """Extract URLs from plain text body. Skip inline/cid/data URIs."""
    if not text:
        return []

    decoded_text = _decode_text(text)
    decoded_text = decoded_text.replace("=\r\n", "").replace("=\n", "")
    decoded_text = html.unescape(decoded_text)

    found = re.findall(URL_RE, decoded_text)
    clean = []
    for u in found:
        if not u:
            continue
        u = html.unescape(u.strip().replace("\r", "").replace("\n", ""))
        u = u.replace("=3D", "=")
        # skip cid/data/content-id URIs
        if _is_cid_url(u):
            continue
        if u.startswith("www."):
            u = "http://" + u
        clean.append(u)
    return list(dict.fromkeys(clean))


def _sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def parse_eml(file_path: str) -> Dict[str, Any]:
    """
    Parse EML and return a structured dict with:
    - headers, from, subject, date, source_ip
    - body_text (preview), body_html (preview)
    - urls (list)
    - attachments: list of {filename, content_type, size, sha256, data}
    """
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = dict(msg.items())
    from_header = msg.get("From", "") or ""
    subject = msg.get("Subject", "") or ""
    date = msg.get("Date", "") or ""
    # X-BESS-Apparent-Source-IP compatibility
    source_ip = headers.get("X-BESS-Apparent-Source-IP", "") or headers.get("X-BESS-Apparent-SourceIP", "") or ""

    body_text = ""
    body_html = ""
    attachments: List[Dict[str, Any]] = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = (part.get_content_disposition() or "") or ""
            filename = part.get_filename()
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None

            # gather inline text/html
            if ctype in ("text/plain", "text/html") and "attachment" not in disp:
                if payload:
                    try:
                        decoded = payload.decode("utf-8", errors="ignore")
                    except Exception:
                        decoded = str(payload)
                    if ctype == "text/html":
                        body_html += decoded
                    else:
                        body_text += decoded

            # attachments (including embedded images)
            if filename or disp == "attachment" or (payload and ctype not in ("text/plain", "text/html")):
                try:
                    b = payload or b""
                    fname = filename or (part.get("Content-Location") or "unknown")
                    sha = _sha256_bytes(b) if b else None
                    attachments.append({
                        "filename": fname,
                        "content_type": ctype,
                        "size": len(b),
                        "sha256": sha,
                        "data": b
                    })
                except Exception:
                    # best-effort: skip problematic attachment
                    continue
    else:
        # singlepart
        ctype = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
        except Exception:
            payload = None
        if payload:
            try:
                decoded = payload.decode("utf-8", errors="ignore")
            except Exception:
                decoded = str(payload)
            if ctype == "text/html":
                body_html = decoded
            else:
                body_text = decoded

    # Extract URLs
    urls = set()
    urls.update(extract_urls_from_text(body_text or ""))
    urls.update(extract_urls_from_html(body_html or ""))

    return {
        "from": from_header,
        "subject": subject,
        "date": date,
        "source_ip": source_ip,
        "urls": list(urls),
        "body_text": (body_text or "")[:2000],
        "body_html": (body_html or "")[:2000],
        "headers": headers,
        "attachments": attachments
    }

if __name__ == "__main__":
    import sys, json
    if len(sys.argv) > 1:
        out = parse_eml(sys.argv[1])
        print(json.dumps(out, indent=2, default=str))

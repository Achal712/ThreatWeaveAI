import os
import json
import re
import requests
import time
from config import settings
from modules.oauth_analyzer import analyze_oauth_url

SAGE_URL = settings.SAGE_API_URL
API_KEY = settings.SAGE_API_KEY

# small helper to extract a JSON object from a string (first {...} block)
def _extract_json_block(s: str):
    # find the first { and last } that form a valid JSON substring (greedy)
    start = s.find('{')
    if start == -1:
        return None
    # attempt progressively larger substrings until json.loads succeeds
    for end in range(len(s), start, -1):
        if s[end-1] != '}':
            continue
        candidate = s[start:end]
        try:
            return json.loads(candidate)
        except Exception:
            continue
    return None

def analyze_with_sage(context):
    if not API_KEY:
        return {'error': 'SAGE_API_KEY not set. Please set it in .env or config/settings.py'}

    body = context.get('body', '')
    subject = context.get('subject', '')
    urls = context.get('urls', [])
    local_findings = context.get('local_findings', {})

    oauth_analyses = []
    for u in urls:
        try:
            oauth_analyses.append(analyze_oauth_url(u))
        except Exception as e:
            oauth_analyses.append({'url': u, 'error': str(e)})

    prompt_obj = {
        'task': 'Threat Analysis of Potential Malicious/Suspicious Email',
        'subject': subject,
        'body_snippet': body[:2000],
        'urls': urls,
        'local_findings': local_findings,
        'oauth_analysis': oauth_analyses,
    }

    prompt = f"""
        You are a cybersecurity analyst LLM. Analyze the input and return JSON only with fields:
        Type of Attack (Taxonomy_list: Account Takeover, Conversation Hijacking, Business Email Compromise (BEC), Phishing, Spam , Extortion), is_phishing (bool), phishing_type (string), confidence_score (0-100),
        Brief_summary (Generate a brief summary (1-2 paragraph) that includes key details about the topic and incorporates local_findings. The summary should be professional,technical,concise, informative, and context-aware.), techniques (list), ioc_domains (list),
        recommended_actions (list of strings 2-3), URL_Evasion Techniques (list of strings), regex_indicator (list of objects), Phaas_kit (string),prompt_tokens(integer),completion_tokens(integer),total_tokens(integer).

        Produce exactly one JSON object and nothing else (no prose, no code fences, no extra fields). Use the provided input (body, subject, urls, and especially local_findings) to populate the fields above.

        CRITICAL RULE: Only generate `regex_indicator` entries when `Type_of_Attack` equals "Phishing" or 'Type_of_Attack' equals "phishing". For any other taxonomy (including Ham, BEC, etc.) `regex_indicator` must be an empty array or omitted.

        Regex / indicator style and evidence rules (required):
        1) Use local_findings: Prefer creating indicators directly from evidence found in `local_findings` (suspicious_urls, redirect_traces, attachment names/hashes, header anomalies); do not invent unrelated indicators.

        2) Regex formatting:
        - Anchor URL patterns with `^` and escape slashes (use `\\/`).
        - When matching OAuth `redirect_uri` or similar percent-encoded params use percent-encoded form (e.g. `redirect_uri=https%3A%2F%2F`).
        - Use character classes and bounded quantifiers instead of broad `.*`. Prefer patterns like `[^#\\s]*` to stop at fragments/spaces or `[^&]*` to stop at the next param.
        - Example desired pattern:
            `^https:\\/\\/login\\.microsoftonline\\.com\\/organizations\\/oauth2\\/v2\\.0\\/authorize\\?[^#\\s]*redirect_uri=https%3A%2F%2F(?:[\\w.-]+\\.)?tetainternational\\.com(?:%2F[^\\s]*)?`

        3) Normalization semantics:
        - If the indicator targets raw/encoded fragments (percent-encoded redirect_uri, base64 client_id), set `"normalized": false`.
        - If the indicator targets canonical hosts/paths (clean, unencoded), set `"normalized": true`.
        - Prefer `"normalized": false` for encoded/obfuscated fragments so rules match logs/forensics.

        4) Headless and determination:
        - `"headless": false` for indicators requiring full URL inspection; `"headless": true` only for header-only/light checks.
        - `"determination"` must be all-caps: `SUSPICIOUS` or `MALICIOUS`. Use `MALICIOUS` only when highly confident.

        5) Highlights naming:
        - Provide short uppercase highlight IDs. For high-confidence OAuth redirect indicators start with `H-` and use hyphens, e.g. `H-MS-OAUTH-TETAINTERNATIONAL-REDIRECT`.
        - Avoid lowercase or verbose names.

        6) Known benign hosts:
        - If the top-level host is a known benign provider (e.g., `microsoftonline.com`, `google.com`, link-protection wrappers), DO NOT emit a domain-based indicator for that benign host.
        - Instead inspect query params and produce indicators for embedded/obfuscated targets (percent-encoded `redirect_uri`, nested domains, base64 payloads).

        7) `regex_indicator` object fields (required when present):
        - `strings`: non-empty array of regex strings or literal substrings (escape slashes/backslashes; use anchors).
        - `or`: boolean — true if `strings` are alternatives (OR).
        - `regex`: boolean — true when `strings` are regexes.
        - `type`: one of `"URL"`, `"HTML"`, `"ATTACHMENT"`.
        - `normalized`: boolean.
        - `headless`: boolean.
        - `determination`: `"SUSPICIOUS"` or `"MALICIOUS"`.
        - `description`: short human-friendly explanation (1 sentence).
        - `highlights`: array of 1+ short unique tag strings (UPPERCASE_WITH_UNDERSCORES or H-...).

        8) Other constraints:
        - `recommended_actions` must contain 2 or 3 clear action items.
        - `URL_Evasion Techniques` should list observed evasion patterns (short strings).
        - Do not produce `regex_indicator` for clean/benign findings — leave empty/omitted.
        - Use `or` appropriately when offering multiple alternative regexes for the same logical indicator.

        Return only JSON that follows these rules. Input: {json.dumps(prompt_obj)}
        """


    response_schema = {
    "type": "object",
    "properties": {
        "Type_of_Attack": { "type": "string" },
        "is_phishing": { "type": "boolean" },
        "phishing_type": { "type": "string" },
        "confidence_score": { "type": "number" },
        "Brief_summary": { "type": "string" },
        "techniques": {
        "type": "array",
        "items": { "type": "string" }
        },
        "ioc_domains": {
        "type": "array",
        "items": { "type": "string" }
        },
        "recommended_actions": {
        "type": "array",
        "items": { "type": "string" }
        },
        "Phaas_kit": { "type": ["string", "null"] },

        "regex_indicator": {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
            "strings": {
                "type": "array",
                "items": { "type": "string" },
                "minItems": 1,
                "description": "List of regex patterns generated for this indicator"
            },
            "or": { "type": "boolean" },
            "regex": { "type": "boolean" },
            "type": {
                "type": "string",
                "enum": ["URL", "HTML", "ATTACHMENT"]
            },
            "normalized": { "type": "boolean" },
            "headless": { "type": "boolean" },
            "determination": {
                "type": "string",
                "enum": ["SUSPICIOUS", "MALICIOUS", "CLEAN"]
            },
            "description": { "type": "string" },
            "highlights": {
                "type": "array",
                "items": { "type": "string" }
            }
            },
            "required": [
            "strings",
            "regex",
            "type",
            "normalized",
            "headless",
            "determination"
            ]
        }
        },

        "completion_tokens": { "type": "integer" },
        "prompt_tokens": { "type": "integer" },
        "total_tokens": { "type": "integer" }
    },

    "required": [
        "Type_of_Attack",
        "is_phishing",
        "phishing_type",
        "confidence_score",
        "completion_tokens",
        "prompt_tokens",
        "total_tokens"
    ]
    }

    headers = {'Authorization': f'Bearer {API_KEY}', 'Content-Type': 'application/json'}
    data = {
    'model': 'gpt-5',
    'messages': [
        {'role': 'system', 'content': 'You are a cybersecurity analyst.'},
        {'role': 'user', 'content': prompt}
    ],
    'temperature': 0.0,
    'response_format': {
        "type": "json_schema",
        "json_schema": {
            "name": "phish_analysis",
            "schema": response_schema
            }
        }
    }


    try:
        r = requests.post(SAGE_URL, headers=headers, json=data, timeout=120)
    except Exception as e:
        return {'error': f'HTTP request failed: {e}'}

    if r.status_code != 200:
        # return raw body to help debugging
        return {'error': f'HTTP {r.status_code}', 'raw': r.text}

    try:
        resp = r.json()
    except Exception:
        # not JSON? return raw text for debugging
        return {'error': 'Response not JSON', 'raw': r.text}

    # 1) If the API returned a top-level JSON object (ideal)
    if isinstance(resp, dict):
        # common case for SAGE/OAI where they might already return the object
        # check that it looks like our analysis by presence of a key
        if 'Type of Attack' in resp or 'is_phishing' in resp:
            return resp

    # 2) Check for OpenAI-like "choices" structure where content is a string
    # (e.g., resp['choices'][0]['message']['content'])
    try:
        choices = resp.get('choices') or resp.get('results') or None
        if isinstance(choices, list) and len(choices) > 0:
            # try a few common locations for the content text
            content = None
            first = choices[0]
            # new chat format
            if isinstance(first, dict):
                msg = first.get('message') or first.get('text') or first.get('output_text') or first
                if isinstance(msg, dict):
                    content = msg.get('content') or msg.get('text') or None
                elif isinstance(msg, str):
                    content = msg
                else:
                    # sometimes choices[0]['text']
                    content = first.get('text') or first.get('message')
            # fallback: choices[0] might directly be a string
            if content is None and isinstance(first, str):
                content = first

            # if we got content as a string, try to parse it
            if isinstance(content, str):
                # first quick attempt: direct json.loads if it's clean JSON
                try:
                    parsed = json.loads(content)
                    if isinstance(parsed, dict):
                        return parsed
                except Exception:
                    pass

                # next: try to extract a JSON {...} block from the string
                parsed = _extract_json_block(content)
                if parsed:
                    return parsed

                # last fallback: sometimes the API returns escaped JSON inside a "content" key:
                # e.g. {"content": "{...json...}", "role": "assistant"}
                try:
                    # attempt to find nested "content": "{"..."}" patterns
                    m = re.search(r'"content"\s*:\s*"(\\\{.*?\\\})"', content, flags=re.DOTALL)
                    if m:
                        candidate = m.group(1).encode('utf-8').decode('unicode_escape')
                        parsed = json.loads(candidate)
                        if isinstance(parsed, dict):
                            return parsed
                except Exception:
                    pass

    except Exception:
        # ignore parse errors in the attempts above and continue to returning raw for debug
        pass

    # If we reach here, we couldn't reliably parse a JSON object — return full response for debugging
    return {'error': 'Could not parse model output as JSON object', 'raw_response': resp}












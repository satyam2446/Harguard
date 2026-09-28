import json
import re
import hashlib
import urllib.parse
from typing import Dict, Any, List, Tuple, Set, Optional

SENSITIVE_COOKIE_KEYWORDS = {
    "session", "sess", "sid", "token", "auth", "jwt", "connect.sid",
    "jsessionid", "phpsessid", "aspsessionid", "okta_session", "dtcookie",
    "csrftoken", "xsrf", "xsrf-token", "cf_clearance", "remember", "ticket",
    "authorization", "id_token", "access_token", "refresh_token"
}

SENSITIVE_PARAM_KEYWORDS = {
    "token", "access_token", "id_token", "refresh_token", "auth", "code",
    "api_key", "apikey", "key", "secret", "client_secret", "password",
    "passwd", "pwd", "signature", "sig", "bearer", "private_key"
}

SENSITIVE_HEADER_NAMES = {
    "authorization", "proxy-authorization", "x-api-key", "x-auth-token",
    "x-access-token", "apikey", "okta-access-token", "x-gitlab-token",
    "x-github-token", "x-slack-token"
}

REGEX_PATTERNS = {
    "JWT_TOKEN": (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "JWT"),
    "AWS_KEY": (re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"), "AWS_ACCESS_KEY"),
    "GITHUB_TOKEN": (re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"), "GITHUB_TOKEN"),
    "SLACK_TOKEN": (re.compile(r"xox[baprs]-[0-9A-Za-z_-]{10,48}"), "SLACK_TOKEN"),
    "STRIPE_KEY": (re.compile(r"(?:sk|rk)_live_[0-9a-zA-Z]{24,}"), "STRIPE_KEY"),
    "PRIVATE_KEY_BLOCK": (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "PRIVATE_KEY"),
    "BASIC_AUTH": (re.compile(r"^Basic\s+([A-Za-z0-9+/=]{8,})", re.IGNORECASE), "BASIC_AUTH_CREDENTIAL"),
    "BEARER_AUTH": (re.compile(r"^Bearer\s+(?!\[REDACTED)(.+)$", re.IGNORECASE), "BEARER_TOKEN")
}


def is_already_redacted(val: str) -> bool:
    return isinstance(val, str) and val.startswith("[REDACTED_") and val.endswith("]")


class HarSanitizer:
    def __init__(self, salt: Optional[str] = None, redact_all_cookies: bool = False):
        self.salt = salt or "harguard-default-deterministic-salt"
        self.redact_all_cookies = redact_all_cookies
        self.redaction_log: List[Dict[str, Any]] = []

    def _hash_val(self, val: str, prefix: str) -> str:
        if is_already_redacted(val):
            return val
        digest = hashlib.sha256((self.salt + val).encode("utf-8")).hexdigest()[:8]
        return f"[REDACTED_{prefix}_{digest}]"

    def _is_sensitive_cookie(self, name: str) -> bool:
        if self.redact_all_cookies:
            return True
        low = name.lower()
        return any(k in low for k in SENSITIVE_COOKIE_KEYWORDS)

    def _is_sensitive_param(self, name: str) -> bool:
        low = name.lower()
        return any(k in low for k in SENSITIVE_PARAM_KEYWORDS)

    def sanitize_cookie_header(self, header_value: str) -> Tuple[str, int]:
        parts = header_value.split(";")
        new_parts = []
        redactions = 0
        for part in parts:
            part_str = part.strip()
            if not part_str:
                continue
            if "=" in part_str:
                k, v = part_str.split("=", 1)
                k_clean = k.strip()
                v_clean = v.strip()
                if self._is_sensitive_cookie(k_clean) and not is_already_redacted(v_clean):
                    masked = self._hash_val(v_clean, "COOKIE")
                    new_parts.append(f"{k_clean}={masked}")
                    redactions += 1
                    self.redaction_log.append({
                        "type": "COOKIE_HEADER",
                        "name": k_clean,
                        "original_length": len(v_clean)
                    })
                else:
                    new_parts.append(f"{k_clean}={v_clean}")
            else:
                new_parts.append(part_str)
        return "; ".join(new_parts), redactions

    def sanitize_headers(self, headers: List[Dict[str, str]]) -> List[Dict[str, str]]:
        cleaned = []
        for h in headers:
            name = h.get("name", "")
            val = h.get("value", "")
            name_low = name.lower()

            if name_low in SENSITIVE_HEADER_NAMES:
                if not is_already_redacted(val):
                    masked = self._hash_val(val, "AUTH_HEADER")
                    cleaned.append({"name": name, "value": masked})
                    self.redaction_log.append({
                        "type": "HEADER_AUTH",
                        "name": name,
                        "original_length": len(val)
                    })
                else:
                    cleaned.append({"name": name, "value": val})
            elif name_low == "cookie":
                new_val, _ = self.sanitize_cookie_header(val)
                cleaned.append({"name": name, "value": new_val})
            elif name_low == "set-cookie":
                tokens = val.split(";")
                first_token = tokens[0] if tokens else ""
                rest = tokens[1:] if len(tokens) > 1 else []
                if "=" in first_token:
                    k, v = first_token.split("=", 1)
                    k_clean = k.strip()
                    v_clean = v.strip()
                    if self._is_sensitive_cookie(k_clean) and not is_already_redacted(v_clean):
                        masked = self._hash_val(v_clean, "SET_COOKIE")
                        self.redaction_log.append({
                            "type": "SET_COOKIE_HEADER",
                            "name": k_clean,
                            "original_length": len(v_clean)
                        })
                        new_first = f"{k_clean}={masked}"
                    else:
                        new_first = first_token
                    rest_str = ("; " + "; ".join(t.strip() for t in rest)) if rest else ""
                    cleaned.append({"name": name, "value": new_first + rest_str})
                else:
                    cleaned.append({"name": name, "value": val})
            else:
                cleaned.append({"name": name, "value": self._scrub_regex_patterns(val)})
        return cleaned

    def sanitize_cookies_array(self, cookies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        cleaned = []
        for c in cookies:
            name = c.get("name", "")
            val = c.get("value", "")
            if self._is_sensitive_cookie(name) and not is_already_redacted(val):
                c_copy = dict(c)
                c_copy["value"] = self._hash_val(val, "COOKIE_PARAM")
                self.redaction_log.append({
                    "type": "COOKIES_ARRAY",
                    "name": name,
                    "original_length": len(val)
                })
                cleaned.append(c_copy)
            else:
                cleaned.append(c)
        return cleaned

    def sanitize_query_string(self, query_params: List[Dict[str, str]], url: str) -> Tuple[List[Dict[str, str]], str]:
        cleaned_params = []
        for q in query_params:
            name = q.get("name", "")
            val = q.get("value", "")
            if self._is_sensitive_param(name) and not is_already_redacted(val):
                masked = self._hash_val(val, "QUERY_PARAM")
                cleaned_params.append({"name": name, "value": masked})
                self.redaction_log.append({
                    "type": "QUERY_PARAM",
                    "name": name,
                    "original_length": len(val)
                })
            else:
                cleaned_params.append(q)

        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            qs_dict = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            new_qs = []
            for k, vs in qs_dict.items():
                if self._is_sensitive_param(k):
                    for v in vs:
                        if not is_already_redacted(v):
                            new_qs.append((k, self._hash_val(v, "URL_PARAM")))
                        else:
                            new_qs.append((k, v))
                else:
                    for v in vs:
                        new_qs.append((k, v))
            new_query_str = urllib.parse.urlencode(new_qs)
            new_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query_str, parsed.fragment
            ))
        else:
            new_url = url

        return cleaned_params, new_url

    def _scrub_json_recursive(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            new_dict = {}
            for k, v in obj.items():
                if self._is_sensitive_param(k) and isinstance(v, (str, int, float)):
                    s_val = str(v)
                    if not is_already_redacted(s_val):
                        new_dict[k] = self._hash_val(s_val, "JSON_SECRET")
                        self.redaction_log.append({
                            "type": "JSON_KEY",
                            "name": k,
                            "original_length": len(s_val)
                        })
                    else:
                        new_dict[k] = s_val
                else:
                    new_dict[k] = self._scrub_json_recursive(v)
            return new_dict
        elif isinstance(obj, list):
            return [self._scrub_json_recursive(item) for item in obj]
        elif isinstance(obj, str):
            return self._scrub_regex_patterns(obj)
        return obj

    def _scrub_regex_patterns(self, text: str) -> str:
        if is_already_redacted(text):
            return text
        scrubbed = text
        for pat_name, (pattern, label) in REGEX_PATTERNS.items():
            matches = list(pattern.finditer(scrubbed))
            for m in reversed(matches):
                original = m.group(0)
                if not is_already_redacted(original):
                    masked = self._hash_val(original, label)
                    scrubbed = scrubbed[:m.start()] + masked + scrubbed[m.end():]
                    self.redaction_log.append({
                        "type": f"REGEX_{pat_name}",
                        "pattern": pat_name,
                        "original_length": len(original)
                    })
        return scrubbed

    def sanitize_post_data(self, post_data: Dict[str, Any]) -> Dict[str, Any]:
        cleaned = dict(post_data)
        mime = post_data.get("mimeType", "").lower()
        text = post_data.get("text", "")

        if "params" in post_data and isinstance(post_data["params"], list):
            new_params = []
            for p in post_data["params"]:
                name = p.get("name", "")
                val = p.get("value", "")
                if self._is_sensitive_param(name) and not is_already_redacted(val):
                    masked = self._hash_val(val, "POST_PARAM")
                    new_params.append({"name": name, "value": masked})
                    self.redaction_log.append({
                        "type": "POST_PARAM",
                        "name": name,
                        "original_length": len(val)
                    })
                else:
                    new_params.append(p)
            cleaned["params"] = new_params

        if text:
            if "application/json" in mime:
                try:
                    parsed = json.loads(text)
                    scrubbed_obj = self._scrub_json_recursive(parsed)
                    cleaned["text"] = json.dumps(scrubbed_obj)
                except Exception:
                    cleaned["text"] = self._scrub_regex_patterns(text)
            elif "application/x-www-form-urlencoded" in mime:
                try:
                    pairs = urllib.parse.parse_qsl(text, keep_blank_values=True)
                    new_pairs = []
                    for k, v in pairs:
                        if self._is_sensitive_param(k) and not is_already_redacted(v):
                            new_pairs.append((k, self._hash_val(v, "FORM_PARAM")))
                            self.redaction_log.append({
                                "type": "FORM_URLENCODED",
                                "name": k,
                                "original_length": len(v)
                            })
                        else:
                            new_pairs.append((k, v))
                    cleaned["text"] = urllib.parse.urlencode(new_pairs)
                except Exception:
                    cleaned["text"] = self._scrub_regex_patterns(text)
            else:
                cleaned["text"] = self._scrub_regex_patterns(text)

        return cleaned

    def sanitize_response_content(self, content: Dict[str, Any]) -> Dict[str, Any]:
        cleaned = dict(content)
        text = content.get("text", "")
        mime = content.get("mimeType", "").lower()

        if text:
            if "application/json" in mime:
                try:
                    parsed = json.loads(text)
                    scrubbed = self._scrub_json_recursive(parsed)
                    cleaned["text"] = json.dumps(scrubbed)
                except Exception:
                    cleaned["text"] = self._scrub_regex_patterns(text)
            else:
                cleaned["text"] = self._scrub_regex_patterns(text)
        return cleaned

    def sanitize_har(self, har_data: Dict[str, Any]) -> Dict[str, Any]:
        log_obj = har_data.get("log", {})
        entries = log_obj.get("entries", [])
        cleaned_entries = []

        for entry in entries:
            req = entry.get("request", {})
            res = entry.get("response", {})

            cleaned_req = dict(req)
            if "headers" in req:
                cleaned_req["headers"] = self.sanitize_headers(req["headers"])
            if "cookies" in req:
                cleaned_req["cookies"] = self.sanitize_cookies_array(req["cookies"])
            if "queryString" in req and "url" in req:
                cleaned_qs, new_url = self.sanitize_query_string(req["queryString"], req["url"])
                cleaned_req["queryString"] = cleaned_qs
                cleaned_req["url"] = new_url
            if "postData" in req:
                cleaned_req["postData"] = self.sanitize_post_data(req["postData"])

            cleaned_res = dict(res)
            if "headers" in res:
                cleaned_res["headers"] = self.sanitize_headers(res["headers"])
            if "cookies" in res:
                cleaned_res["cookies"] = self.sanitize_cookies_array(res["cookies"])
            if "content" in res:
                cleaned_res["content"] = self.sanitize_response_content(res["content"])

            cleaned_entry = dict(entry)
            cleaned_entry["request"] = cleaned_req
            cleaned_entry["response"] = cleaned_res
            cleaned_entries.append(cleaned_entry)

        cleaned_har = dict(har_data)
        cleaned_har["log"] = dict(log_obj)
        cleaned_har["log"]["entries"] = cleaned_entries
        return cleaned_har

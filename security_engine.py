import os
import re
import json
import secrets
import string
import uuid
from typing import Callable, Dict, List

# 100+ high-confidence patterns, inspired by Kingfisher/TruffleHog/Yelp.
SECRET_PATTERNS = {}
GENERIC_SERVICES = []
FAKE_GENERATORS = {}

_config_path = os.path.join(os.path.dirname(__file__), 'security_config.json')
try:
    with open(_config_path, 'r') as f:
        _config_data = json.load(f)
        SECRET_PATTERNS = _config_data.get('secret_patterns', {})
        GENERIC_SERVICES = _config_data.get('generic_services', [])
        _generators_config = _config_data.get('fake_generators', {})
except Exception as e:
    print(f"Warning: Could not load security_config.json: {e}")
    _generators_config = {}

# Broad fallback rules. Tracked so a tuned rule always wins an overlap against them
# (see sanitize_payload); without this a generic match starting at the field name
# shadows the specific rule that matches the value itself.
GENERIC_RULE_NAMES = {"GENERIC_API_KEY"}

# Generic {SERVICE}_KEY rules, one per configured service name.
for service in GENERIC_SERVICES:
    # {{16,}} must stay escaped: in an f-string a bare {16,} is read as a replacement
    # field and silently emits "(16,)", matching nothing. The key/token/secret/password
    # requirement keeps ordinary names like "azure_account_name = ..." from matching.
    _name = f"{service.upper()}_KEY"
    GENERIC_RULE_NAMES.add(_name)
    SECRET_PATTERNS[_name] = (
        rf"(?i)['\"]?\b{service}[_a-z0-9]*(?:key|token|secret|password|pwd)['\"]?\s*[:=]\s*"
        rf"['\"]?(?P<secret>[a-zA-Z0-9\-_]{{16,}})['\"]?"
    )


# Generators are built from JSON data, never executable strings: config picks a
# type below and passes parameters, it can't introduce new behaviour. This
# process holds every intercepted secret in plaintext, so the config file has to
# stay safe to accept from someone else.

CHARSETS: Dict[str, str] = {
    "alnum": string.ascii_letters + string.digits,
    "alnum_lower": string.ascii_lowercase + string.digits,
    "alnum_upper": string.ascii_uppercase + string.digits,
    "alpha_lower": string.ascii_lowercase,
    "alpha_upper": string.ascii_uppercase,
    "hex": "0123456789abcdef",
    "digits": string.digits,
    "urlsafe": string.ascii_letters + string.digits + "-_",  # what real Google/GCP keys use
}


def _validate_charset(charset: str) -> str:
    if charset not in CHARSETS:
        raise ValueError(f"unknown charset {charset!r}; expected one of {sorted(CHARSETS)}")
    return charset


def _random_string(length: int, charset: str = "alnum") -> str:
    alphabet = CHARSETS[charset]
    return "".join(secrets.choice(alphabet) for _ in range(length))


# Template placeholders: {random:LEN:CHARSET}, {random:LEN}, {uuid}. Rest is literal.
_PLACEHOLDER_RE = re.compile(r"\{(?:random:(\d+)(?::([a-z_]+))?|(uuid))\}")


def _build_prefix_random(spec: dict) -> Callable[[str], str]:
    """Fixed prefix (or one carried over from the real value) plus random filler."""
    prefix = spec.get("prefix", "")
    length = int(spec["length"])
    charset = _validate_charset(spec.get("charset", "alnum"))
    preserve = int(spec.get("preserve_prefix", 0))
    # Guards the carried-over prefix: an unexpected match can't leak its first chars.
    requires = spec.get("preserve_if_contains")

    def generate(real: str) -> str:
        head = prefix
        if preserve and len(real) >= preserve:
            candidate = real[:preserve]
            if requires is None or requires in candidate:
                head = candidate
        return head + _random_string(length, charset)

    return generate


def _build_random(spec: dict) -> Callable[[str], str]:
    length = int(spec["length"])
    charset = _validate_charset(spec.get("charset", "alnum"))
    return lambda real: _random_string(length, charset)


def _build_template(spec: dict) -> Callable[[str], str]:
    """Literal text with {random:...} / {uuid} placeholders filled per call."""
    template = spec["template"]
    for _, charset, _uuid in _PLACEHOLDER_RE.findall(template):
        if charset:
            _validate_charset(charset)

    def fill(match: re.Match) -> str:
        length, charset, is_uuid = match.groups()
        if is_uuid:
            return str(uuid.uuid4())
        return _random_string(int(length), charset or "alnum")

    return lambda real: _PLACEHOLDER_RE.sub(fill, template)


def _build_literal(spec: dict) -> Callable[[str], str]:
    value = spec["value"]
    return lambda real: value


def _build_connection_string(spec: dict) -> Callable[[str], str]:
    """Preserve the real scheme (postgresql, mongodb, ...), fake everything else."""
    user = spec.get("user", "fakeuser")
    password = spec.get("password", "fakepassword")
    host = spec.get("host", "localhost")
    port = spec.get("port", 5432)
    database = spec.get("database", "fakedb")

    def generate(real: str) -> str:
        scheme = real.split("://")[0] if "://" in real else "db"
        return f"{scheme}://{user}:{password}@{host}:{port}/{database}"

    return generate


GENERATOR_BUILDERS: Dict[str, Callable[[dict], Callable[[str], str]]] = {
    "prefix_random": _build_prefix_random,
    "random": _build_random,
    "template": _build_template,
    "literal": _build_literal,
    "connection_string": _build_connection_string,
}


def build_generator(spec: dict) -> Callable[[str], str]:
    if not isinstance(spec, dict):
        raise TypeError(
            f"expected an object describing the generator, got {type(spec).__name__}. "
            "Lambda strings are no longer supported; see the README."
        )
    kind = spec.get("type")
    builder = GENERATOR_BUILDERS.get(kind)
    if builder is None:
        raise ValueError(f"unknown generator type {kind!r}; expected one of {sorted(GENERATOR_BUILDERS)}")
    return builder(spec)


for _rule_name, _spec in _generators_config.items():
    try:
        FAKE_GENERATORS[_rule_name] = build_generator(_spec)
    except (TypeError, ValueError, KeyError) as exc:
        # Fail safe: falls back to Vault._generate_fake, so a broken generator costs
        # realism but never lets the real secret through.
        print(f"Warning: ignoring fake generator for {_rule_name!r}: {exc}")


class Vault:
    def __init__(self):
        # Maps fake secret -> real secret
        self.mapping: Dict[str, str] = {}
        # Maps real secret -> fake secret
        self.reverse_mapping: Dict[str, str] = {}
        
    def store(self, real_secret: str, secret_type: str) -> str:
        if real_secret in self.reverse_mapping:
            return self.reverse_mapping[real_secret]
            
        fake_secret = self._generate_fake(real_secret, secret_type)
        
        while fake_secret in self.mapping:
            fake_secret = self._generate_fake(real_secret, secret_type)
            
        self.mapping[fake_secret] = real_secret
        self.reverse_mapping[real_secret] = fake_secret
        return fake_secret

    def rehydration_pairs(self) -> List[tuple]:
        """(fake, real) substitutions to apply to a response body.

        Includes each pair's JSON-escaped form. A multi-line fake -- a private key
        block -- reaches the client with its newlines written as the two characters
        '\\' + 'n', so searching for the raw fake never matches and the key would
        never be restored. Longest first, so an escaped form is tried before any
        shorter pair that might sit inside it.
        """
        pairs = []
        for fake, real in self.mapping.items():
            pairs.append((fake, real))
            escaped = json.dumps(fake)[1:-1]
            if escaped != fake:
                pairs.append((escaped, json.dumps(real)[1:-1]))
        pairs.sort(key=lambda p: len(p[0]), reverse=True)
        return pairs


    def _generate_fake(self, real_secret: str, secret_type: str) -> str:
        # Longest matching generator name wins, so SLACK_WEBHOOK beats SLACK for
        # SLACK_WEBHOOK_URL no matter how the config is ordered.
        best = max((k for k in FAKE_GENERATORS if k in secret_type), key=len, default=None)
        if best is not None:
            return FAKE_GENERATORS[best](real_secret)


        # Default fallback logic for unknown keys
        if "KEY" in secret_type or "TOKEN" in secret_type:
            length = len(real_secret) if len(real_secret) > 8 else 32
            return _random_string(length)
        return _random_string(32)

    def get_real(self, fake_secret: str) -> str:
        return self.mapping.get(fake_secret, fake_secret)


class SecurityEngine:
    def __init__(self):
        self.vault = Vault()
        # (rule_name, matched_text) for the most recent sanitize_body call
        self.last_hits: List[tuple] = []

    def sanitize_payload(self, text: str) -> str:
        if not text:
            return text
            
        matches = []
        for entity_name, pattern in SECRET_PATTERNS.items():
            for match in re.finditer(pattern, text):
                # A pattern that wraps its value in (?P<secret>...) gets only that
                # group replaced, so `api_key="<fake>"` keeps its surrounding syntax.
                # Patterns without the group replace the whole match, as before.
                group = 'secret' if 'secret' in match.re.groupindex else 0
                if match.start(group) < 0:
                    continue
                matches.append({
                    'start': match.start(group),
                    'end': match.end(group),
                    'entity_type': entity_name,
                    'text': match.group(group)
                })

        # Specific rules claim their span before broad fallbacks, so a tuned rule is
        # never shadowed by a generic one that merely starts earlier. Within a class:
        # earliest first, then longest.
        matches.sort(key=lambda x: (
            x['entity_type'] in GENERIC_RULE_NAMES,
            x['start'],
            -(x['end'] - x['start']),
        ))

        filtered_matches = []
        for m in matches:
            if all(m['end'] <= f['start'] or m['start'] >= f['end'] for f in filtered_matches):
                filtered_matches.append(m)

        # Replace back-to-front so earlier indices stay valid.
        filtered_matches.sort(key=lambda x: x['start'], reverse=True)

        sanitized_text = text
        for m in filtered_matches:
            fake_secret = self.vault.store(m['text'], m['entity_type'])
            # Recorded so a false positive can be traced back to its pattern.
            self.last_hits.append((m['entity_type'], m['text']))
            sanitized_text = sanitized_text[:m['start']] + fake_secret + sanitized_text[m['end']:]

        return sanitized_text

    def sanitize_body(self, body: str) -> str:
        """
        Sanitize a request body, decoding JSON first when possible.

        Scanning the raw wire format misses secrets: inside a JSON string a newline is
        '\\' + 'n', so a secret at the start of a line abuts the letter 'n' and \\b
        never matches. Decoding first lets patterns scan the real text.
        """
        if not body:
            return body

        # Reset so hits describe only this request.
        self.last_hits = []

        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            return self.sanitize_payload(body)  # not JSON, scan raw

        sanitized = self._sanitize_json(payload)
        # Compact separators match what HTTP clients emit, so a secret-free body
        # re-encodes to the exact bytes that came in.
        return json.dumps(sanitized, ensure_ascii=False, separators=(',', ':'))

    def _sanitize_json(self, node):
        """Recursively sanitize every string value in a decoded JSON structure."""
        if isinstance(node, str):
            return self.sanitize_payload(node)
        if isinstance(node, dict):
            # Keys can carry secrets too (e.g. a map keyed by token)
            return {self.sanitize_payload(k) if isinstance(k, str) else k: self._sanitize_json(v)
                    for k, v in node.items()}
        if isinstance(node, list):
            return [self._sanitize_json(item) for item in node]
        return node

"""Lookalike-domain detection: does this hostname imitate a Bangladeshi brand?

Given one hostname (from a TLS certificate, a feed, anywhere), `analyze()`
returns a Finding with a 0-100 risk score and the reasons behind it, or None
when the name does not imitate any watched brand.

What counts as imitation, strongest first:

  homoglyph   an IDN that only spells the brand once Cyrillic/Greek letters
              are read as Latin:              bkаsh.com  (Cyrillic "а")
  typosquat   one edit away from the brand:   bkassh-login.com, nagadd.xyz
  digit swap  digits standing in for letters: bka5h.top, nag4d.app
  subdomain   the brand placed in front of an unrelated domain:
                                              bkash.com.secure-login.top
  exact       the brand inside a new name:    bkash-reward-bd.top

Supporting signals then raise the score: phishing words (login, verify,
bonus...), cheap TLDs favoured by phishers, free hosting, long hyphenated
names. The genuine domains (bkash.com, nagad.com.bd, ...) are never flagged.

Everything here is pure computation on the name - no network - so it runs
on the live certificate stream as well as in tests.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache

import tldextract

from sentinel.allowlist import SHARED_PLATFORMS, USER_PLATFORMS, is_allowlisted_domain, is_official_bd_domain
from sentinel.indicators import normalize_domain

# token -> brand. Tokens are matched against the name with separators removed.
BRANDS: dict[str, str] = {
    "bkash": "bKash",
    "nagad": "Nagad",
    "dutchbangla": "Dutch-Bangla Bank",
    "dbbl": "Dutch-Bangla Bank",
    "sonalibank": "Sonali Bank",
    "janatabank": "Janata Bank",
    "agranibank": "Agrani Bank",
    "rupalibank": "Rupali Bank",
    "bracbank": "BRAC Bank",
    "islamibank": "Islami Bank",
    "ibbl": "Islami Bank",
    "pubalibank": "Pubali Bank",
    "primebank": "Prime Bank",
    "citybankbd": "City Bank",
    "grameenphone": "Grameenphone",
    "banglalink": "Banglalink",
    "teletalk": "Teletalk",
}

# Tokens searched in certificate logs (crt.sh). Short or generic ones would
# return too much; they are still matched by analyze() on the live stream.
SEARCH_TOKENS: tuple[str, ...] = (
    "bkash", "nagad", "dutchbangla", "dbbl", "sonalibank", "janatabank",
    "agranibank", "rupalibank", "bracbank", "islamibank", "pubalibank",
    "primebank", "grameenphone", "banglalink", "teletalk",
)

# Typos are only looked for on tokens this long; shorter ones collide with
# ordinary words far too often.
FUZZY_MIN_LEN = 5

# Real words and names one edit away from a brand. "Bikash" and "Akash" are
# common Bangladeshi names; "nagar" means town and is in countless place names.
FALSE_FRIENDS: frozenset[str] = frozenset(
    {"bikash", "akash", "bkash", "nagar", "nagor", "nagas", "nagao", "magad", "nogad",
     "telltalk", "primebanks"}
)

PHISHING_WORDS: tuple[str, ...] = (
    "login", "signin", "verify", "verification", "secure", "security", "update",
    "account", "bonus", "reward", "offer", "gift", "prize", "cashback", "otp",
    "pin", "kyc", "wallet", "support", "helpline", "customer", "care", "refund",
    "claim", "free", "lottery", "app", "apk", "download", "payment", "pay",
)

RISKY_TLDS: frozenset[str] = frozenset(
    {"top", "xyz", "shop", "online", "site", "click", "info", "icu", "cfd", "sbs",
     "cyou", "buzz", "live", "store", "fun", "monster", "rest", "lol", "vip",
     "work", "support", "help", "cc", "ru", "tk", "ml", "ga", "cf", "gq"}
)

# Cyrillic and Greek letters that render like Latin ones.
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "к": "k",
    "м": "m", "т": "t", "н": "h", "в": "b", "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d",
    "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ս": "u",
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "κ": "k", "ν": "v", "τ": "t", "ι": "i",
    "ı": "i", "ł": "l", "ß": "b",
})
DIGIT_SWAPS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})

THRESHOLD = 55

_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


@dataclass
class Finding:
    domain: str            # the hostname that was analysed (normalised)
    indicator: str         # what to block: the attacker's registrable domain
    brand: str
    technique: str         # exact | typosquat | digit-swap | homoglyph | subdomain
    score: int
    reasons: list[str] = field(default_factory=list)

    @property
    def reportable(self) -> bool:
        return self.score >= THRESHOLD


def _deletions(word: str) -> set[str]:
    return {word[:i] + word[i + 1:] for i in range(len(word))}


@lru_cache
def _fuzzy_index() -> dict[str, set[str]]:
    """Deletion neighbourhood of every long token: variant -> tokens."""
    index: dict[str, set[str]] = {}
    for token in BRANDS:
        if len(token) >= FUZZY_MIN_LEN:
            for variant in _deletions(token) | {token}:
                index.setdefault(variant, set()).add(token)
    return index


def _edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment) distance."""
    rows = [list(range(len(b) + 1))] + [[i] + [0] * len(b) for i in range(1, len(a) + 1)]
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[-1][-1]


def _flat(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text)


def _exact(text: str) -> str | None:
    for token in sorted(BRANDS, key=len, reverse=True):
        if token in text:
            return token
    return None


def _typo(name: str) -> tuple[str, str] | None:
    """(token, the misspelling) when a whole word of the name is one edit
    from a brand.

    Typosquats change the brand itself and keep it a word of its own:
    bkassh-login, gramenphone-offer, bksh24. Searching inside longer words
    instead finds coincidences: "tkash" in hojatkashfi, "primebask" in
    primebaskets. So the candidates are each word, each pair of adjacent
    words joined (prime-bnak), and each of those without trailing digits.
    """
    index = _fuzzy_index()
    words = [w for w in re.split(r"[^a-z0-9]+", name) if w]
    candidates: list[str] = []
    for i, word in enumerate(words):
        candidates.append(word)
        if i + 1 < len(words):
            candidates.append(word + words[i + 1])
    candidates += [c.rstrip("0123456789") for c in candidates]

    for candidate in dict.fromkeys(c for c in candidates if len(c) >= FUZZY_MIN_LEN - 1):
        if candidate in FALSE_FRIENDS:
            continue
        for variant in _deletions(candidate) | {candidate}:
            for token in index.get(variant, ()):
                if candidate != token and _edit_distance(candidate, token) == 1:
                    return token, candidate
    return None


def _skeletons(label: str) -> tuple[str, bool]:
    """ASCII reading of a (possibly punycode) label, and whether it was an IDN."""
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna").translate(CONFUSABLES), True
        except UnicodeError:
            return label, True
    return label, False


def analyze(hostname: str) -> Finding | None:
    domain = normalize_domain(hostname)
    if domain is None or is_official_bd_domain(domain) or domain in SHARED_PLATFORMS | USER_PLATFORMS:
        return None

    parts = _extract(domain)
    registrable = parts.registered_domain or domain
    # On shared infrastructure (amazonaws.com, sharepoint.com...) the
    # registrable domain belongs to the provider, not the attacker: report
    # the exact hostname instead, never the platform.
    if is_allowlisted_domain(registrable):
        registrable = domain
    name = parts.domain           # e.g. "bkash-verify" in bkash-verify.com
    sub = parts.subdomain         # e.g. "bkash.com" in bkash.com.secure-login.top

    decoded, is_idn = zip(*(_skeletons(label) for label in name.split("."))) if name else ((), (False,))
    name_ascii = ".".join(decoded)
    flat_name = _flat(name_ascii)
    flat_sub = _flat(sub)

    technique = token = None
    misspelling = None
    token = _exact(flat_name)
    if token:
        technique = "homoglyph" if any(is_idn) and _exact(_flat(name)) is None else "exact"
    elif token := _exact(_flat(name_ascii.translate(DIGIT_SWAPS))):
        technique = "digit-swap"
    elif found := _typo(name_ascii):
        technique, (token, misspelling) = "typosquat", found
    elif token := _exact(flat_sub):
        technique = "subdomain"
    if not token:
        return None

    brand = BRANDS[token]
    base = {"homoglyph": 75, "digit-swap": 60, "typosquat": 55, "subdomain": 50, "exact": 40}[technique]
    # Short tokens are more often coincidence ("dbbl" inside an unrelated word).
    if technique == "exact" and len(token) <= 4:
        base -= 10
    reasons = [
        {
            "exact": f"Contains the brand name '{token}'",
            "homoglyph": f"Spells '{token}' with look-alike foreign letters",
            "typosquat": f"'{misspelling}' is one letter away from '{token}'",
            "digit-swap": f"Spells '{token}' with digits in place of letters",
            "subdomain": f"Puts '{token}' in front of an unrelated domain",
        }[technique]
    ]
    score = base

    # Phishing words only count inside the lookalike name itself. In
    # login.primebank.com the "login" belongs to whoever owns primebank.com;
    # in bkash.com.secure-login.top it belongs to the attacker.
    word_zone = _flat(name_ascii) if technique != "subdomain" else _flat(domain)
    words = sorted({w for w in PHISHING_WORDS if w in word_zone and w not in token})
    if words:
        score += 15
        reasons.append("Phishing words: " + ", ".join(words[:4]))
    tld = parts.suffix.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        score += 15
        reasons.append(f"Cheap TLD favoured by phishers: .{tld}")
    platform = next((p for p in USER_PLATFORMS if registrable.endswith("." + p)), None)
    if platform:
        score += 10
        reasons.append(f"Free hosting: {platform}")
    if domain.count("-") >= 2 or len(domain) > 30:
        score += 10
        reasons.append("Long or heavily hyphenated name")
    if parts.suffix.endswith("bd") and technique == "exact" and not words:
        score -= 10  # a .bd name containing a brand is often a partner or agent

    return Finding(
        domain=domain,
        indicator=registrable,
        brand=brand,
        technique=technique,
        score=max(0, min(100, score)),
        reasons=reasons,
    )

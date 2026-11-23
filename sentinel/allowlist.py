"""Domains and IPs that must never appear in a domain or IP blocklist.

Attackers routinely host malware on GitHub, Google Drive or Dropbox, and
phishing pages on compromised government sites. The specific URL is a
valid indicator; the whole domain is not - blocking github.com or gov.bd
across a network would cause an outage. So these entries are excluded
from the domain and IP feeds, while the URL feed (which blocks only the
exact URL) still includes them.

Two kinds of platform are treated differently:

  SHARED_PLATFORMS   every subdomain is shared or belongs to the provider
                     (raw.githubusercontent.com, foo.sharepoint.com): never
                     block any of them.
  USER_PLATFORMS     each subdomain belongs to one customer
                     (bkash-login.pages.dev): the platform itself is safe,
                     but a customer's subdomain can be blocked precisely.
"""

from __future__ import annotations

SHARED_PLATFORMS: frozenset[str] = frozenset(
    {
        "google.com", "googleapis.com", "googleusercontent.com", "gstatic.com",
        "github.com", "githubusercontent.com", "gitlab.com",
        "microsoft.com", "live.com", "office.com", "office365.com", "outlook.com",
        "sharepoint.com", "onedrive.com", "1drv.ms", "windows.net", "azureedge.net",
        "amazonaws.com", "amazon.com", "cloudfront.net", "cloudflare.com",
        "dropbox.com", "dropboxusercontent.com", "mediafire.com", "mega.nz",
        "facebook.com", "fb.com", "fbcdn.net", "instagram.com", "whatsapp.com",
        "telegram.org", "t.me", "discord.com", "discordapp.com", "discordapp.net",
        "youtube.com", "apple.com", "icloud.com", "yahoo.com",
        "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    }
)

USER_PLATFORMS: frozenset[str] = frozenset(
    {
        "github.io", "workers.dev", "pages.dev", "r2.dev",
        "wordpress.com", "blogspot.com", "weebly.com", "wixsite.com",
        "000webhostapp.com", "firebaseapp.com", "web.app", "vercel.app",
        "netlify.app", "herokuapp.com", "onrender.com", "ngrok.io", "ngrok-free.app",
        "duckdns.org", "glitch.me", "replit.app", "repl.co",
    }
)

# Bangladesh: government, education, and the genuine services attackers imitate.
BD_OFFICIAL: frozenset[str] = frozenset(
    {
        "gov.bd", "edu.bd", "ac.bd",
        "bkash.com", "nagad.com.bd", "dutchbanglabank.com", "sonalibank.com.bd",
        "janatabank-bd.com", "agranibank.org", "rupalibank.com.bd",
        "bracbank.com", "islamibankbd.com", "ebl.com.bd", "citybankplc.com",
        "primebank.com.bd", "pubalibangla.com", "jb.com.bd", "bb.org.bd", "bkashcdn.com",
        "grameenphone.com", "robi.com.bd", "banglalink.net", "teletalk.com.bd",
        "prothomalo.com", "bdnews24.com", "thedailystar.net",
    }
)

ALLOWED_DOMAINS: frozenset[str] = SHARED_PLATFORMS | USER_PLATFORMS | BD_OFFICIAL

# Public resolvers: blocking them breaks DNS for the whole network.
ALLOWED_IPS: frozenset[str] = frozenset(
    {
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220",
    }
)


def _under(domain: str, parent: str) -> bool:
    return domain == parent or domain.endswith("." + parent)


def is_official_bd_domain(domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    return any(_under(domain, entry) for entry in BD_OFFICIAL)


def is_allowlisted_domain(domain: str) -> bool:
    """True when blocking this domain would hit more than one bad actor."""
    domain = domain.lower().rstrip(".")
    if any(_under(domain, entry) for entry in SHARED_PLATFORMS | BD_OFFICIAL):
        return True
    # The platform itself (and its www) is safe; a customer subdomain is not.
    return any(domain in (entry, "www." + entry) for entry in USER_PLATFORMS)


def is_allowlisted_ip(ip: str) -> bool:
    return ip in ALLOWED_IPS

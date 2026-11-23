"""Domains and IPs that must never appear in a domain or IP blocklist.

Attackers routinely host malware on GitHub, Google Drive or Dropbox, and
phishing pages on compromised government sites. The specific URL is a
valid indicator; the whole domain is not - blocking github.com or gov.bd
across a network would cause an outage. So these entries are excluded
from the domain and IP feeds, while the URL feed (which blocks only the
exact URL) still includes them.
"""

from __future__ import annotations

ALLOWED_DOMAINS: frozenset[str] = frozenset(
    {
        # Global platforms commonly abused for hosting
        "google.com", "googleapis.com", "googleusercontent.com", "gstatic.com",
        "github.com", "githubusercontent.com", "github.io", "gitlab.com",
        "microsoft.com", "live.com", "office.com", "office365.com", "outlook.com",
        "sharepoint.com", "onedrive.com", "1drv.ms", "windows.net", "azureedge.net",
        "amazonaws.com", "amazon.com", "cloudfront.net",
        "cloudflare.com", "workers.dev", "pages.dev", "r2.dev",
        "dropbox.com", "dropboxusercontent.com", "mediafire.com", "mega.nz",
        "facebook.com", "fb.com", "fbcdn.net", "instagram.com", "whatsapp.com",
        "telegram.org", "t.me", "discord.com", "discordapp.com", "discordapp.net",
        "youtube.com", "apple.com", "icloud.com", "yahoo.com",
        "bit.ly", "tinyurl.com", "t.co", "goo.gl",
        "wordpress.com", "blogspot.com", "weebly.com", "wixsite.com",
        "000webhostapp.com", "firebaseapp.com", "web.app", "vercel.app",
        "netlify.app", "herokuapp.com", "onrender.com", "ngrok.io", "ngrok-free.app",
        # Bangladesh: government and the genuine services attackers imitate
        "gov.bd", "edu.bd", "ac.bd",
        "bkash.com", "nagad.com.bd", "dutchbanglabank.com", "sonalibank.com.bd",
        "janatabank-bd.com", "agranibank.org", "rupalibank.com.bd",
        "bracbank.com", "islamibankbd.com", "ebl.com.bd", "citybankplc.com",
        "grameenphone.com", "robi.com.bd", "banglalink.net", "teletalk.com.bd",
        "prothomalo.com", "bdnews24.com", "thedailystar.net",
    }
)

# Public resolvers: blocking them breaks DNS for the whole network.
ALLOWED_IPS: frozenset[str] = frozenset(
    {
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220",
    }
)


def is_allowlisted_domain(domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    return any(domain == entry or domain.endswith("." + entry) for entry in ALLOWED_DOMAINS)


def is_allowlisted_ip(ip: str) -> bool:
    return ip in ALLOWED_IPS

import re

def classify_indicator(indicator: str) -> str:
    """
    Returns one of: ip, domain, url, file, unknown
    """
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", indicator):
        return "ip"
    elif re.match(r"^[a-fA-F0-9]{32}$", indicator):
        return "file"   # MD5
    elif re.match(r"^[a-fA-F0-9]{40}$", indicator):
        return "file"   # SHA1
    elif re.match(r"^[a-fA-F0-9]{64}$", indicator):
        return "file"   # SHA256
    elif re.match(r"^https?://", indicator):
        return "url"
    elif re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", indicator):
        return "domain"
    else:
        return "unknown"

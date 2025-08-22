import os
import httpx
from dotenv import load_dotenv

# Load .env early
load_dotenv()

OTX_KEY = os.getenv("OTX_API_KEY", "")
BASE = "https://otx.alienvault.com/api/v1/indicators"

# Correct OTX type mapping
MAP = {
    "ip": "IPv4",
    "domain": "domain",
    "url": "url",         # still works, OTX accepts /url/<value>/general
    "file": "file_hash"   # correct name for hashes
}

async def check_otx(indicator: str, ioc_type: str) -> dict:
    """
    Returns: {"source":"OTX","verdict":<str>,"details":<str>}
    Always returns a row so it shows on the dashboard.
    """
    def row(verdict: str, details: str) -> dict:
        return {"source": "OTX", "verdict": verdict, "details": details}

    if ioc_type not in MAP:
        return row("N/A", f"Unsupported IOC type: {ioc_type}")

    if not OTX_KEY:
        return row("Error", "Missing OTX_API_KEY")

    headers = {"X-OTX-API-KEY": OTX_KEY}
    url = f"{BASE}/{MAP[ioc_type]}/{indicator}/general"

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(url, headers=headers)

            if r.status_code == 429:
                return row("Rate-Limited", "OTX API limit hit")
            if r.status_code == 403:
                return row("Error", "Invalid or missing OTX_API_KEY")
            if r.status_code == 400:
                return row("Error", f"Bad request (check IOC type: {ioc_type})")
            if not r.is_success:
                return row("Error", f"HTTP {r.status_code}")

            data = r.json()
            pulse_info = data.get("pulse_info") or {}
            count = pulse_info.get("count", 0)
            # Show up to 2 pulse names for quick context
            pulses = pulse_info.get("pulses") or []
            names = [p.get("name") for p in pulses[:2] if isinstance(p, dict)]
            extra = f" | Top: {', '.join(names)}" if names else ""
            return row("Checked", f"Pulses={count}{extra}")

    except Exception as e:
        return row("Error", str(e))

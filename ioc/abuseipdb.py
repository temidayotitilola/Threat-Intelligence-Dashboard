import os
import httpx

ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
BASE = "https://api.abuseipdb.com/api/v2/check"

async def check_abuseipdb(indicator: str, ioc_type: str) -> dict:
    """
    Returns: {"source":"AbuseIPDB","verdict":<str>,"details":<str>}
    """
    def row(verdict: str, details: str) -> dict:
        return {"source": "AbuseIPDB", "verdict": verdict, "details": details}

    if ioc_type != "ip":
        return row("N/A", "Only supports IP addresses")

    if not ABUSE_KEY:
        return row("Error", "Missing ABUSEIPDB_API_KEY")

    headers = {"Key": ABUSE_KEY, "Accept": "application/json"}
    params = {"ipAddress": indicator, "maxAgeInDays": 90}

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(BASE, headers=headers, params=params)
            if r.status_code == 429:
                return row("Rate-Limited", "AbuseIPDB API limit hit")
            if not r.is_success:
                return row("Error", f"HTTP {r.status_code}")
            data = r.json().get("data") or {}
            score = data.get("abuseConfidenceScore", 0)
            reports = data.get("totalReports", 0)
            return row("Checked", f"Score={score} Reports={reports}")
    except Exception as e:
        return row("Error", str(e))

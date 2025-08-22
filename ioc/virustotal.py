import os
import httpx

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
BASE = "https://www.virustotal.com/api/v3"

async def check_virustotal(indicator: str, ioc_type: str) -> dict:
    """
    Returns: {"source":"VirusTotal","verdict":<str>,"details":<str>}
    Always returns a row (no exceptions leak to the route).
    """
    headers = {"x-apikey": VT_KEY} if VT_KEY else {}

    def row(verdict: str, details: str) -> dict:
        return {"source": "VirusTotal", "verdict": verdict, "details": details}

    if not VT_KEY:
        return row("Error", "Missing VIRUSTOTAL_API_KEY")

    # Resolve endpoint
    if ioc_type == "ip":
        url = f"{BASE}/ip_addresses/{indicator}"
        mode = "get"
    elif ioc_type == "domain":
        url = f"{BASE}/domains/{indicator}"
        mode = "get"
    elif ioc_type == "file":
        url = f"{BASE}/files/{indicator}"
        mode = "get"
    elif ioc_type == "url":
        # For URLs, VT requires submission then reading the analysis
        url = f"{BASE}/urls"
        mode = "post"
    else:
        return row("N/A", "Unsupported IOC type")

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            if mode == "get":
                r = await client.get(url, headers=headers)
                if r.status_code == 429:
                    return row("Rate-Limited", "VirusTotal API limit hit")
                if not r.is_success:
                    return row("Error", f"HTTP {r.status_code}")
                data = r.json().get("data", {})
                stats = (data.get("attributes") or {}).get("last_analysis_stats", {})
                total = sum(stats.values()) if stats else 0
                return row(
                    "Checked",
                    f"Malicious={stats.get('malicious',0)} Suspicious={stats.get('suspicious',0)} Total={total}"
                )

            # mode == "post" (URL)
            r = await client.post(url, headers=headers, data={"url": indicator})
            if r.status_code == 429:
                return row("Rate-Limited", "VirusTotal API limit hit")
            if not r.is_success:
                return row("Error", f"HTTP {r.status_code} on submit")
            analysis_id = (r.json().get("data") or {}).get("id")
            if not analysis_id:
                return row("Queued", "URL submitted; analysis id missing")

            # Try to pull quick analysis snapshot
            ra = await client.get(f"{BASE}/analyses/{analysis_id}", headers=headers)
            if not ra.is_success:
                return row("Queued", f"Analysis queued (HTTP {ra.status_code})")
            attrs = (ra.json().get("data") or {}).get("attributes") or {}
            stats = attrs.get("stats") or {}
            total = sum(stats.values()) if stats else 0
            return row(
                "Checked",
                f"Malicious={stats.get('malicious',0)} Suspicious={stats.get('suspicious',0)} Total={total}"
            )
    except Exception as e:
        return row("Error", str(e))

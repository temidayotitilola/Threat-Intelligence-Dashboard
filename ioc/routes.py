from flask import render_template, request
from . import ioc_bp
from .helpers import classify_indicator
from .virustotal import check_virustotal
from .abuseipdb import check_abuseipdb
from .otx import check_otx
import asyncio

@ioc_bp.route("/", methods=["GET", "POST"])
async def index():
    results = []
    query = ""

    if request.method == "POST":
        query = (request.form.get("indicator") or "").strip()
        if query:
            ioc_type = classify_indicator(query)

            # Run all three providers concurrently
            vt_task = check_virustotal(query, ioc_type)
            ab_task = check_abuseipdb(query, ioc_type)
            otx_task = check_otx(query, ioc_type)

            provider_results = await asyncio.gather(vt_task, ab_task, otx_task, return_exceptions=True)

            # Always produce 3 rows (one per provider)
            # If any task raised, show an Error row for that provider.
            names = ["VirusTotal", "AbuseIPDB", "OTX"]
            for name, res in zip(names, provider_results):
                if isinstance(res, Exception):
                    results.append({"source": name, "verdict": "Error", "details": str(res)})
                else:
                    # res is already a dict with source/verdict/details
                    results.append(res)

    return render_template("index.html", results=results, query=query)

"""
vt_checker.py
-------------
Optional integration with the VirusTotal public API (v3).

Instead of relying only on our own small local signature database, this
lets us ask VirusTotal "has anyone, anywhere, already flagged a file
with this hash as malicious?" VirusTotal aggregates results from 70+
antivirus engines, so this gives real threat-intelligence context.

Getting an API key (free):
1. Create a free account at https://www.virustotal.com/gui/join-us
2. Go to your profile -> API Key
3. Copy the key into config.json (see config.json.example) or pass it
   with --api-key on the command line.

Note: the free/public API has a rate limit (around 4 requests/minute).
This module is written to fail gracefully if the key is missing,
invalid, or the rate limit is hit -- it should never crash the scan.
"""

import requests

VT_API_URL = "https://www.virustotal.com/api/v3/files/{}"


def check_hash_virustotal(file_hash, api_key, timeout=15):
    """
    Query VirusTotal for a given SHA-256 hash.

    Returns a dict:
        {
            "checked": True/False,   # whether the API call succeeded
            "found": True/False,     # whether VT has seen this hash before
            "malicious_count": int,  # how many AV engines flagged it
            "total_engines": int,    # how many engines gave a verdict
            "message": str           # human-readable summary / error
        }
    """
    result = {
        "checked": False,
        "found": False,
        "malicious_count": 0,
        "total_engines": 0,
        "message": "",
    }

    if not api_key:
        result["message"] = "No VirusTotal API key configured -- skipped."
        return result

    headers = {"x-apikey": api_key}

    try:
        response = requests.get(
            VT_API_URL.format(file_hash), headers=headers, timeout=timeout
        )
    except requests.exceptions.RequestException as e:
        result["message"] = f"VirusTotal request failed: {e}"
        return result

    if response.status_code == 200:
        result["checked"] = True
        result["found"] = True
        data = response.json()
        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        result["malicious_count"] = malicious + suspicious
        result["total_engines"] = total
        result["message"] = (
            f"{malicious + suspicious}/{total} AV engines flagged this hash"
        )

    elif response.status_code == 404:
        result["checked"] = True
        result["found"] = False
        result["message"] = "Hash not found in VirusTotal database."

    elif response.status_code == 401:
        result["message"] = "Invalid VirusTotal API key."

    elif response.status_code == 429:
        result["message"] = "VirusTotal rate limit hit -- try again shortly."

    else:
        result["message"] = f"VirusTotal returned unexpected status {response.status_code}."

    return result

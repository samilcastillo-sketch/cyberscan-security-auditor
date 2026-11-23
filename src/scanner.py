"""
CyberScan Security Headers & Web Posture Audit Engine
"""
from typing import Dict, Any

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "weight": 25,
        "description": "Enforces secure HTTPS connections and prevents SSL-stripping MITM attacks.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
    },
    "Content-Security-Policy": {
        "weight": 25,
        "description": "Restricts resources (scripts, images) executable by browser to prevent XSS attacks.",
        "remediation": "Configure a strict 'Content-Security-Policy' header defining trusted script sources."
    },
    "X-Frame-Options": {
        "weight": 15,
        "description": "Prevents Clickjacking attacks by restricting iframe embedding.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'."
    },
    "X-Content-Type-Options": {
        "weight": 15,
        "description": "Prevents MIME-sniffing vulnerabilities.",
        "remediation": "Add 'X-Content-Type-Options: nosniff'."
    },
    "Referrer-Policy": {
        "weight": 10,
        "description": "Controls privacy of the Referer header sent to external origins.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'."
    },
    "Permissions-Policy": {
        "weight": 10,
        "description": "Restricts browser feature access like camera, microphone, and geolocation.",
        "remediation": "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()'."
    }
}

def evaluate_headers(response_headers: Dict[str, str]) -> Dict[str, Any]:
    # Normalize header keys to lowercase
    normalized = {k.lower(): v for k, v in response_headers.items()}
    score = 0
    results = []

    for header_name, meta in SECURITY_HEADERS.items():
        val = normalized.get(header_name.lower())
        present = val is not None
        if present:
            score += meta["weight"]

        results.append({
            "header": header_name,
            "present": present,
            "value": val or "Missing",
            "weight": meta["weight"],
            "description": meta["description"],
            "remediation": meta["remediation"]
        })

    # Determine letter grade
    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 65:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": score,
        "grade": grade,
        "headers_evaluated": len(SECURITY_HEADERS),
        "headers_passed": sum(1 for r in results if r["present"]),
        "results": results
    }

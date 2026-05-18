def score_from_risk_counts(high, medium, low):
    score = 100
    score -= high * 18
    score -= medium * 9
    score -= low * 3
    return max(0, min(100, score))


def rating_from_score(score):
    if score >= 85:
        return "strong"
    if score >= 70:
        return "moderate"
    if score >= 50:
        return "watch"
    return "critical"


def collect_latest_findings(latest):
    if not latest:
        return {
            "high": 0,
            "medium": 0,
            "low": 0,
            "open_services": 0,
            "missing_headers": 0,
            "devices": 0,
        }

    result = latest.get("result", latest)

    high = medium = low = 0
    open_services = 0
    missing_headers = 0
    devices = 0

    if result.get("scan_type") == "port_scan":
        open_ports = result.get("open_ports", [])
        open_services = len(open_ports)
        for item in open_ports:
            if item.get("risk") == "high":
                high += 1
            elif item.get("risk") == "medium":
                medium += 1
            elif item.get("risk") == "low":
                low += 1

    if result.get("scan_type") == "web_security_header_scan":
        missing = result.get("missing_headers", [])
        missing_headers = len(missing)
        for item in missing:
            if item.get("risk") == "high":
                high += 1
            elif item.get("risk") == "medium":
                medium += 1
            else:
                low += 1

    if result.get("scan_type") in {"private_subnet_device_discovery", "current_wifi_lan_discovery"}:
        device_list = result.get("devices", [])
        devices = len(device_list)
        for device in device_list:
            for item in device.get("open_ports", []):
                open_services += 1
                if item.get("risk") == "high":
                    high += 1
                elif item.get("risk") == "medium":
                    medium += 1
                elif item.get("risk") == "low":
                    low += 1

    return {
        "high": high,
        "medium": medium,
        "low": low,
        "open_services": open_services,
        "missing_headers": missing_headers,
        "devices": devices,
    }


def build_assessment_summary(history, latest):
    findings = collect_latest_findings(latest)
    score = score_from_risk_counts(findings["high"], findings["medium"], findings["low"])

    return {
        "exposure_score": score,
        "rating": rating_from_score(score),
        "total_scans": len(history or []),
        "latest_findings": findings,
        "executive_takeaway": build_takeaway(score, findings),
    }


def build_takeaway(score, findings):
    if findings["high"] > 0:
        return "High-priority exposure was detected. Review ownership, access controls, and remediation steps before treating this environment as ready."
    if findings["medium"] > 0:
        return "Moderate exposure was detected. The environment needs validation, access review, and monitoring before production-style readiness."
    if score >= 85:
        return "The latest review looks controlled for the selected checks. Continue monitoring after changes."
    return "The latest review needs follow-up before it should be considered operationally mature."

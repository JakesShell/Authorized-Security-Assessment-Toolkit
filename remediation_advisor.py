def print_remediation_guidance(findings=None):
    print("\nRemediation Guidance")
    print("--------------------")

    if not findings:
        print("- Enforce HTTPS wherever possible.")
        print("- Add important security headers such as CSP, HSTS, and X-Frame-Options.")
        print("- Reduce unnecessary open ports and exposed services.")
        print("- Patch server software and libraries regularly.")
        print("- Limit public exposure of administrative interfaces.")
        print("- Document findings and assign ownership for remediation.")
        return

    if not findings.get("https_enabled", False):
        print("- Enable HTTPS and redirect HTTP traffic to secure endpoints.")

    missing_headers = findings.get("missing_headers", [])
    if missing_headers:
        print("- Add the following missing security headers:")
        for header in missing_headers:
            print(f"  * {header}")
    else:
        print("- Core reviewed security headers were present.")

    if findings.get("status_code", 0) >= 400:
        print("- Investigate unexpected HTTP error responses during assessment.")

    print("- Review exposed services and remove anything unnecessary.")
    print("- Track findings in an internal remediation plan.")

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse
import ipaddress
import socket
import requests


SAFE_MAX_PORTS = 64
SAFE_MAX_HOSTS = 128
SOCKET_TIMEOUT = 0.45

PORT_PRESETS = {
    "common": [20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017],
    "web": [80, 443, 8000, 8080, 8443, 3000, 4200, 5000, 5050, 5173, 9000],
    "admin": [22, 23, 3389, 5900, 5985, 5986, 8080, 8443],
    "database": [1433, 1521, 3306, 5432, 6379, 9200, 27017],
    "device": [22, 80, 443, 445, 3389, 5900, 8080],
}


SECURITY_HEADERS = {
    "Strict-Transport-Security": "Forces secure HTTPS communication and reduces downgrade risk.",
    "Content-Security-Policy": "Limits where scripts, frames, images, and other resources can load from.",
    "X-Frame-Options": "Helps prevent clickjacking by controlling whether the site can be framed.",
    "X-Content-Type-Options": "Helps prevent MIME-sniffing attacks.",
    "Referrer-Policy": "Controls how much referrer information is shared with other sites.",
    "Permissions-Policy": "Limits browser features such as camera, microphone, and geolocation.",
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def get_default_port_set(preset):
    ports = PORT_PRESETS.get(preset, PORT_PRESETS["common"])
    return ports[:SAFE_MAX_PORTS]


def is_safe_private_ip(ip_text):
    ip = ipaddress.ip_address(ip_text)
    return ip.is_private or ip.is_loopback or ip.is_link_local


def resolve_target(target):
    if not target:
        raise ValueError("Target is required.")

    clean_target = target.strip().replace("http://", "").replace("https://", "").split("/")[0]
    clean_target = clean_target.split(":")[0]

    try:
        resolved_ip = socket.gethostbyname(clean_target)
    except socket.gaierror:
        raise ValueError("Could not resolve target.")

    return clean_target, resolved_ip


def validate_private_target(target):
    clean_target, resolved_ip = resolve_target(target)

    if not is_safe_private_ip(resolved_ip):
        raise ValueError("Safe mode only allows localhost, private IP ranges, or private hostnames you are authorized to assess.")

    return {
        "target": clean_target,
        "resolved_ip": resolved_ip,
    }


def validate_private_subnet(cidr):
    if not cidr:
        raise ValueError("CIDR range is required. Example: 192.168.1.0/24")

    network = ipaddress.ip_network(cidr, strict=False)

    if not network.is_private and not network.is_loopback and not network.is_link_local:
        raise ValueError("Safe mode only allows private subnet discovery.")

    host_count = sum(1 for _ in network.hosts())
    if host_count > SAFE_MAX_HOSTS:
        raise ValueError(f"Subnet too large for safe demo mode. Use a range with {SAFE_MAX_HOSTS} hosts or fewer.")

    return network


def describe_port(port):
    descriptions = {
        20: "FTP data transfer",
        21: "FTP control service",
        22: "SSH remote administration",
        23: "Telnet remote administration",
        25: "SMTP mail service",
        53: "DNS service",
        80: "HTTP web service",
        110: "POP3 mail retrieval",
        139: "NetBIOS session service",
        143: "IMAP mail retrieval",
        443: "HTTPS web service",
        445: "SMB file sharing",
        587: "SMTP submission",
        993: "Secure IMAP",
        995: "Secure POP3",
        1433: "Microsoft SQL Server",
        1521: "Oracle database",
        3306: "MySQL database",
        3389: "Remote Desktop Protocol",
        5432: "PostgreSQL database",
        5900: "VNC remote access",
        5985: "Windows Remote Management HTTP",
        5986: "Windows Remote Management HTTPS",
        6379: "Redis database/cache",
        8080: "Alternate HTTP/admin web service",
        8443: "Alternate HTTPS/admin web service",
        9200: "Elasticsearch API",
        27017: "MongoDB database",
    }
    return descriptions.get(port, "Unknown or custom service")


def classify_port_risk(port):
    high = {21, 23, 445, 3389, 5900, 6379, 9200, 27017}
    medium = {20, 22, 25, 53, 110, 139, 143, 1433, 1521, 3306, 5432, 5985, 5986, 8080, 8443}
    if port in high:
        return "high"
    if port in medium:
        return "medium"
    return "low"


def check_single_port(target, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(SOCKET_TIMEOUT)
        result = sock.connect_ex((target, port))
        is_open = result == 0

    return {
        "port": port,
        "state": "open" if is_open else "closed",
        "service": describe_port(port),
        "risk": classify_port_risk(port) if is_open else "none",
    }


def scan_ports(target, ports, resolved_ip=None):
    safe = validate_private_target(target)
    scan_target = safe["target"]
    resolved_ip = resolved_ip or safe["resolved_ip"]

    ports = list(dict.fromkeys([int(port) for port in ports]))[:SAFE_MAX_PORTS]

    results = []
    with ThreadPoolExecutor(max_workers=24) as pool:
        future_map = {pool.submit(check_single_port, resolved_ip, port): port for port in ports}
        for future in as_completed(future_map):
            results.append(future.result())

    results.sort(key=lambda item: item["port"])
    open_ports = [item for item in results if item["state"] == "open"]

    return {
        "scan_type": "port_scan",
        "target": scan_target,
        "resolved_ip": resolved_ip,
        "timestamp": utc_now(),
        "ports_scanned": len(results),
        "open_port_count": len(open_ports),
        "open_ports": open_ports,
        "all_ports": results,
        "recommendations": build_port_recommendations(open_ports),
    }


def build_port_recommendations(open_ports):
    if not open_ports:
        return [
            {
                "priority": "low",
                "title": "No exposed services found in this review set",
                "guidance": "Continue monitoring and validate firewall rules after major changes.",
            }
        ]

    recommendations = []
    for item in open_ports:
        risk = item["risk"]
        port = item["port"]
        service = item["service"]

        if risk == "high":
            guidance = "Restrict exposure, require VPN or private access, validate authentication, and review whether the service must be reachable."
        elif risk == "medium":
            guidance = "Confirm business need, restrict source ranges, enable logging, and verify patch status."
        else:
            guidance = "Confirm the service is expected and covered by monitoring."

        recommendations.append({
            "priority": risk,
            "title": f"Review open port {port}",
            "service": service,
            "guidance": guidance,
        })

    return recommendations


def scan_headers(url):
    parsed = urlparse(url if url.startswith(("http://", "https://")) else f"https://{url}")

    if not parsed.hostname:
        raise ValueError("A valid internal URL is required.")

    validate_private_target(parsed.hostname)

    try:
        response = requests.head(parsed.geturl(), timeout=4, allow_redirects=True)
    except requests.RequestException:
        response = requests.get(parsed.geturl(), timeout=4, allow_redirects=True)

    present = []
    missing = []

    for header, purpose in SECURITY_HEADERS.items():
        if header in response.headers:
            present.append({
                "header": header,
                "value": response.headers.get(header),
                "purpose": purpose,
                "status": "present",
            })
        else:
            missing.append({
                "header": header,
                "purpose": purpose,
                "status": "missing",
                "risk": "medium" if header in {"Content-Security-Policy", "Strict-Transport-Security"} else "low",
            })

    return {
        "scan_type": "web_security_header_scan",
        "url": response.url,
        "status_code": response.status_code,
        "timestamp": utc_now(),
        "present_headers": present,
        "missing_headers": missing,
        "missing_count": len(missing),
        "recommendations": build_header_recommendations(missing),
    }


def build_header_recommendations(missing):
    if not missing:
        return [
            {
                "priority": "low",
                "title": "Security headers look complete",
                "guidance": "Keep headers monitored during application and proxy changes.",
            }
        ]

    return [
        {
            "priority": item["risk"],
            "title": f"Add {item['header']}",
            "guidance": item["purpose"],
        }
        for item in missing
    ]


def discover_private_subnet(cidr, ports):
    network = validate_private_subnet(cidr)
    hosts = [str(host) for host in network.hosts()]
    ports = list(dict.fromkeys([int(port) for port in ports]))[:SAFE_MAX_PORTS]

    discovered = []

    def scan_host(host):
        open_ports = []
        for port in ports:
            try:
                result = check_single_port(host, port)
                if result["state"] == "open":
                    open_ports.append(result)
            except OSError:
                continue

        if open_ports:
            return {
                "host": host,
                "open_port_count": len(open_ports),
                "open_ports": open_ports,
                "highest_risk": highest_risk(open_ports),
            }

        return None

    with ThreadPoolExecutor(max_workers=32) as pool:
        future_map = {pool.submit(scan_host, host): host for host in hosts}
        for future in as_completed(future_map):
            item = future.result()
            if item:
                discovered.append(item)

    discovered.sort(key=lambda item: item["host"])

    return {
        "scan_type": "private_subnet_device_discovery",
        "cidr": str(network),
        "timestamp": utc_now(),
        "hosts_reviewed": len(hosts),
        "devices_found": len(discovered),
        "devices": discovered,
        "recommendations": build_discovery_recommendations(discovered),
    }


def highest_risk(open_ports):
    order = {"high": 3, "medium": 2, "low": 1, "none": 0}
    highest = "none"
    for port in open_ports:
        if order.get(port["risk"], 0) > order[highest]:
            highest = port["risk"]
    return highest


def build_discovery_recommendations(devices):
    if not devices:
        return [
            {
                "priority": "low",
                "title": "No devices found with the selected service set",
                "guidance": "Use this as a baseline and repeat after network or firewall changes.",
            }
        ]

    recommendations = []
    for device in devices:
        priority = device["highest_risk"]
        recommendations.append({
            "priority": priority,
            "title": f"Review exposed services on {device['host']}",
            "guidance": "Confirm device ownership, expected services, firewall rules, and monitoring coverage.",
        })

    return recommendations

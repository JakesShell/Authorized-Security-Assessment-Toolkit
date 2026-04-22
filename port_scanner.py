import socket

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt"
}


def scan_common_ports(target):
    print(f"\nReviewing common ports on {target}...")
    open_ports = []

    for port, service in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        sock.close()

        if result == 0:
            print(f"Port {port} ({service}) is open.")
            open_ports.append({"port": port, "service": service})

    return open_ports


if __name__ == "__main__":
    target_input = input("Enter the target hostname or IP address: ").strip()
    scan_common_ports(target_input)

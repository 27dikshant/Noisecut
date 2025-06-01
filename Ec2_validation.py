import socket
import sys

def port_scan(ip):
    ports = [22, 3389]
    open_ports = []

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)  # 2 second timeout
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except socket.error as err:
            print(f"Socket error while scanning port {port}: {err}")

    if open_ports:
        print(f"Open ports on {ip}: {open_ports}")
    else:
        print(f"No open ports (22, 3389) found on {ip}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Error: No IP address supplied.\nUsage: python3 port_scanner.py <IP_ADDRESS>")
        sys.exit(1)

    target_ip = sys.argv[1]
    port_scan(target_ip)

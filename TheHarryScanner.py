
import tqdm
import socket
import csv
import ipinfo
import ipaddress
import pyfiglet
import traceback
from datetime import datetime
import pytz

ascii_banner = pyfiglet.figlet_format("THE HARRY SCANNER")
print(ascii_banner)

# Initialize ipinfo client
def get_ip_details(ip):
    access_token = "3ed0f927b72bf1"
    handler = ipinfo.getHandler(access_token)

    # Get IP details
    details = handler.getDetails(ip)
    return details.all

# Geolocate IP address
def print_details(ip_details):
    print(f"IP address: {ip_details['ip']}")
    if 'city' in ip_details:
        print(f"City: {ip_details['city']}")
    else:
        print("No city information available for this IP.")
    if 'region' in ip_details:
        print(f"Region: {ip_details['region']}")
    else:
        print("No region information available for this IP.")
    if 'country_name' in ip_details:
        print(f"Country: {ip_details['country_name']}")
    else:
        print("No country information available for this IP.")
    if 'longitude' in ip_details:
        print(f"Longitude: {ip_details['longitude']}")
    else:
        print("No longitude information available for this IP.")
    if 'latitude' in ip_details:
        print(f"Latitude: {ip_details['latitude']}")
    else:
        print("No latitude information available for this IP.")
    if 'postal' in ip_details:
        print(f"Postal code: {ip_details['postal']}")
    if 'asn' in ip_details:
        print(f"AS: {ip_details['asn']} {ip_details['org']}")
    if 'isp' in ip_details:
        print(f"ISP: {ip_details['isp']}")
    if 'timezone' in ip_details:
        tz = pytz.timezone(ip_details['timezone'])
        dt = datetime.now(tz)
        print(f"Timezone: {ip_details['timezone']}")
        print(f"Date: {dt.strftime('%Y-%m-%d')}")
        print(f"Time: {dt.strftime('%H:%M:%S')}")

# Scan ports
def scan_ports(ip, ports):
    open_ports = []

    for port in tqdm.tqdm(ports):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                print(f"Port {port} is open.")
            sock.close()
        except KeyboardInterrupt:
            print("Scan interrupted by user.")
            exit()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
            traceback.print_exc()
    
    return open_ports

# Scan IP address
def scan_ip(ip, ports):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        print(f"Hostname: {hostname}")
    except socket.herror:
        pass

    ip_details = get_ip_details(ip)
    print(f"Details for IP address {ip}:")
    print_details(ip_details)

    open_ports = scan_ports(ip, ports)  # Retrieve open ports
    return open_ports

# Write results to a CSV file
def write_csv(open_ports, ip, filename):
    with open(filename, 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write the header
        writer.writerow(["IP", "Port", "Date & Time"])

        # Write the scan results
        for port in open_ports:
            dt = datetime.now()
            writer.writerow([ip, port, dt.strftime('%Y-%m-%d %H:%M:%S')])

# Initialize variables
ip = None
ip_range = None
ports = list(range(1, 55))

# Ask the user for input
option = input("Enter '1' to scan a single IP address, or '2' to scan a range of IPs: ")
if option == "1":
    ip = input("Enter IP address to scan: ")
elif option == "2":
    ip_range = input("Enter IP range to scan (e.g. 192.168.1.1/24): ")
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        print("Invalid IP address range. Please try again.")
        exit()
else:
    print("Invalid option. Please try again.")
    exit()

# Scan IP addresses
if ip:
    open_ports = scan_ip(ip, ports)  # Retrieve open ports
    filename = f"{ip}_scan_results.csv"
    write_csv(open_ports, ip, filename)  # Write open ports to CSV
elif ip_range:
    scan_results = []
    for ip in network.hosts():
        ip = str(ip)
        try:
            open_ports = scan_ip(ip, ports)  # Retrieve open ports
            scan_results.extend(open_ports)
        except KeyboardInterrupt:
            print("Scan interrupted by user.")
            break
    filename = f"{ip_range}_scan_results.csv"
    write_csv(scan_results, ip_range, filename)  # Write open ports to CSV

else:
    print("No input provided. Please try again.")
    exit()






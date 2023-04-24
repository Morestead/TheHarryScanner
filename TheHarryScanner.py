# This script is a port scanner that can scan a single IP address or a range of IP addresses. It uses the socket library to create a socket object and connect to ports, and the tqdm library to provide a progress bar while scanning.

# The script also uses the ipinfo library to get details about an IP address, such as the city, region, country, latitude, longitude, postal code, and time zone.

# After scanning, the script writes the results to a CSV file with the format "Host, Port, Service, Banner".

# The script begins with importing necessary libraries and dependencies like pyfiglet, tqdm, socket, csv, ipinfo, ipaddress. (You will need to input your own ipinfo.io access token on line 36)

# Next, the script defines the get_ip_details() function that takes an IP address as input, initializes an ipinfo client with an access token, and returns the details of the IP address.

# Then, the script defines the scan_ports() function that takes an IP address and a list of ports as input, and returns a list of open ports and a list of scan results. This function iterates over the ports and uses the socket library to create a socket object and connect to each port. If the port is open, it appends the port number to the open_ports list and collects the banner. Then, it appends the scan results to the results list.

# The script also defines the print_details() function that takes an IP address details dictionary as input and prints the relevant details.

# The scan_ip() function takes an IP address and a list of ports as input and scans the IP address for open ports using the scan_ports() function. It also gets the IP address details using the get_ip_details() function and prints them using the print_details() function.

# The write_csv() function takes the scan results and a filename as input and writes the results to a CSV file.

# Finally, the script prompts the user to enter an option to scan a single IP address or a range of IP addresses, and then prompts for the IP address or IP range to scan. It then scans the IP addresses and writes the results to a CSV file.

#!/bin/env python3

import tqdm
import socket
import csv
import ipinfo
import ipaddress
import pyfiglet
import traceback

ascii_banner = pyfiglet.figlet_format("THE HARRY SCANNER")
print(ascii_banner)


# Initialize ipinfo client
def get_ip_details(ip):
    access_token = "3ed0f927b72bf1"
    handler = ipinfo.getHandler(access_token)

    # Get IP details
    details = handler.getDetails(ip)
    return details.all


# Initialize variables
def scan_ports(ip, ports):
    results = []
    open_ports = []

    for port in tqdm.tqdm(ports):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                results.append((ip, port, "Open", ""))
                print(f"Port {port} is open.")
            sock.close()
        except KeyboardInterrupt:
            print("Scan interrupted by user.")
            exit()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
            traceback.print_exc()
            
    return open_ports, results

1
# Geolocate IP address
def print_details(ip_details):
    print(f"IP address: {ip_details['ip']}")
    if 'city' in ip_details:
        print(f"City: {ip_details['city']}")
    else:
        print("No city information available for this IP.")
    print(f"Region: {ip_details['region']}")
    print(f"Country: {ip_details['country_name']}")
    print(f"Latitude: {ip_details['latitude']}")
    print(f"Longitude: {ip_details['longitude']}")
    print(f"Postal code: {ip_details['postal']}")
    print(f"Time zone: {ip_details['timezone']}")


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

    open_ports, scan_results = scan_ports(ip, ports)
    return scan_results


# Write results to CSV file
def write_csv(scan_results, filename):
    if not filename.endswith(".csv"):
        filename += ".csv"
    with open(filename, mode="w") as file:
        writer = csv.writer(file)
        writer.writerow(["Host", "Port", "Service", "Banner"])
        for result in scan_results:
            writer.writerow(result)
    print(f"Results written to CSV file {filename}.")


# Initialize variables
ip = None
ip_range = None
ports = list(range(1, 100))

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
    scan_results = scan_ip(ip, ports)
    filename = f"{ip}_scan_results.csv"
elif ip_range:
    scan_results = []
    for ip in network.hosts():
        ip = str(ip)
        try:
            scan_results.extend(scan_ip(ip, ports))
        except KeyboardInterrupt:
            print("Scan interrupted by user.")
            break
    filename = f"{ip}_scan_results.csv"
else:
    print("No input provided. Please try again.")
    exit()

# Write results to CSV file
write_csv(scan_results, filename)





# This script is a Python program that scans for open ports on one or more IP addresses and writes the results to a CSV file. It uses the socket module to create a socket object for each IP and port combination and attempts to connect to it to determine if the port is open or closed. If the port is open, the script collects the banner (if available) and adds the IP address, port number, status, and banner to the results.

# The script also uses the ipinfo module to geolocate the IP addresses and collect additional information about the IP address, such as the city, region, country, latitude, longitude, postal code, and time zone.

# The ipaddress module is used to handle IP address ranges. The user can enter a single IP address or an IP address range in the format start_ip-end_ip.

# The script defines four functions:

#    get_ip_details: Returns IP details for a given IP address using the ipinfo module.
#    scan_ports: Scans for open ports on a given IP address and a list of ports.
#    write_csv: Writes the results to a CSV file.
#    print_details: Prints the geolocation details for a given IP address.

# The main function of the script prompts the user to enter an IP address or IP range, scans the ports of each IP address, and writes the results to a CSV file. It also prints the geolocation details for each IP address

# Note that the script requires the ipinfo library to be installed and an access token for the ipinfo API. You can obtain an access token by signing up for a free account on the ipinfo website. Techincally for better practise you could store the access_token variable instead of hard coding it, you can do this by creating a separate file named config.py and adding the access_token variable as a global variable in that file. Here's an example:
# makefile
# access_token = "3ed0f927b72bf1"

# Then, in your main script, you can import the access_token variable from the config.py file using the import statement:
#     import config
#     def get_ip_details(ip):
#     Initialize ipinfo client
#     handler = ipinfo.getHandler(config.access_token)
#     Rest of the code ...
    
# Line 65 add your own ipinfo.io access_token to the variable

# If nothing happens, you can try running the program with the -u flag, which forces the output to be unbuffered and printed immediately. You can do this by running the following command:
# python -u portscanner.py     --   although very unlikely to be needed

# If you are running the code on a version of Python that does not support f-strings. This feature was introduced in Python 3.6. To fix this error, you can replace the f-string with string concatenation using the + operator, like this:
# print("\nIP Address: " + ip_details['ip'])     -- You'll need to replace all f-strings in the code with this syntax however, so probably better to update and get the latest version of python and all other directories needed

# Be sure to have ipinfo installed for Python 3.6.... You can run the following command to install ipinfo for Python 3.6:
# python3.6 -m pip install ipinfo     --   no pip needed if you are on a later model

# This should install ipinfo for Python 3.6 specifically. Once it is installed, try running your port scanner again with Python 3.6

# python3.6 -m pip install --upgrade pip     -- This will upgrade pip to the latest version that's compatible with Python 3.6

# Be sure to be in the /python directory and that inside you have   --   ipinfo, csv & socket installed so they are able to be imported

# Feel free to add any extra print statements should they be needed for you, however I feel like there are plenty as it covers all bases

# To write an IP range, you can do it as an input by separating the start IP and end IP with a hyphen (-), like this:
# 192.168.0.1/24

# In this script, the default range of ports being scanned is from 1 to 1000. It could take a few minutes to several hours, depending on the number of ports being scanned and the speed of the network connection. It is also worth noting that the settimeout() method is set to 0.5 seconds, which means that each port will be given half a second to respond. If a port takes longer to respond, the script will move on to the next port. Therefore, increasing the timeout value will increase the time it takes for the script to complete the scan.

# In the final function input the script first initializes ip and ip_range to None and then asks the user which option they would like to use by prompting them to enter either '1' or '2'. Depending on the user's choice, the script then either prompts them for an IP address or an IP range... The input "193.176.30.20/24" specifies an IP address range to scan. In particular, it specifies a range of IP addresses with the prefix 193.176.30, and it will scan all the IP addresses in that range from 193.176.30.0 to 193.176.30.255. The "/24" at the end of the IP address specifies the number of bits in the network prefix, which in this case is 24. The network prefix determines which part of the IP address identifies the network and which part identifies the host within that network. In this case, the first three octets (i.e. 193.176.30) identify the network, while the last octet can take any value between 0 and 255 to identify individual hosts within that network. The first three octets (82.112.149) represent the network portion and the last octet (182) represents the host portion.

#!/bin/env python3

import tqdm
import socket
import csv
import ipinfo
import ipaddress
import pyfiglet

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

    # Scan ports
    for port in tqdm.tqdm(ports):
        try:
            # Create socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)

            # Connect to port
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)

                # Collect banner
                banner = sock.recv(1024)
                banner = banner.decode().strip()

                # Add to results
                results.append((ip, port, "Open", banner))
                print(f"Port {port} is open.")
            else:
                results.append((ip, port, "Closed", ""))

            sock.close()
        except KeyboardInterrupt:
            print("Scan interrupted by user.")
            exit()
        except:
            pass

    return open_ports, results


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





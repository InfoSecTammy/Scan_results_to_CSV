import ipaddress
import subprocess
import csv
import sys

# Function to perform Nmap scan and parse the results
def nmap_scan(ip_range):
    try:
        # Constructing Nmap command
        print(f"Scanning IP range: {ip_range}")
        result = subprocess.run(['nmap', '-sS', str(ip_range)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            print(f"Scan successful for {ip_range}")
            
            # Parse Nmap output for open ports and hostnames
            open_ports = []
            hostname = None
            for line in result.stdout.splitlines():
                if 'Nmap scan report for' in line:
                    # Extract the hostname or IP address
                    hostname = line.split(" ")[-1]
                elif 'open' in line:  # Look for open ports
                    port_info = line.split()
                    open_ports.append(port_info[0])  # Extract port (e.g., 80/tcp)

            if open_ports:
                # Write to CSV
                write_to_csv(hostname, open_ports)
        else:
            print(f"Error scanning {ip_range}: {result.stderr}")
    except Exception as e:
        print(f"Error: {e}")

# Function to write results to a CSV file
def write_to_csv(hostname, open_ports):
    with open('nmap_scan_results.csv', 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # Write header if the file is empty
        if csvfile.tell() == 0:
            writer.writerow(['Hostname', 'Open Ports'])
        # Write the hostname and open ports to the CSV file
        writer.writerow([hostname, ', '.join(open_ports)])

# Function to generate the IP range and perform scan
def scan_ip_range(fromaddr, toaddr):
    try:
        # Convert IPs to network objects
        from_ip = ipaddress.ip_address(fromaddr)
        to_ip = ipaddress.ip_address(toaddr)
        
        # Check if the range is valid (fromaddr should not be larger than toaddr)
        if from_ip > to_ip:
            print(f"Invalid range: {fromaddr} cannot be greater than {toaddr}")
            return
        
        # Create a range of IP addresses
        ip_range = ipaddress.summarize_address_range(from_ip, to_ip)
        
        # Scan each network segment in the range
        for network in ip_range:
            nmap_scan(network)
    
    except ValueError as e:
        print(f"Error: {e}")

# Main function to accept command-line arguments and call the scan function
def main():
    if len(sys.argv) != 3:
        print("Usage: python script.py <fromaddr> <toaddr>")
        sys.exit(1)
    
    fromaddr = sys.argv[1]
    toaddr = sys.argv[2]
    
    # Perform the scan on the provided range
    scan_ip_range(fromaddr, toaddr)

# Entry point of the script
if __name__ == "__main__":
    main()

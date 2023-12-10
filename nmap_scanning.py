import nmap
import socket
from datetime import datetime, time as dt_time
import requests
import sys

import nmap
import socket
from datetime import time as dt_time
import requests

def run_initial_nmap_scan():
    global initial_nmap_result
    nm = nmap.PortScanner()
    try:
        # Get the local machine's IP address
        local_ip = socket.gethostbyname(socket.gethostname())
        print(f"Local IP address: {local_ip}")

        # Logging: Add a log to indicate the start of the Nmap scan
        print("Running initial Nmap scan...")

        # Scan the local network
        nm.scan(hosts=f'{local_ip}/24', arguments='-sn -T5')

        # Logging: Print the Nmap command executed
        print("Nmap command:", nm.command_line())

        # Logging: Print the scan results
        print("Nmap scan results:", nm.all_hosts(), nm)

        # Logging: Add a log to indicate the completion of the Nmap scan
        print("Nmap scan completed.")

        initial_nmap_result = nm.all_hosts(), nm
        return initial_nmap_result  # Return the result
    except Exception as e:
        # Logging: Add a log to indicate an error during the Nmap scan
        print(f"Error during Nmap scan: {e}")
        initial_nmap_result = None  # Set initial_nmap_result to None in case of an error
        return None

initial_nmap_result = run_initial_nmap_scan()

def run_nmap_scan(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-p 80,443')
    return nm.all_hosts(), nm

def parse_nmap_output(nmap_hosts, nm):
    devices = []
    for host in nmap_hosts:
        ip = host
        mac = nm[host]['addresses'].get('mac', 'Unknown')
        manufacturer = nm[host]['vendor'] if 'vendor' in nm[host] else 'Unknown'
        hostname = nm[host]['hostnames'][0]['name'] if 'hostnames' in nm[host] and nm[host]['hostnames'] else 'Unknown'
        device_info = {
            'device_name': get_device_name(mac),
            'ip': ip,
            'mac': mac,
            'manufacturer': manufacturer,
            'hostname': hostname
        }
        devices.append(device_info)
    
    return devices


def get_device_name(mac_address):
    try:
        url = f'https://api.macvendors.com/{mac_address}'
        response = requests.get(url)
        if response.status_code == 200:
            return response.text.strip()
        else:
            return 'Unknown'
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        return 'Unknown'


def parse_device_id(device_select):
    if device_select:
        parts = device_select.split('_')
        if len(parts) == 2:
            ip_address, mac_address = parts
            print(f'Parsed IP: {ip_address}, MAC: {mac_address}')
            return ip_address, mac_address
        else:
            print('Invalid device_select format')
            return None, None
    else:
        print('device_select is None')
        return None, None
    
def get_schedule_times(form):
    start_time = dt_time(8, 0)  # Replace with the actual start time
    end_time = dt_time(17, 0)  # Replace with the actual end time
    return start_time, end_time

def log_and_exit(text):
    print(text)
    sys.exit(1)

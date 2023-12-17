import socket
import json
import logging
from pathlib import Path
from datetime import time as dt_time
import nmap
import requests
import sys

# Configure logging
logging.basicConfig(level=logging.INFO)

# Constants
NETWORK_MASK = '/24'
NMAP_ARGUMENTS = '-sn -T5'
LOG_FILE_PATH = 'nmap_result.json'

def run_initial_nmap_scan():
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        logging.info(f"Local IP address: {local_ip}")
        logging.info("Running initial Nmap scan...")

        nm = nmap.PortScanner()
        nm.scan(hosts=f'{local_ip}{NETWORK_MASK}', arguments=NMAP_ARGUMENTS)

        logging.info("Nmap command: %s", nm.command_line())
        logging.info("Nmap scan results: %s", nm.all_hosts())

        nmap_result = {"hosts": []}

        for host in nm.all_hosts():
            try:
                logging.info(f"Processing host: {host}")
                host_info = {
                    "ip": host,
                    "mac": nm[host]['addresses'].get('mac', 'Unknown'),
                    "manufacturer": nm[host]['vendor'] if 'vendor' in nm[host] else 'Unknown',
                    "hostname": nm[host]['hostnames'][0]['name'] if 'hostnames' in nm[host] and nm[host]['hostnames'] else 'Unknown',
                    "status": nm[host].state(),
                    "open_ports": []
                }

                if 'tcp' in nm[host]:
                    for port in nm[host]['tcp']:
                        if 'state' in nm[host]['tcp'][port] and nm[host]['tcp'][port]['state'] == 'open':
                            port_info = {
                                "port": port,
                                "protocol": nm[host]['tcp'][port]['protocol'],
                                "service": nm[host]['tcp'][port]['name']
                            }
                            host_info["open_ports"].append(port_info)

                nmap_result["hosts"].append(host_info)
                logging.info(f"Host {host} processed successfully.")
            except Exception as e:
                logging.error(f"Error processing host {host}: {e}")

        return nmap_result
    except Exception as e:
        logging.error(f"Error during Nmap scan: {e}")
        return None

def save_nmap_result(result):
    with open(LOG_FILE_PATH, 'w') as file:
        json.dump(result, file)

def load_nmap_result():
    if Path(LOG_FILE_PATH).exists():
        try:
            with open(LOG_FILE_PATH, 'r') as file:
                return json.load(file)
        except json.decoder.JSONDecodeError as e:
            logging.error(f"Error decoding JSON: {e}")
            return None
    else:
        logging.info("File nmap_result.json not found.")
        return None

def parse_nmap_output(nmap_hosts, nm):
    devices = []
    for host in nmap_hosts:
        try:
            logging.info(f"Processing host: {host}")
            
            host_info = {
                "ip": host,
                "mac": nm[host].get('addresses', {}).get('mac', 'Unknown'),
                "manufacturer": nm[host].get('vendor', 'Unknown'),
                "hostname": nm[host].get('hostnames', [{'name': 'Unknown'}])[0].get('name', 'Unknown'),
                "status": nm[host].get('status', {}).get('state', 'Unknown'),
                "open_ports": []
            }

            if 'tcp' in nm[host]:
                for port in nm[host]['tcp']:
                    if 'state' in nm[host]['tcp'][port] and nm[host]['tcp'][port]['state'] == 'open':
                        port_info = {
                            "port": port,
                            "protocol": nm[host]['tcp'][port].get('protocol', 'Unknown'),
                            "service": nm[host]['tcp'][port].get('name', 'Unknown')
                        }
                        host_info["open_ports"].append(port_info)

                devices.append(host_info)
                logging.info(f"Host {host} processed successfully.")
        except Exception as e:
            logging.error(f"Error processing host {host}: {e}")

            # If an error occurs, add a default entry with 'Unknown' values
            default_entry = {
                "ip": host,
                "mac": 'Unknown',
                "manufacturer": 'Unknown',
                "hostname": 'Unknown',
                "status": 'Unknown',
                "open_ports": []
            }
            devices.append(default_entry)

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
        logging.error(f"An error occurred: {e}")
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
    
def get_schedule_times(form):
    start_time = dt_time(8, 0)  # Replace with the actual start time
    end_time = dt_time(17, 0)  # Replace with the actual end time
    return start_time, end_time

def log_and_exit(text):
    logging.error(text)
    sys.exit(1)

if __name__ == "__main__":
    initial_nmap_result = run_initial_nmap_scan()
    if initial_nmap_result and "hosts" in initial_nmap_result:
        nmap_hosts = initial_nmap_result["hosts"]
        nm = nmap.PortScanner()
        nm._scan_result = {'scan': {host['ip']: host for host in nmap_hosts}}
        save_nmap_result(initial_nmap_result)
        devices = parse_nmap_output(nm.all_hosts(), nm)
        logging.info("Parsed devices: %s", devices)
    else:
        log_and_exit("Error during initial Nmap scan. Exiting.")

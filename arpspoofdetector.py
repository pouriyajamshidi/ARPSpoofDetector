#!/usr/bin/env/ python3

import signal
from re import search
from subprocess import check_output
from time import sleep
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from sys import platform


def signal_handler(signal, frame):
    print("\033[95m", end="")
    print(f"\nSIGINT Detected... Exiting")
    print("\033[0m", end="")
    exit(0)


def get_linux_gw():
    IP_command = ["ip", "route", "show", "match", "0/0"]
    gw_ip_output = check_output(IP_command).decode()
    gw_ip = search(r"(\d*\.){3}\d*", gw_ip_output)[0]

    dev = (gw_ip_output.split())[-1]

    GW_command = ["ip", "neighbor", "show", "dev", dev]
    gw_mac_output = check_output(GW_command).decode()
    gw_mac = search(r"..:..:..:..:..:..", gw_mac_output)[0]

    return gw_ip, gw_mac


def check_linux_gw(gw_ip):
    broadcast_address = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_query = ARP(pdst=gw_ip)
    packet = broadcast_address/arp_query
    request = srp(packet, verbose=False, timeout=2)[0][0][1].hwsrc

    return request


def main():

    if platform == "win32":
        print("[+] Windows support will be added soon! ", end="")
        print("Stay tuned for future updates.")
        exit(0)
    else:
        gw_ip, gw_mac = get_linux_gw()
        queried_mac = check_linux_gw(gw_ip)

    while True:

        if queried_mac != gw_mac:
            print("\033[91m", end="")
            print(f"[*] Possible ARP spoof attack!")
            print(f"[*] Received MAC is at:\t{gw_mac}")
            print(f"[*] Gateway MAC is at:\t{queried_mac}")
            print("\033[0m", end="")
        else:
            print("\033[92m", end="")
            print(f"[+] Gateway is {gw_ip} at {gw_mac}")
            print("\033[0m", end="")

        sleep(10)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()

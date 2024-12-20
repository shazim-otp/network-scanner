from scapy.all import ARP, Ether, srp

def banner():
    print("="*50)
    print("               NETWORK SCANNER - By SHAZAM")
    print("="*50)

def scan_network(ip_range):
    # Create ARP packet
    arp_request = ARP(pdst=ip_range)
    # Create Ethernet frame
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine ARP request with Ethernet frame
    packet = ether_frame / arp_request

    print(f"Scanning network: {ip_range}...")

    # Send the packet and capture the response
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'IP': received.psrc, 'MAC': received.hwsrc})

    return devices

def find_device_by_mac(mac_address, devices):
    for device in devices:
        if device['MAC'].lower() == mac_address.lower():
            return device
    return None

if __name__ == "__main__":
    banner()
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ")
    devices = scan_network(ip_range)

    print("\nDevices found:")
    print("------------------------")
    for device in devices:
        print(f"IP: {device['IP']}, MAC: {device['MAC']}")
    print("------------------------")

    while True:
        print("\nOptions:")
        print("1. Search for a device by MAC address")
        print("2. Exit")
        choice = input("Enter your choice (1 or 2): ")

        if choice == "1":
            mac_address = input("Enter the MAC address to search for (e.g., 00:11:22:33:44:55): ")
            device = find_device_by_mac(mac_address, devices)

            if device:
                print(f"Device found: IP = {device['IP']}, MAC = {device['MAC']}")
            else:
                print("Device not found.")
        elif choice == "2":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

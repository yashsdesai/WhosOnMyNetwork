import scapy.all as scapy
import socket


def get_network_range():

    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)

        network_range = ".".join(ip_address.split('.')[:-1]) + ".0/24"
        return network_range
    except socket.error as e:
        print(f"Error getting local IP: {e}")
        return None


def scan_network(ip):

    if not ip:
        print("Could not determine network range.")
        return []

    arp_request = scapy.ARP(pdst=ip)
    broadcast_ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast_ether / arp_request

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices_list = []
    for element in answered_list:
        ip_addr = element[1].psrc
        mac_addr = element[1].hwsrc

        try:
            device_name = socket.gethostbyaddr(ip_addr)[0]
        except (socket.herror, socket.gaierror):
            device_name = "Unknown"

        devices_list.append({"name": device_name, "ip": ip_addr, "mac": mac_addr})

    return devices_list


if __name__ == "__main__":
    network_range = get_network_range()

    if network_range:
        print(f"Scanning network: {network_range}\n")

        connected_devices = scan_network(network_range)

        if connected_devices:
            print("Connected Devices:")
            print("-" * 50)
            print("{:<20} {:<15} {:<18}".format("Device Name", "IP Address", "MAC Address"))
            print("-" * 50)
            for device in connected_devices:
                print("{:<20} {:<15} {:<18}".format(device['name'], device['ip'], device['mac']))
            print("-" * 50)
        else:
            print("No devices found.")


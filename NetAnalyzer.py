from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP


def packet_analyser(int_packet, s_protocol):
    global payload, src_port, dst_port
    if int_packet.haslayer(IP):
        src_ip = int_packet[IP].src
        dst_ip = int_packet[IP].dst
        print(f"{'Source IP:':<15} {src_ip:<15} >>> {'Destination IP:':<15} {dst_ip:<15}")

        if int_packet.haslayer(TCP):
            s_protocol = "TCP"
            src_port = int_packet[TCP].sport
            dst_port = int_packet[TCP].dport
            payload = int_packet[TCP].payload
        elif int_packet.haslayer(UDP):
            s_protocol = "UDP"
            src_port = int_packet[UDP].sport
            dst_port = int_packet[UDP].dport
            payload = int_packet[UDP].payload
        elif int_packet.haslayer(ICMP):
            s_protocol = "ICMP"
            src_port = None
            dst_port = None
            payload = int_packet[ICMP].payload

        print(f"{'Protocol:':<15} {s_protocol:<15}")
        if src_port and dst_port:
            print(f"{'Source Port:':<15} {src_port:<15} >>> {'Destination Port:':<15} {dst_port:<15}")

        print("Payload Hex Data:")
        payload_hex = ' '.join(f"{i:02x}" for i in bytes(payload))
        print(format_payload(payload_hex))

        print("Decoded Payload Data:")
        try:
            decoded_payload = payload.decode()
            print(decoded_payload)
        except Exception as e:
            print("Raw Payload")


def format_payload(payload_hex):
    formatted_payload = ""
    for i in range(0, len(payload_hex), 32):
        chunk = payload_hex[i:i + 32]
        formatted_payload += ' '.join([chunk[j:j + 2] for j in range(0, len(chunk), 2)]) + '\n'
    return formatted_payload.strip()


interfaces = get_if_list()
print("Available Interfaces:")
for idx, interface in enumerate(interfaces, start=1):
    print(f"{idx}. {interface}")

interface_index = int(input("Enter the interface index for sniffing: "))
selected_interface = interfaces[interface_index - 1]

protocol = input("Enter the service protocol to filter (TCP/UDP/ICMP): ").upper()
if protocol == '':
    print(" Please enter either TCP/UDP/ICMP!")
    exit()

num_packets = int(
    input("Enter the number of packets to capture (enter 0 for continuous capture,and ctrl+c to exit the capture): "))

conf.iface = selected_interface
p_count = 0

while True:
    if num_packets != 0 and p_count >= num_packets:
        break
    packet = sniff(count=1)[0]
    packet_analyser(packet, protocol)
    p_count += 1

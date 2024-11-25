import socket
import struct
import textwrap

def format_multi_line(prefix, string, size=80):
    """Format data for multi-line display."""
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size += 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def ethernet_frame(data):
    """Unpack Ethernet frame."""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    """Convert a MAC address from bytes to a readable format."""
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def ipv4_packet(data):
    """Unpack IPv4 packet."""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    """Convert a 4-byte IPv4 address to dotted-quad format."""
    return '.'.join(map(str, addr))

def main():
    """Main sniffer function."""
    # Create a raw socket to capture packets
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)  # Receive packets
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'\tDestination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}')

        # IPv4
        if eth_proto == 8:  # IPv4 protocol
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(f'\tIPv4 Packet:')
            print(f'\t\tVersion: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'\t\tProtocol: {proto}, Source IP: {src}, Destination IP: {target}')

            # Print raw data
            print(f'\t\tData:')
            print(format_multi_line('\t\t\t', data))

if __name__ == "__main__":
    main()

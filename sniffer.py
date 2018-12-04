import socket
import struct
import textwrap
import pcap


def main():
    """
    Wait and listen for packets to come in.
    """
    connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.htons(0x03))

    # Start the main loop.
    while True:
        # 65536 is the biggest buffer size that can be used.
        raw_data, addr = connection.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))


def ethernet_frame(packet):
    """
    Unpack ethernet frame.
    (sync, receiver, sender, type, payload, crc)
    - dest_mac, src_mac are 6s - 6 characters
    - H - small unsigned int
    All this is in the first 14 bytes.
    socket.htons - format data to readable (little/big indi).
    Data after first 14 bytes is the actual payload.
    """
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', packet[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), packet[14:]


def get_mac_addr(bytes):
    """
    Properly format a mac address.
    Expected final format: AA:BB:CC:DD:EE:FF
    """
    bytes_str = map('{:02x}'.format, bytes)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


if __name__ == '__main__':
    main()

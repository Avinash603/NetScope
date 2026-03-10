# ============================================================
# NetScope - Network Packet Analyzer
# ============================================================
#
# What is a PCAP file?
# A PCAP file is a recording of network traffic.
# Tools like Wireshark save network packets into .pcap files.
# Each packet is a chunk of data sent over the network.
#
# PCAP File Structure:
#   [Global Header - 24 bytes]   <- file info
#   [Packet Header - 16 bytes]   <- timestamp, length
#   [Packet Data   - N bytes ]   <- actual network bytes
#   [Packet Header - 16 bytes]
#   [Packet Data   - N bytes ]
#   ... repeats for every packet

import struct  # struct helps us read binary (raw bytes) data
import sys


def read_pcap(filename):
    """
    Open a PCAP file and count all packets inside it.
    Also print the timestamp of the first packet.
    """
    print(f"Opening file: {filename}")
    print("-" * 40)

    try:
        f = open(filename, 'rb')  # 'rb' = read binary
    except FileNotFoundError:
        print(f"ERROR: File '{filename}' not found!")
        print("Please provide a valid .pcap file.")
        return

    # ── Step 1: Read the Global Header (always 24 bytes) ──────────────
    global_header = f.read(24)

    if len(global_header) < 24:
        print("ERROR: File is too small to be a valid PCAP file!")
        f.close()
        return

    # The first 4 bytes are the "magic number"
    # Magic number tells us if the file is valid PCAP
    # 0xa1b2c3d4 = standard PCAP format
    magic_number = struct.unpack('<I', global_header[0:4])[0]

    if magic_number == 0xa1b2c3d4:
        print("File format : PCAP (valid!)")
    else:
        print(f"File format : Unknown (magic = {hex(magic_number)})")
        print("This might not be a valid PCAP file.")
        f.close()
        return

    # Bytes 20-24 tell us the link type (1 = Ethernet, most common)
    link_type = struct.unpack('<I', global_header[20:24])[0]
    print(f"Link type   : {link_type} (1 = Ethernet)")

    # ── Step 2: Read packets one by one ───────────────────────────────
    packet_count  = 0
    total_bytes   = 0
    first_timestamp = None

    while True:
        # Every packet starts with a 16-byte header
        packet_header = f.read(16)

        # If we can't read 16 bytes, we've reached the end of file
        if len(packet_header) < 16:
            break

        # Unpack the 4 fields from the packet header
        # ts_sec   = timestamp seconds
        # ts_usec  = timestamp microseconds
        # incl_len = how many bytes are saved in this file
        # orig_len = original packet size on the network
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', packet_header)

        # Save the timestamp of the very first packet
        if first_timestamp is None:
            first_timestamp = ts_sec + ts_usec / 1_000_000

        # Read the actual packet data (we just skip it for now)
        packet_data = f.read(incl_len)

        packet_count += 1
        total_bytes  += incl_len

    f.close()

    # ── Step 3: Print the results ──────────────────────────────────────
    print("-" * 40)
    print(f"Total packets : {packet_count}")
    print(f"Total bytes   : {total_bytes} bytes ({total_bytes / 1024:.1f} KB)")

    if first_timestamp:
        import datetime
        dt = datetime.datetime.fromtimestamp(first_timestamp)
        print(f"First packet  : {dt.strftime('%Y-%m-%d %H:%M:%S')}")

    print("-" * 40)
    print(" We can now read a PCAP file.")


# ── Entry point ────────────────────────────────────────────────────────
if __name__ == "__main__":
    # If user passes a filename as argument, use that
    # Otherwise use "sample.pcap" by default
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = "sample.pcap"

    read_pcap(filename)

    # ============================================================
# NetScope - Network Packet Analyzer
# Parse Ethernet headers - extract MAC addresses
# ============================================================
#
# What is an Ethernet Header?
# Every packet on a local network starts with an Ethernet header.
# It contains:
#   - Destination MAC address (6 bytes) - who should receive this
#   - Source MAC address      (6 bytes) - who sent this
#   - EtherType               (2 bytes) - what type of data follows
#                                         0x0800 = IPv4 (most common)
#                                         0x0806 = ARP
#                                         0x86DD = IPv6
#
# A MAC address looks like: aa:bb:cc:dd:ee:ff
# It identifies a physical network device (network card)

import struct
import sys


# ── Ethernet Header Parser ─────────────────────────────────────────────────
def parse_ethernet(data):
    """
    Parse the Ethernet header from raw packet bytes.

    An Ethernet header is always 14 bytes:
      Bytes 0-5  : Destination MAC address
      Bytes 6-11 : Source MAC address
      Bytes 12-13: EtherType (what protocol comes next)

    Returns: (dst_mac, src_mac, ether_type, header_length)
    """
    if len(data) < 14:
        return None, None, None, 0

    # Extract destination MAC (first 6 bytes)
    dst_mac = ':'.join(f'{b:02x}' for b in data[0:6])

    # Extract source MAC (next 6 bytes)
    src_mac = ':'.join(f'{b:02x}' for b in data[6:12])

    # Extract EtherType (next 2 bytes) - '!' means big-endian (network byte order)
    ether_type = struct.unpack('!H', data[12:14])[0]

    return dst_mac, src_mac, ether_type, 14  # header is always 14 bytes


def ether_type_name(ether_type):
    """Convert EtherType number to a human-readable name."""
    types = {
        0x0800: 'IPv4',
        0x0806: 'ARP',
        0x86DD: 'IPv6',
        0x8100: 'VLAN',
    }
    return types.get(ether_type, f'Unknown ({hex(ether_type)})')


# ── PCAP Reader (from Day 1) ───────────────────────────────────────────────
def read_pcap(filename):
    """
    Read a PCAP file and parse Ethernet headers from each packet.
    """
    print(f"Opening file: {filename}")
    print("-" * 60)

    try:
        f = open(filename, 'rb')
    except FileNotFoundError:
        print(f"ERROR: File '{filename}' not found!")
        return

    # Read and validate global header (24 bytes)
    global_header = f.read(24)
    magic = struct.unpack('<I', global_header[0:4])[0]

    if magic != 0xa1b2c3d4:
        print("ERROR: Not a valid PCAP file!")
        f.close()
        return

    print("PCAP file opened successfully!")
    print("-" * 60)

    # Counters for statistics
    packet_count  = 0
    ipv4_count    = 0
    arp_count     = 0
    ipv6_count    = 0
    other_count   = 0
    mac_addresses = set()  # set of unique MAC addresses seen

    # Read each packet
    while True:
        pkt_header = f.read(16)
        if len(pkt_header) < 16:
            break

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_header)
        data = f.read(incl_len)

        packet_count += 1

        # Parse Ethernet header
        dst_mac, src_mac, ether_type, eth_len = parse_ethernet(data)

        if dst_mac is None:
            continue  # packet too small, skip

        # Track unique MAC addresses
        mac_addresses.add(src_mac)
        mac_addresses.add(dst_mac)

        # Count by EtherType
        if ether_type == 0x0800:
            ipv4_count += 1
        elif ether_type == 0x0806:
            arp_count += 1
        elif ether_type == 0x86DD:
            ipv6_count += 1
        else:
            other_count += 1

        # Print first 5 packets in detail so we can see what's happening
        if packet_count <= 5:
            print(f"Packet #{packet_count}:")
            print(f"  Source MAC      : {src_mac}")
            print(f"  Destination MAC : {dst_mac}")
            print(f"  EtherType       : {ether_type_name(ether_type)}")
            print(f"  Packet size     : {incl_len} bytes")
            print()

    f.close()

    # Print summary
    print("-" * 60)
    print("SUMMARY")
    print("-" * 60)
    print(f"Total packets     : {packet_count}")
    print(f"IPv4 packets      : {ipv4_count}")
    print(f"ARP packets       : {arp_count}")
    print(f"IPv6 packets      : {ipv6_count}")
    print(f"Other packets     : {other_count}")
    print(f"Unique MAC addrs  : {len(mac_addresses)}")
    print("-" * 60)
    print(" We can now parse Ethernet headers.")


    # ============================================================
# NetScope - Network Packet Analyzer
# Day 3: Parse IPv4 headers - extract IP addresses
# ============================================================
#
# What is an IPv4 Header?
# After the Ethernet header comes the IP header.
# It tells us WHERE the packet is going on the internet.
#
# IPv4 Header structure (minimum 20 bytes):
#   Byte 0     : Version (4 bits) + Header Length (4 bits)
#   Byte 1     : DSCP/ECN (service type)
#   Bytes 2-3  : Total Length
#   Bytes 4-5  : Identification
#   Bytes 6-7  : Flags + Fragment Offset
#   Byte 8     : TTL (Time To Live - how many hops before discarded)
#   Byte 9     : Protocol (6=TCP, 17=UDP, 1=ICMP)
#   Bytes 10-11: Header Checksum
#   Bytes 12-15: Source IP Address
#   Bytes 16-19: Destination IP Address
#
# Protocol numbers:
#   1  = ICMP (ping)
#   6  = TCP  (web, email, etc.)
#   17 = UDP  (DNS, video streaming, etc.)

import struct
import socket  # socket.inet_ntoa converts bytes to "192.168.1.1" format
import sys


# ── Ethernet Header Parser (from Day 2) ───────────────────────────────────
def parse_ethernet(data):
    if len(data) < 14:
        return None, None, None, 0
    dst_mac    = ':'.join(f'{b:02x}' for b in data[0:6])
    src_mac    = ':'.join(f'{b:02x}' for b in data[6:12])
    ether_type = struct.unpack('!H', data[12:14])[0]
    return dst_mac, src_mac, ether_type, 14


# ── NEW: IPv4 Header Parser ────────────────────────────────────────────────
def parse_ipv4(data, offset):
    """
    Parse IPv4 header starting at 'offset' in the data.

    offset = position right after the Ethernet header (usually 14)

    Returns: (src_ip, dst_ip, protocol, ttl, ip_header_length)
    """
    if len(data) < offset + 20:
        return None, None, None, 0, 0

    # Byte 0: Version (top 4 bits) + IHL (bottom 4 bits)
    # IHL = Internet Header Length in 32-bit words
    # Multiply by 4 to get bytes (e.g., IHL=5 means 20 bytes)
    version_ihl    = data[offset]
    version        = (version_ihl >> 4) & 0xF   # top 4 bits
    ihl            = (version_ihl & 0xF) * 4     # bottom 4 bits × 4

    if version != 4:
        return None, None, None, 0, 0  # not IPv4

    # Byte 8: TTL - each router decrements this by 1
    # When it reaches 0, the packet is dropped (prevents infinite loops)
    ttl = data[offset + 8]

    # Byte 9: Protocol number
    protocol = data[offset + 9]

    # Bytes 12-15: Source IP (4 bytes)
    src_ip = socket.inet_ntoa(data[offset + 12 : offset + 16])

    # Bytes 16-19: Destination IP (4 bytes)
    dst_ip = socket.inet_ntoa(data[offset + 16 : offset + 20])

    return src_ip, dst_ip, protocol, ttl, ihl


def protocol_name(proto):
    """Convert protocol number to name."""
    protocols = {
        1:  'ICMP',
        6:  'TCP',
        17: 'UDP',
    }
    return protocols.get(proto, f'OTHER({proto})')


# ── PCAP Reader ────────────────────────────────────────────────────────────
def read_pcap(filename):
    print(f"Opening file: {filename}")
    print("-" * 60)

    try:
        f = open(filename, 'rb')
    except FileNotFoundError:
        print(f"ERROR: File '{filename}' not found!")
        return

    global_header = f.read(24)
    magic = struct.unpack('<I', global_header[0:4])[0]
    if magic != 0xa1b2c3d4:
        print("ERROR: Not a valid PCAP file!")
        f.close()
        return

    print("PCAP file opened successfully!")
    print("-" * 60)

    packet_count = 0
    tcp_count    = 0
    udp_count    = 0
    icmp_count   = 0
    other_count  = 0

    # Track unique IP addresses and conversations
    src_ips      = set()
    dst_ips      = set()

    while True:
        pkt_header = f.read(16)
        if len(pkt_header) < 16:
            break

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_header)
        data = f.read(incl_len)
        packet_count += 1

        # Step 1: Parse Ethernet header
        dst_mac, src_mac, ether_type, eth_len = parse_ethernet(data)

        # Step 2: Only process IPv4 packets (EtherType 0x0800)
        if ether_type != 0x0800:
            continue

        # Step 3: Parse IP header (starts right after Ethernet = offset 14)
        src_ip, dst_ip, protocol, ttl, ip_hdr_len = parse_ipv4(data, eth_len)

        if src_ip is None:
            continue

        # Track IPs
        src_ips.add(src_ip)
        dst_ips.add(dst_ip)

        # Count protocols
        if protocol == 6:
            tcp_count += 1
        elif protocol == 17:
            udp_count += 1
        elif protocol == 1:
            icmp_count += 1
        else:
            other_count += 1

        # Print first 5 packets in detail
        if packet_count <= 5:
            print(f"Packet #{packet_count}:")
            print(f"  Source IP       : {src_ip}")
            print(f"  Destination IP  : {dst_ip}")
            print(f"  Protocol        : {protocol_name(protocol)}")
            print(f"  TTL             : {ttl}")
            print(f"  IP header size  : {ip_hdr_len} bytes")
            print()

    f.close()

    # Print summary
    all_ips = src_ips | dst_ips  # union of all IP addresses seen
    print("-" * 60)
    print("SUMMARY")
    print("-" * 60)
    print(f"Total packets     : {packet_count}")
    print(f"TCP packets       : {tcp_count}")
    print(f"UDP packets       : {udp_count}")
    print(f"ICMP packets      : {icmp_count}")
    print(f"Other packets     : {other_count}")
    print(f"Unique IPs seen   : {len(all_ips)}")
    print()
    print("IP Addresses found:")
    for ip in sorted(all_ips):
        print(f"  {ip}")
    print("-" * 60)
    print("Day 3 complete! We can now extract IP addresses from packets.")






# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    filename = sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"
    read_pcap(filename)



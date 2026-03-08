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

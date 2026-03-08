"""
Quick script to generate a sample.pcap for testing.

    python generate_sample.py
"""
import struct, socket, os

def write_pcap(path, packets):
    with open(path, 'wb') as f:
        # Global header
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for data in packets:
            f.write(struct.pack('<IIII', 1000, 0, len(data), len(data)))
            f.write(data)

def eth(src, dst, etype=0x0800):
    return bytes([int(x,16) for x in dst.split(':')]) + \
           bytes([int(x,16) for x in src.split(':')]) + \
           struct.pack('!H', etype)

def ip4(src, dst, proto=6):
    return struct.pack('!BBHHHBBH4s4s', 0x45,0,40,1,0,64,proto,0,
                       socket.inet_aton(src), socket.inet_aton(dst))

def tcp(sp, dp, flags=0x02):
    return struct.pack('!HHIIBBHHH', sp, dp, 0,0,0x50,flags,65535,0,0)

def udp(sp, dp):
    return struct.pack('!HHHH', sp, dp, 8, 0)

pkts = []
src = 'aa:bb:cc:dd:ee:01'
dst = 'aa:bb:cc:dd:ee:02'
for i in range(20):
    pkts.append(eth(src,dst) + ip4('192.168.1.10','8.8.8.8') + tcp(50000+i, 443))
for i in range(10):
    pkts.append(eth(src,dst) + ip4('192.168.1.10','8.8.4.4',17) + udp(50000+i,53))

write_pcap('sample.pcap', pkts)
print(f"Generated sample.pcap with {len(pkts)} packets")

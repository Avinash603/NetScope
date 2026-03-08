# 🔍 NetScope — Network Packet Analyzer

A Python project to analyze `.pcap` network capture files.
Built step by step to learn how networks actually work.

---

## Day 1 — Reading a PCAP File

- What a PCAP file is (a recording of network traffic)
- How to open and read binary files in Python
- What a "magic number" is and how to validate a file format
- How packets are stored in a PCAP file (global header + packet headers)


- Opens a `.pcap` file
- Reads the 24-byte global header
- Counts every packet in the file
- Shows total packets, total bytes, and timestamp of first packet

**How to run:**
```bash
python main.py sample.pcap
```

**Sample output:**
```
Opening file: sample.pcap
----------------------------------------
File format : PCAP (valid!)
Link type   : 1 (1 = Ethernet)
----------------------------------------
Total packets : 110
Total bytes   : 28311 bytes (27.7 KB)
First packet  : 2023-11-14 12:34:56
----------------------------------------
 We can now read a PCAP file.



## Project Goal

Build a full **Deep Packet Inspection (DPI) engine** in Python that:
- Reads network captures
- Identifies which apps are being used (YouTube, TikTok, etc.)
- Can block traffic based on rules
- Shows a web dashboard with charts




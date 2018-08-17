import pyshark
import sys
from manuf import manuf

cap = pyshark.FileCapture(sys.argv[1])
MACs = []
IPs = []
OUIs = []


def format_print():
    print('-----------------------------------------------------')
    print('| {:^17s} | {:^15s} | {:^11s} |'.format("MAC", "IP", "OUI"))
    print('-----------------------------------------------------')
    for i in range(0, len(MACs)):
        if str(OUIs[i]) != "None":
            print('| {:^17s} | {:^15s} | {:^11s} |'.format(str(MACs[i]), str(IPs[i]), str(OUIs[i])))
            print('-----------------------------------------------------')


def create_list():
    p = manuf.MacParser(update=True)
    for pkt in cap:
            for i in range(0, len(MACs)):
                if MACs[i] == pkt.eth.src:
                    try:
                        if IPs[i] == "" or IPs[i] == "0.0.0.0":
                            IPs[i] = pkt.ip.src
                    except AttributeError:
                        pass
                    break
            else:
                MACs.append(pkt.eth.src)
                try:
                    IPs.append(pkt.ip.src)
                except AttributeError:
                    IPs.append("")
                OUIs.append(p.get_manuf(pkt.eth.src))

            for i in range(0, len(MACs)):
                if MACs[i] == pkt.eth.dst:
                    try:
                        if IPs[i] == "" or IPs[i] == "0.0.0.0":
                            IPs[i] = pkt.ip.dst
                    except AttributeError:
                        pass
                    break
            else:
                MACs.append(pkt.eth.dst)
                try:
                    IPs.append(pkt.ip.dst)
                except AttributeError:
                    IPs.append("")
                OUIs.append(p.get_manuf(pkt.eth.dst))


def print_ip_address():
    for pkt in cap:
        try:
            print(pkt.ip.src)
        except AttributeError:
            pass


create_list()
format_print()
# print_ip_address()


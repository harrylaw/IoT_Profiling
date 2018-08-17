import pyshark
import sys
from manuf import manuf

cap = pyshark.FileCapture(sys.argv[1])
MACs = []
IPs = []
OUIs = []


def format_print():
    print('------------------------------------------------------------------')
    print('| {:^17s} | {:^11s} | {:^10s} |'.format("MAC", "IP", "OUI"))
    print('------------------------------------------------------------------')
    for i in range(0, len(MACs)):
        print('| {:^17s} | {:^11s} | {:^10s} |'.format(str(MACs[i]), str(IPs[i]), str(OUIs[i])))
        print('------------------------------------------------------------------')


def create_list():
    p = manuf.MacParser(update=True)
    for pkt in cap:
            for i in range(0, len(MACs)):
                if MACs[i] == pkt.eth.src:
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
                    break
            else:
                MACs.append(pkt.eth.dst)
                try:
                    IPs.append(pkt.ip.dst)
                except AttributeError:
                    IPs.append("")
                OUIs.append(p.get_manuf(pkt.eth.dst))


create_list()
format_print()


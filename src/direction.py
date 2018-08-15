import pyshark
import sys

cap = pyshark.FileCapture(sys.argv[1])
protocol = []
size = []
summary = []

for pkt in cap:
    try:
        for [src,dst] in summary:
            if src == pkt.ip.src and dst == pkt.ip.dst:
                index = summary.index([src,dst])
                size[index] = size[index] + int(pkt.length)
                break
        else:
            pair = [pkt.ip.src, pkt.ip.dst]
            summary.append(pair)
            size.append(int(pkt.length))
            

    except AttributeError as e:
            pass


print('-----------------------------------------------------------')
print('| {:^20s} | {:^20s} |'.format("Direction", "Size"))
print('-----------------------------------------------------------')

for i in range(0, len(summary)):
    print('| {:^10s} | {:^10s}|'.format(str(summary[i]), str(size[i])))
    print('-----------------------------------------------------------')

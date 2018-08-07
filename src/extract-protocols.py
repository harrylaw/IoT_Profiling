import pyshark
import sys

cap = pyshark.FileCapture(sys.argv[1], only_summaries=True)
type = []
number = []
length = []
summary = [type, number, length]

for pkt in cap:
    for protocol in type:
        if protocol == pkt.protocol:
            index = type.index(protocol)
            number[index] = number[index] + 1
            length[index] = length[index] + int(pkt.length)
            break
    else:
        type.append(pkt.protocol)
        number.append(1)
        length.append(int(pkt.length))

print('----------------------------------------')
print('| {:^10s} | {:^10s} | {:^10s} |'.format("Type", "Number", "Length"))
print('----------------------------------------')
for i in range(0, len(type)):
    print('| {:^10s} | {:^10s} | {:^10s} |'.format(str(type[i]), str(number[i]), str(length[i])))
    print('----------------------------------------')

import pyshark
import sys

cap = pyshark.FileCapture(sys.argv[1])
type1 = []
number = []
length = []
summary = [type1, number, length]

for pkt in cap:
    for protocol in type1:
        if protocol == pkt.highest_layer:
            index = type1.index(protocol)
            number[index] = number[index] + 1
            length[index] = length[index] + int(pkt.length)
            break
    else:
        try:
            print("Hostname:",pkt.bootp.option_hostname)
        except AttributeError as e:
            pass

        type1.append(pkt.highest_layer)
        number.append(1)
        length.append(int(pkt.length))

print('----------------------------------------')
print('| {:^10s} | {:^10s} | {:^10s}|'.format("Type", "Number", "Length"))
print('----------------------------------------')
for i in range(0, len(type1)):
    print('| {:^10s} | {:^10s} | {:^10s}|'.format(str(type1[i]), str(number[i]), str(length[i])))
    print('----------------------------------------')

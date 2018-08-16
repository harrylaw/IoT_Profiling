import pyshark
import sys
import ipaddress

cap = pyshark.FileCapture(sys.argv[1])
protocol = []
size = []
number = []
summary = []

for pkt in cap:
    try:
        for [src,dst] in summary:
            if src == pkt.ip.src and dst == pkt.ip.dst:
                index = summary.index([src,dst])
                size[index] = size[index] + int(pkt.length)
                number[index] = number[index] + 1
                break
        else:
            pair = [pkt.ip.src, pkt.ip.dst]
            summary.append(pair)
            size.append(int(pkt.length))
            number.append(1)
            protocol.append(pkt.highest_layer)

    except AttributeError as e:
            pass


print('-----------------------------------------------------------')
print('| {:^20s} | {:^20s} |{:^20s}'.format("Direction", "Size","Number"))
print('-----------------------------------------------------------')
local = 0
multicast = 0
cloud = 0
totaln = 0
for i in range(0, len(summary)):
	totaln = totaln + number[i]
	if ipaddress.ip_address(summary[i][0]).is_private and ipaddress.ip_address(summary[i][1]).is_private :
			local = local+number[i] 
	elif ipaddress.ip_address(summary[i][0]).is_multicast or ipaddress.ip_address(summary[i][1]).is_multicast:
			multicast = multicast +number[i]
	else:
		cloud = cloud +number[i]

for i in range(0, len(summary)):
    print('| {:^10s} | {:^10s}|{:^10s} |'.format(str(summary[i]), str(size[i]),str(number[i])))
    print('-----------------------------------------------------------')
print("Local:",local/totaln)
print("Multicast:",multicast/totaln)
print("Cloud:",cloud/totaln)

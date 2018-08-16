import pyshark
import sys
i=0
time = []
size = 0
cap = pyshark.FileCapture(sys.argv[1], only_summaries=True)
for pkt in cap:
	time.append(pkt.time)
	size = size + float(pkt.length)
	i = i+1

a=float(time[i-1])-float(time[0])
length = float(size) 
print(length/a)

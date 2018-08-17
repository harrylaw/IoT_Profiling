import pyshark
import sys
import ipaddress
cap = pyshark.FileCapture(sys.argv[1])
cap2 = pyshark.FileCapture(sys.argv[1], only_summaries=True)
def U_D_Rate(ip):
	uploadesize = 0
	downloadesize = 0
	for pkt in cap:
		try:
			if pkt.ip.src == ip:
				uploadesize = uploadesize + int(pkt.length)
			elif pkt.ip.dst == ip:
				downloadesize = downloadesize + int(pkt.length)
		except AttributeError as e:
				pass

	urate = uploadesize/(uploadesize+downloadesize)
	drate = downloadesize/(downloadesize+uploadesize)
	print ("Upload Rate:",urate)
	print("Download Rate:",drate)

def L_C_Rate():
	local = 0
	multicast = 0
	cloud = 0
	total = 0
	for pkt in cap:
		try:
			if ipaddress.ip_address(pkt.ip.src).is_private and ipaddress.ip_address(pkt.ip.dst).is_private:
				local = local + 1 
			elif ipaddress.ip_address(pkt.ip.src).is_multicast or ipaddress.ip_address(pkt.ip.dst).is_multicast:
				multicast = multicast + 1
			else:
				cloud = cloud + 1
		except AttributeError as e:
				pass
	total = local + multicast + cloud
	lr = local/total
	cr = cloud/total
	return lr,cr

def Rate():
	i = 0
	time = []
	size = 0
	for pkt in cap2:
		time.append(pkt.time)
		size = size + float(pkt.length)
		i = i+1
	totaltime = float(time[i-1])-float(time[0])
	rate = size/totaltime
	return rate 

def protocol_list():
	protocols = []
	for pkt in cap2:
		for i in range(0, len(protocols)):
			if protocols[i] == pkt.protocol:
				break
		else:
			protocols.append(pkt.protocol)
	return protocols

def If_encrypted(protocols):
	for protocol in protocols:
		if protocol == 'TLSv1.2' or protocol == 'TLSv1':
			return 1
	return 0
		
def If_lightweight(protocols):
	for protocol in protocols:
		if protocol == 'MQTT':
			return 1
	return 0		

def If_IoT(protocols):
	for protocol in protocols:
		if protocol == 'MDNS':
			return 1
	return 0

def If_UPnP(protocols):
	for protocol in protocols:
		if protocol == 'SSDP':
			return 1
	return 0

def If_timesync(protocols):
	for protocol in protocols:
		if protocol == 'NTP':
			return 1
	return 0

def If_unreliable(protocols):
	for protocol in protocols:
		if protocol == 'UDP':
			return 1
	return 0

def If_mainlylocal(list):
	if list[0]>0.3:
		return 1
	else:
		return 0

def If_moreglobal(list):
	if 0.1<list[0]<0.3:
		return 1
	else:
		return 0

def If_mainlyglobal(list):
	if list[0]<0.1:
		return 1
	else:
		return 0

def If_talkative(rate):
	if rate > 100:
		return 1
	else:
		return 0

def If_shy(rate):
	if rate < 100:
		return 1
	else:
		return 0

def Check_premuim():

	prate = 0.6*If_moreglobal(L_C_Rate()) + 0.3*If_encrypted(protocol_list()) + 0.1*If_talkative(Rate())
	return prate

def Check_Bulb():
	brate = 0.7*If_mainlyglobal(L_C_Rate()) + 0.2*If_shy(Rate()) + 0.1*If_IoT(protocol_list())
	return brate

def Check_strip():
	srate1 = 0.8*If_lightweight(protocol_list())+0.1*If_unreliable(protocol_list())+0.1*If_IoT(protocol_list())
	srate2 = 0.8*If_mainlylocal(L_C_Rate())+0.2*If_IoT(protocol_list())
	if srate1>srate2:
		return srate1
	else:
		return srate2

def Check_other():
	if Check_premuim()<0.5 and Check_Bulb()<0.5 and Check_strip()< 0.5:
		return 1		


if If_IoT(protocol_list()):
	print("IoT")
if If_unreliable(protocol_list()):
	print("Have unreliable conversation")
if If_lightweight(protocol_list()):
	print("Lightweight")
if If_UPnP(protocol_list()):
	print("Universal plug and play")
if If_encrypted(protocol_list()):
	print("Encrypted")
if If_timesync(protocol_list()):
	print("Time syncing")
if If_mainlylocal(L_C_Rate()):
	print("Talks mainly locally")
if If_moreglobal(L_C_Rate()):
	print("Talks globally and locally")
if If_mainlyglobal(L_C_Rate()):
	print("Talks mainly globally")
if If_talkative(Rate()):
	print("Talkative")
if If_shy(Rate()):
	print("Shy")

print("Voice Assistant Score:",Check_premuim())
print("Bulb Score:",Check_Bulb())
print("Strip Score",Check_strip())
if Check_other():
	print("Other devices")






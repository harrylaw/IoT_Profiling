from manuf import manuf
import ipaddress

MACs = []
IPs = []
Manufacturers = []


def print_list():
    print('{:^60s}'.format("Device List"))
    print('--------------------------------------------------------------')
    print('| {:^3s} | {:^17s} | {:^15s} | {:^14s} |'.format("No.", "MAC", "IP", "Manufacturer"))
    print('--------------------------------------------------------------')
    for i in range(0, len(MACs)):
        print('| {:^3s} | {:^17s} | {:^15s} | {:^14s} |'.format(str(i), str(MACs[i]), str(IPs[i]), str(Manufacturers[i])))
        print('--------------------------------------------------------------')


def ask_for_device():
    device_number = int(input("Please select the device you want to profile. (Enter device no.)"))
    print("You selected: " + Manufacturers[device_number])
    return device_number


def create_list(cap):
    mac_parser = manuf.MacParser(update=True)
    for pkt in cap:
            for i in range(0, len(MACs)):
                if MACs[i] == pkt.eth.src:
                    try:
                        if IPs[i] == "" and pkt.ip.src != "0.0.0.0" and ipaddress.ip_address(pkt.ip.src).is_private:
                            IPs[i] = pkt.ip.src
                    except AttributeError:
                        pass
                    break
            else:
                manufacturer = mac_parser.get_manuf(pkt.eth.src)
                if str(manufacturer) != "None":
                    MACs.append(pkt.eth.src)
                    Manufacturers.append(manufacturer)
                    try:
                        if pkt.ip.src != "0.0.0.0" and ipaddress.ip_address(pkt.ip.src).is_private:
                            IPs.append(pkt.ip.src)
                        else:
                            raise AttributeError
                    except AttributeError:
                        IPs.append("")

            for i in range(0, len(MACs)):
                if MACs[i] == pkt.eth.dst:
                    try:
                        if IPs[i] == "" and pkt.ip.dst != "0.0.0.0" and ipaddress.ip_address(pkt.ip.dst).is_private:
                            IPs[i] = pkt.ip.dst
                    except AttributeError:
                        pass
                    break
            else:
                manufacturer = mac_parser.get_manuf(pkt.eth.dst)
                if str(manufacturer) != "None":
                    MACs.append(pkt.eth.dst)
                    Manufacturers.append(manufacturer)
                    try:
                        if pkt.ip.dst != "0.0.0.0" and ipaddress.ip_address(pkt.ip.dst).is_private:
                            IPs.append(pkt.ip.dst)
                        else:
                            raise AttributeError
                    except AttributeError:
                        IPs.append("")


def filter_devices(cap):
    create_list(cap)
    print_list()
    index = ask_for_device()
    return IPs[index]



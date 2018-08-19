from manuf import manuf
import ipaddress

MACs = []
IPs = []
Manufacturers = []


def print_list():
    print()
    print('{:^60s}'.format("Device List"))
    print('--------------------------------------------------------------')
    print('| {:^3s} | {:^17s} | {:^15s} | {:^14s} |'.format("No.", "MAC", "IP", "Manufacturer"))
    print('--------------------------------------------------------------')
    for i in range(0, len(MACs)):
        print('| {:^3s} | {:^17s} | {:^15s} | {:^14s} |'.format(str(i), str(MACs[i]), str(IPs[i]), str(Manufacturers[i])))
        print('--------------------------------------------------------------')
    print()


def ask_for_device():
    device_number = int(input("Please select the device you want to profile. (Enter device no.) "))
    print("Now profiling: " + Manufacturers[device_number])
    return device_number


def create_list(cap):
    print("Please wait while we generate the device list.")
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


def filter_packets(device_number, cap, cap_sum):
    filtered_cap = []
    filtered_cap_sum = []
    packet_number = []

    # print("len(cap) = " + str(len(cap)))

    for pkt in cap:
        if MACs[device_number] == pkt.eth.src or MACs[device_number] == pkt.eth.dst:
            filtered_cap.append(pkt)
            packet_number.append(pkt.number)

    # print("str(len(packet_number)) = " + str(len(packet_number)))

    for pkt1 in cap_sum:
        if pkt1.no > packet_number[0]:
            packet_number.remove(packet_number[0])
        print("pkt1.no = " + str(pkt1.no) + " packet_number[0] = " + str(packet_number[0]))
        if pkt1.no == packet_number[0]:
            filtered_cap_sum.append(pkt1)
            packet_number.remove(packet_number[0])

    # print("len(filtered_cap) = " + str(len(filtered_cap)))
    # print("len(filtered_cap_sum) = " + str(len(filtered_cap_sum)))
    return filtered_cap, filtered_cap_sum


def filter_devices(cap, cap_sum):
    create_list(cap)
    print_list()
    device_number = ask_for_device()
    filtered_cap, filtered_cap_sum = filter_packets(device_number, cap, cap_sum)
    return filtered_cap, filtered_cap_sum


if __name__ == "__main__":
    import pyshark
    import sys

    cap = pyshark.FileCapture(sys.argv[1])  # should not use only_summaries
    cap_sum = pyshark.FileCapture(sys.argv[1], only_summaries=True)
    filtered_cap, filtered_cap_sum = filter_devices(cap, cap_sum)


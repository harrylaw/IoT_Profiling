from manuf import manuf
import ipaddress

MACs = []
IPs = []
Manufacturers = []


def print_list():
    print()
    print('{:^62s}'.format("Device List"))
    print('--------------------------------------------------------------')
    print('| {:^3s} | {:^17s} | {:^15s} | {:^14s} |'.format("No.", "MAC", "IP", "Manufacturer"))
    print('--------------------------------------------------------------')
    for i in range(0, len(MACs)):
        print('| {:^3s} | {:^17s} | {:^15s} | {:^14s} |'.format(str(i), str(MACs[i]), str(IPs[i]), str(Manufacturers[i])))
        print('--------------------------------------------------------------')
    print()


def ask_for_device():
    while True:
        try:
            device_number = int(input("Please select the device you want to profile. (Enter device no.) "))
            if device_number < 0 or device_number > len(Manufacturers) - 1:
                raise ValueError
            print("You selected: " + Manufacturers[device_number])
            return device_number
        except ValueError:
            print("Invalid input! Please try again.")


def create_list(cap):
    rows_to_remove = []
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

    for i in range(0, len(IPs)):
        if IPs[i] == "":
            rows_to_remove.append(i)
    for row_number in rows_to_remove:
        MACs.remove(MACs[row_number])
        IPs.remove(IPs[row_number])
        Manufacturers.remove(Manufacturers[row_number])


def filter_packets(device_number, cap, cap_sum):
    filtered_cap = []
    filtered_cap_sum = []
    packet_numbers = []

    print("Now filtering packets", end="", flush=True)

    for pkt in cap:
        if MACs[device_number] == pkt.eth.src or MACs[device_number] == pkt.eth.dst:
            filtered_cap.append(pkt)
            packet_numbers.append(pkt.number)

    for pkt in cap_sum:
        if int(pkt.no) < int(packet_numbers[0]):
            continue

        while int(pkt.no) > int(packet_numbers[0]):
            packet_numbers.remove(packet_numbers[0])
            if not packet_numbers:
                break
        if not packet_numbers:
            break

        if pkt.no == packet_numbers[0]:
            filtered_cap_sum.append(pkt)
            packet_numbers.remove(packet_numbers[0])
        if not packet_numbers:
            break

    print("...Done")
    print()
    print("Now profiling: " + Manufacturers[device_number])
    return filtered_cap, filtered_cap_sum


def filter_devices(cap, cap_sum):
    create_list(cap)
    print_list()
    device_number = ask_for_device()
    filtered_cap, filtered_cap_sum = filter_packets(device_number, cap, cap_sum)
    return IPs[device_number], filtered_cap, filtered_cap_sum


def get_ip(device_number):
    return IPs[device_number]


def get_mac(device_number):
    return MACs[device_number]


if __name__ == "__main__":
    import pyshark
    import sys

    cap = pyshark.FileCapture(sys.argv[1])  # should not use only_summaries
    cap_sum = pyshark.FileCapture(sys.argv[1], only_summaries=True)
    ip, filtered_cap, filtered_cap_sum = filter_devices(cap, cap_sum)
    # for pkt in filtered_cap:
    #     print("1 " + str(pkt.number))
    #
    # for pkt in filtered_cap_sum:
    #     print("2 " + str(pkt.no))

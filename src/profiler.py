import pyshark
import sys
import ipaddress
from filter import Filter


class Result:
    def __init__(self, tag, comment):
        self.tag = tag
        self.comment = comment


class Possibility:
    def __init__(self, device_type, number):
        self.device_type = device_type
        self.number = number


def calculate_heartbeat(cap_sum):  # use cap_sum
    time_differences = []
    for i in range(1, len(cap_sum)):
        time_differences.append(float(cap_sum[i].time) - float(cap_sum[i-1].time))
    heartbeat = sum(time_differences) / (len(cap_sum) - 1)
    return heartbeat


def calculate_upload_minus_download_rate(ip, cap):  # use cap
    upload_size = 0
    download_size = 0
    for pkt in cap:
        try:
            if ipaddress.ip_address(pkt.ip.src).is_multicast or ipaddress.ip_address(pkt.ip.dst).is_multicast:
                continue
            elif pkt.ip.src == '255.255.255.255' or pkt.ip.dst == '255.255.255.255':
                continue

            elif pkt.ip.src == ip:
                upload_size = upload_size + int(pkt.length)
            elif pkt.ip.dst == ip:
                download_size = download_size + int(pkt.length)
        except AttributeError:
                pass

    upload_rate = upload_size / (upload_size + download_size)
    download_rate = download_size / (download_size + upload_size)
    return upload_rate - download_rate


def calculate_local_and_global_packets_rate(cap):  # use cap
    local_packets = 0
    multicast_packets = 0
    global_packets = 0
    for pkt in cap:
        try:
            if ipaddress.ip_address(pkt.ip.src).is_private and ipaddress.ip_address(pkt.ip.dst).is_private:
                local_packets = local_packets + 1
            elif ipaddress.ip_address(pkt.ip.src).is_multicast or ipaddress.ip_address(pkt.ip.dst).is_multicast:
                multicast_packets = multicast_packets + 1
            else:
                global_packets = global_packets + 1
        except AttributeError:
                pass
    total_packets = local_packets + multicast_packets + global_packets
    local_packets_rate = local_packets / total_packets
    global_packets_rate = global_packets / total_packets
    return local_packets_rate, global_packets_rate


def calculate_rate(cap_sum):  # use cap_sum
    time = []
    size = 0
    for pkt in cap_sum:
        time.append(pkt.time)
        size = size + float(pkt.length)
    total_time = float(time[-1]) - float(time[0])
    rate = size / total_time
    return rate


def generate_protocol_list(cap_sum):  # use cap_sum
    protocols = []
    for pkt in cap_sum:
        for protocol in protocols:
            if protocol == pkt.protocol:
                break
        else:
            protocols.append(pkt.protocol)
    return protocols


def has_public_ip(mac, cap):
    for pkt in cap:
        try:
            if (pkt.eth.src == mac and ipaddress.ip_address(pkt.ip.src).is_global) or (
                    pkt.eth.dst == mac and ipaddress.ip_address(pkt.ip.dst).is_global):
                return 1
        except AttributeError as e:
            pass
    else:
        return 0


def is_encrypted(protocols):
    for protocol in protocols:
        if protocol == 'TLSv1.2' or protocol == 'TLSv1':
            return 1
    return 0


def is_lightweight(protocols):
    for protocol in protocols:
        if protocol == 'MQTT':
            return 1
    return 0


def is_iot(protocols):
    for protocol in protocols:
        if protocol == 'MDNS':
            return 1
    return 0


def is_upnp(protocols):
    for protocol in protocols:
        if protocol == 'SSDP':
            return 1
    return 0


def is_time_synchronizer(protocols):
    for protocol in protocols:
        if protocol == 'NTP':
            return 1
    return 0


def is_unreliable(protocols):
    for protocol in protocols:
        if protocol == 'UDP':
            return 1
    return 0


def is_mainly_local(local_packets_rate):
    if local_packets_rate >= 0.3:
        return 1
    else:
        return 0


def is_neither_local_nor_global(local_packets_rate, global_packets_rate):
    if local_packets_rate < 0.3 and global_packets_rate < 0.3:
        return 1
    else:
        return 0


def is_mainly_global(global_packets_rate):
    if global_packets_rate >= 0.3:
        return 1
    else:
        return 0


def is_talkative(rate, heartbeat):
    if rate > 500 and heartbeat < 1:
        return 1
    else:
        return 0


def is_neither_talkative_nor_shy(rate, heartbeat):
    if 90 <= rate <= 500 or 1 <= heartbeat <= 3:
        return 1
    else:
        return 0


def is_shy(rate, heartbeat):
    if rate < 90 and heartbeat > 3:
        return 1
    else:
        return 0


def is_uploader(dif):
    if dif > 0 and abs(dif) > 0.45:
        return 1
    else:
        return 0


def is_downloader(dif):
    if dif < 0 and abs(dif) > 0.45:
        return 1
    else:
        return 0


def check_premium(local_packets_rate, global_packets_rate, protocol_list, rate, heartbeat):
    p_rate = 0.6 * is_neither_local_nor_global(local_packets_rate, global_packets_rate) + 0.1 * is_encrypted(protocol_list) + 0.3 * is_talkative(rate, heartbeat)
    return p_rate


def check_bulb(global_packets_rate, protocol_list):
    b_rate = 0.7 * is_mainly_global(global_packets_rate) + 0.3 * is_iot(protocol_list)
    return b_rate


def check_strip(protocol_list, local_packets_rate):
    s_rate1 = 0.8 * is_lightweight(protocol_list) + 0.1 * is_unreliable(protocol_list) + 0.1 * is_iot(protocol_list)
    s_rate2 = 0.8 * is_mainly_local(local_packets_rate) + 0.2 * is_iot(protocol_list)
    if s_rate1 > s_rate2:
        return s_rate1
    else:
        return s_rate2


def check_uploader(upload_minus_download_rate, rate, heartbeat):
    u_rate = 0.6 * is_uploader(upload_minus_download_rate) + 0.4 * is_talkative(rate, heartbeat)
    return u_rate


def check_router(mac, cap):
    return has_public_ip(mac, cap)


def continue_or_exit():
    while True:
        try:
            print()
            choice = input("Do you want to profile another device in the same .pcap file? (y/n) ")
            if choice == 'y':
                return
            elif choice == 'n':
                print("Goodbye!")
                exit()
            else:
                raise ValueError
        except ValueError:
            print("Invalid input! Please try again.")


def add_tags(manufacturer):
    print("Now profiling: " + manufacturer, end='', flush=True)
    if has_public_ip(mac, cap):
        results.append(Result("Has public IP", "Has public IP associated with MAC"))
    if is_uploader(upload_minus_download_rate):
        results.append(Result("Uploader", "Upload Rate - Download Rate = {:.2f}%".format(upload_minus_download_rate * 100)))
    if is_downloader(upload_minus_download_rate):
        results.append(Result("Downloader", "Upload Rate - Download Rate = {:.2f}%".format(upload_minus_download_rate * 100)))
    if is_iot(protocol_list):
        results.append(Result("IoT", "Using MDNS Protocol"))
    if is_unreliable(protocol_list):
        results.append(Result("Has unreliable traffic", "Using UDP Protocol"))
    if is_lightweight(protocol_list):
        results.append(Result("Lightweight", "Using MQTT Protocol"))
    if is_upnp(protocol_list):
        results.append(Result("Universal Plug and Play", "Using SSDP Protocol"))
    if is_encrypted(protocol_list):
        results.append(Result("Encrypted", "Using TLSv1 or TLSv1.2 Protocol"))
    if is_time_synchronizer(protocol_list):
        results.append(Result("Time synchronizer", "Using NTP Protocol"))
    if is_mainly_local(local_rate):
        results.append(Result("Talks mainly locally", "Local Packet Ratio = {:.2f}%".format(local_rate * 100)))
    if is_neither_local_nor_global(local_rate, global_rate):
        results.append(Result("Talks globally and locally", "Local Packet Ratio = {:.2f}%, Global Packet Ratio = {:.2f}%".format(local_rate * 100, global_rate * 100)))
    if is_mainly_global(global_rate):
        results.append(Result("Talks mainly globally", "Global Packet Ratio = {:.2f}%".format(global_rate * 100)))
    if is_talkative(rate, heartbeat):
        results.append(Result("Talkative", "Size / Time = {:.2f}B, Heartbeat = {:.2f}s".format(rate, heartbeat)))
    if is_neither_talkative_nor_shy(rate, heartbeat):
        results.append(Result("Neither talkative nor shy", "Size / Time = {:.2f}B, Heartbeat = {:.2f}s".format(rate, heartbeat)))
    if is_shy(rate, heartbeat):
        results.append(Result("Shy", "Size / Time = {:.2f}B, Heartbeat = {:.2f}s".format(rate, heartbeat)))
    print("...Done")


def print_tags():
    print()
    print('{:^72s}'.format("Profiling Result"))
    print('------------------------------------------------------------------------')
    print('| {:^25s} | {:^40s} |'.format("Tag", "Comment"))
    print('------------------------------------------------------------------------')
    for result in results:
        print('| {:^25s} | {:^40s} |'.format(result.tag, result.comment))
        print('------------------------------------------------------------------------')
    print()


def calculate_possibilities():
    possibilities.append(Possibility("Router", "{:.2f}%".format(check_router(mac, cap) * 100)))
    possibilities.append(Possibility("Voice Assistant", "{:.2f}%".format(check_premium(local_rate, global_rate, protocol_list, rate, heartbeat) * 100)))
    possibilities.append(Possibility("Bulb", "{:.2f}%".format(check_bulb(global_rate, protocol_list) * 100)))
    possibilities.append(Possibility("Strip", "{:.2f}%".format(check_strip(protocol_list, local_rate) * 100)))
    possibilities.append(Possibility("Camera", "{:.2f}%".format(check_uploader(upload_minus_download_rate, rate, heartbeat) * 100)))


def print_possibilities():
    print("Based on the above result, possible type of the device is inferred as follows.")
    print()
    print('{:^29s}'.format("Possible Type"))
    print('-----------------------------')
    print('| {:^15s} | {:^7s} |'.format("Device Type", "Number"))
    print('-----------------------------')
    for possibility in possibilities:
        print('| {:^15s} | {:^7s} |'.format(possibility.device_type, possibility.number))
        print('-----------------------------')


if __name__ == "__main__":
    unfiltered_cap = pyshark.FileCapture(sys.argv[1])
    unfiltered_cap_sum = pyshark.FileCapture(sys.argv[1], only_summaries=True)
    pkt_filter = Filter(unfiltered_cap, unfiltered_cap_sum)

    pkt_filter.create_device_list()
    while True:
        results = []
        possibilities = []
        pkt_filter.print_device_list()
        pkt_filter.ask_for_device()
        cap, cap_sum = pkt_filter.filter_packets()
        ip = pkt_filter.get_profile_device_ip()
        mac = pkt_filter.get_profile_device_mac()
        manufacturer = pkt_filter.get_profile_device_manufacturer()

        upload_minus_download_rate = calculate_upload_minus_download_rate(ip, cap)
        protocol_list = generate_protocol_list(cap_sum)
        local_rate, global_rate = calculate_local_and_global_packets_rate(cap)
        rate = calculate_rate(cap_sum)
        heartbeat = calculate_heartbeat(cap_sum)

        add_tags(manufacturer)
        print_tags()

        calculate_possibilities()
        print_possibilities()

        continue_or_exit()

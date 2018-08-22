import pyshark
import sys
import ipaddress
from filter import Filter


class Result:
    def __init__(self, tag, comment):
        self.tag = tag
        self.comment = comment


def calculate_u_d_rate(ip, cap):  # use cap
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

    u_rate = upload_size / (upload_size + download_size)
    d_rate = download_size / (download_size + upload_size)
    return u_rate - d_rate


def calculate_l_c_rate(cap):  # use cap
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
        except AttributeError:
                pass
    total = local + multicast + cloud
    l_rate = local / total
    c_rate = cloud / total
    return l_rate, c_rate


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
        for i in range(0, len(protocols)):
            if protocols[i] == pkt.protocol:
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


def is_timesync(protocols):
    for protocol in protocols:
        if protocol == 'NTP':
            return 1
    return 0


def is_unreliable(protocols):
    for protocol in protocols:
        if protocol == 'UDP':
            return 1
    return 0


def is_mainly_local(list):
    if list[0] > 0.3:
        return 1
    else:
        return 0


def is_more_global(list):
    if 0.1 < list[0] < 0.3:
        return 1
    else:
        return 0


def is_mainly_global(list):
    if list[0] < 0.1:
        return 1
    else:
        return 0


def is_talkative(rate):
    if rate > 100:
        return 1
    else:
        return 0


def is_shy(rate):
    if rate < 100:
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


def check_premium(l_c_rate, protocol_list, rate):
    p_rate = 0.6 * is_more_global(l_c_rate) + 0.1 * is_encrypted(protocol_list) + 0.3 * is_talkative(rate)
    return p_rate


def check_bulb(l_c_rate, rate, protocol_list):
    b_rate = 0.7 * is_mainly_global(l_c_rate)  + 0.3 * is_iot(protocol_list)
    return b_rate


def check_strip(protocol_list, l_c_rate):
    s_rate1 = 0.8 * is_lightweight(protocol_list) + 0.1 * is_unreliable(protocol_list) + 0.1 * is_iot(protocol_list)
    s_rate2 = 0.8 * is_mainly_local(l_c_rate) + 0.2 * is_iot(protocol_list)
    if s_rate1 > s_rate2:
        return s_rate1
    else:
        return s_rate2


def check_uploader(u_d_rate,rate, protocol_list):
    u_rate = 0.6 * is_uploader(u_d_rate) + 0.4 * is_talkative(rate) 
    return u_rate


def check_other(l_c_rate,protocol_list, rate, u_d_rate):
    if check_premium(l_c_rate,protocol_list,rate) < 0.7 and check_bulb(l_c_rate,rate,protocol_list) < 0.7 and check_strip(protocol_list,l_c_rate) < 0.7 and check_uploader() < 0.7:
        return 1


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


def add_tags():
    if has_public_ip(mac, cap):
        result = Result("Has public IP", "Has public IP associated with MAC")
        results.append(result)
    if is_uploader(u_d_rate):
        result = Result("Uploader", "Upload Rate - Download Rate = {:.2f}".format(u_d_rate))
        results.append(result)
    if is_downloader(u_d_rate):
        result = Result("Downloader", "Difference between upload and download rate: {:.2f}".format(u_d_rate))
        results.append(result)
    if is_iot(protocol_list):
        result = Result("IoT", "Using MDNS Protocol")
        results.append(result)
    if is_unreliable(protocol_list):
        result = Result("Has unreliable traffic", "Using UDP Protocol")
        results.append(result)
    if is_lightweight(protocol_list):
        result = Result("Lightweight", "Using MQTT Protocol")
        results.append(result)
    if is_upnp(protocol_list):
        result = Result("Universal Plug and Play", "Using SSDP Protocol")
        results.append(result)
    if is_encrypted(protocol_list):
        result = Result("Encrypted", "Using TLSv1 or TLSv1.2 Protocol")
        results.append(result)
    if is_timesync(protocol_list):
        result = Result("Time synchronizer", "Using NTP Protocol")
        results.append(result)
    if is_mainly_local(l_c_rate):
        result = Result("Talks mainly locally", "Local Packets / All Packets = {:.2f}".format(l_c_rate[0]))
        results.append(result)
    if is_more_global(l_c_rate):
        result = Result("Talks globally and locally", "Local Packets / All Packets = {:.2f}".format(l_c_rate[0]))
        results.append(result)
    if is_mainly_global(l_c_rate):
        result = Result("Talks mainly globally", "Global Packets / All Packets = {:.2f}".format(l_c_rate[1]))
        results.append(result)
    if is_talkative(rate):
        result = Result("Talkative", "Packets Size/Total Time: {:.2f}".format(rate))
        results.append(result)
    if is_shy(rate):
        result = Result("Shy", "Cumulative Packets Size/Total Time: {:.2f}".format(rate))
        results.append(result)


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


if __name__ == "__main__":
    unfiltered_cap = pyshark.FileCapture(sys.argv[1])
    unfiltered_cap_sum = pyshark.FileCapture(sys.argv[1], only_summaries=True)
    pkt_filter = Filter(unfiltered_cap, unfiltered_cap_sum)
    results = []

    pkt_filter.create_device_list()
    while True:
        pkt_filter.print_device_list()
        pkt_filter.ask_for_device()
        cap, cap_sum = pkt_filter.filter_packets()
        ip = pkt_filter.get_profile_device_ip()
        mac = pkt_filter.get_profile_device_mac()

        u_d_rate = calculate_u_d_rate(ip, cap)
        protocol_list = generate_protocol_list(cap_sum)
        l_c_rate = calculate_l_c_rate(cap)
        rate = calculate_rate(cap_sum)

        add_tags()
        print_tags()

        print()
        print("Router Score: {:.2f}%".format(check_router(mac, cap) * 100))
        print("Voice Assistant Score: {:.2f}%".format(check_premium(l_c_rate,protocol_list,rate) * 100))
        print("Bulb Score: {:.2f}%".format(check_bulb(l_c_rate,rate,protocol_list) * 100))
        print("Strip Score {:.2f}%".format(check_strip(protocol_list,l_c_rate) * 100))
        print("Camera Score: {:.2f}%".format(check_uploader(u_d_rate,rate,protocol_list) * 100))
        if check_other(l_c_rate,protocol_list,rate,u_d_rate):
            print("Other devices")

        continue_or_exit()

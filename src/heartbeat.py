import pyshark
import sys
from filter import create_device_list, print_device_list, ask_for_device, filter_packets


def calculate_heartbeat(cap_sum):  # use cap_sum
    time_differences = []
    for i in range(1, len(cap_sum)):
        time_differences.append(float(cap_sum[i].time) - float(cap_sum[i-1].time))
    heartbeat = sum(time_differences) / (len(cap_sum) - 1)
    return heartbeat


if __name__ == "__main__":
    unfiltered_cap = pyshark.FileCapture(sys.argv[1])
    unfiltered_cap_sum = pyshark.FileCapture(sys.argv[1], only_summaries=True)
    create_device_list(unfiltered_cap)
    print_device_list()
    device_number = ask_for_device()
    cap, cap_sum = filter_packets(device_number, unfiltered_cap, unfiltered_cap_sum)
    print("heartbeat = {:.4f}".format(calculate_heartbeat(cap_sum)))

protocols = []
numbers = []
lengths = []
average_lengths = []
percentages = []


def partition(arr_to_sort, arr1, arr2, low, high):
    i = (low - 1)  # index of smaller element
    pivot = arr_to_sort[high]  # pivot

    for j in range(low, high):

        # If current element is smaller than or
        # equal to pivot
        if arr_to_sort[j] <= pivot:
            # increment index of smaller element
            i = i + 1
            arr_to_sort[i], arr_to_sort[j] = arr_to_sort[j], arr_to_sort[i]
            arr1[i], arr1[j] = arr1[j], arr1[i]
            arr2[i], arr2[j] = arr2[j], arr2[i]

    arr_to_sort[i + 1], arr_to_sort[high] = arr_to_sort[high], arr_to_sort[i + 1]
    arr1[i + 1], arr1[high] = arr1[high], arr1[i + 1]
    arr2[i + 1], arr2[high] = arr2[high], arr2[i + 1]

    return i + 1


# Function to do Quick sort
def quick_sort(arr_to_sort, arr1, arr2, low, high):
    if low < high:
        # pi is partitioning index, arr_to_sort[p] is now
        # at right place
        pi = partition(arr_to_sort, arr1, arr2, low, high)

        # Separately sort elements before
        # partition and after partition
        quick_sort(arr_to_sort, arr1, arr2, low, pi - 1)
        quick_sort(arr_to_sort, arr1, arr2, pi + 1, high)


def calculate_average_length():
    for i in range(0, len(lengths)):
        average_lengths.append('{:.2f}'.format(lengths[i]/numbers[i]))


def format_print():
    total_number = 0
    total_length = 0
    print("...Done")
    print()
    print("{:^66s}".format("Protocol List"))
    print('------------------------------------------------------------------')
    print('| {:^10s} | {:^10s} | {:^10s} | {:^10s} | {:^10s} |'.format("Protocol", "Number", "Length", "Avg Length",
                                                                       "Percentage"))
    print('------------------------------------------------------------------')
    for i in range(0, len(protocols)):
        print('| {:^10s} | {:^10s} | {:^10s} | {:^10s} | {:^10s} |'.format(str(protocols[i]), str(numbers[i]), str(lengths[i]), str(average_lengths[i]), str(percentages[i])))
        print('------------------------------------------------------------------')
        total_number = total_number + numbers[i]
        total_length = total_length + lengths[i]
    print('Overall Average Packet Length: ' + '{:.2f}B'.format(total_length/total_number))


def create_list(cap, manufacturer):
    print("Extracting protocols for: " + manufacturer, end='', flush=True)
    for pkt in cap:
        for i in range(0, len(protocols)):
            if protocols[i] == pkt.protocol:
                numbers[i] = numbers[i] + 1
                lengths[i] = lengths[i] + int(pkt.length)
                break
        else:
            protocols.append(pkt.protocol)
            numbers.append(1)
            lengths.append(int(pkt.length))


def calculate_percentage():
    total_number = 0
    for i in range(0, len(numbers)):
        total_number = total_number + numbers[i]
    for i in range(0, len(protocols)):
        percentages.append("{:.2f}%".format(numbers[i]/total_number * 100))


def extract_protocols(cap, manufacturer):
    create_list(cap, manufacturer)
    quick_sort(protocols, numbers, lengths, 0, len(protocols) - 1)
    calculate_average_length()
    calculate_percentage()
    format_print()


def continue_or_exit():
    while True:
        try:
            print()
            choice = input("Do you want to profile another device in the same .pcap file? (y/n) ")
            if choice == 'y' or choice == 'Y':
                return
            elif choice == 'n' or choice == 'N':
                print("Thanks for using. Goodbye!")
                exit()
            else:
                raise ValueError
        except ValueError:
            print("Invalid input! Please try again.")


if __name__ == "__main__":
    import pyshark
    import sys
    from filter import Filter

    unfiltered_cap_sum = pyshark.FileCapture(sys.argv[1], only_summaries=True)  # should use only_summaries
    unfiltered_cap = pyshark.FileCapture(sys.argv[1])
    pkt_filter = Filter(unfiltered_cap, unfiltered_cap_sum)

    pkt_filter.create_device_list()
    while True:
        pkt_filter.print_device_list()
        pkt_filter.ask_for_device()
        cap, cap_sum = pkt_filter.filter_packets()
        ip = pkt_filter.get_profile_device_ip()
        mac = pkt_filter.get_profile_device_mac()
        manufacturer = pkt_filter.get_profile_device_manufacturer()
        extract_protocols(cap_sum, manufacturer)

        continue_or_exit()

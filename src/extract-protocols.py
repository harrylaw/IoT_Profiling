import pyshark
import sys

cap = pyshark.FileCapture(sys.argv[1], only_summaries=True)
protocols = []
numbers = []
lengths = []
average_lengths = []


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
        average_lengths.append('%.2f' % (lengths[i]/numbers[i]))


def format_print():
    total_number = 0
    total_length = 0
    print('-----------------------------------------------------')
    print('| {:^10s} | {:^10s} | {:^10s} | {:^10s} |'.format("Protocol", "Number", "Length", "Avg Length"))
    print('-----------------------------------------------------')
    for i in range(0, len(protocols)):
        print('| {:^10s} | {:^10s} | {:^10s} | {:^10s} |'.format(str(protocols[i]), str(numbers[i]), str(lengths[i]),
                                                                 str(average_lengths[i])))
        print('-----------------------------------------------------')
        total_number = total_number + numbers[i]
        total_length = total_length + lengths[i]
    print('Overall Average Length: ', '%.2f' % (total_length/total_number))


for pkt in cap:
    for protocol in protocols:
        if protocol == pkt.protocol:
            index = protocols.index(protocol)
            numbers[index] = numbers[index] + 1
            lengths[index] = lengths[index] + int(pkt.length)
            break
    else:
        protocols.append(pkt.protocol)
        numbers.append(1)
        lengths.append(int(pkt.length))
quick_sort(protocols, numbers, lengths, 0, len(protocols) - 1)
calculate_average_length()
format_print()

import pyshark
import sys

cap = pyshark.FileCapture(sys.argv[1])
size = []
summary = []


def partition(arr_to_sort, arr1, low, high):
    i = (low - 1)  # index of smaller element
    pivot = arr_to_sort[high]  # pivot

    for j in range(low, high):

        # If current element is larger than or
        # equal to pivot
        if arr_to_sort[j] >= pivot:
            # increment index of larger element
            i = i + 1
            arr_to_sort[i], arr_to_sort[j] = arr_to_sort[j], arr_to_sort[i]
            arr1[i], arr1[j] = arr1[j], arr1[i]

    arr_to_sort[i + 1], arr_to_sort[high] = arr_to_sort[high], arr_to_sort[i + 1]
    arr1[i + 1], arr1[high] = arr1[high], arr1[i + 1]

    return i + 1


# Function to do Quick sort
def quick_sort(arr_to_sort, arr1, low, high):
    if low < high:
        # pi is partitioning index, arr_to_sort[p] is now
        # at right place
        pi = partition(arr_to_sort, arr1, low, high)

        # Separately sort elements before
        # partition and after partition
        quick_sort(arr_to_sort, arr1, low, pi - 1)
        quick_sort(arr_to_sort, arr1, pi + 1, high)


def format_print():
    print('-----------------------------------------------------------')
    print('| {:^20s} | {:^20s} |'.format("Direction", "Size"))
    print('-----------------------------------------------------------')

    for i in range(0, len(summary)):
        print('| {:^10s} | {:^10s}|'.format(str(summary[i]), str(size[i])))
        print('-----------------------------------------------------------')


for pkt in cap:
    try:
        for [src, dst] in summary:
            if src == pkt.ip.src and dst == pkt.ip.dst:
                index = summary.index([src, dst])
                size[index] = size[index] + int(pkt.length)
                break
        else:
            pair = [pkt.ip.src, pkt.ip.dst]
            summary.append(pair)
            size.append(int(pkt.length))

    except AttributeError as e:
            pass

quick_sort(size, summary, 0, len(size)-1)
format_print()
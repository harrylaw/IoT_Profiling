from manuf import manuf
import ipaddress


class Device:
    MAC = ""
    IP = ""
    Manufacturer = ""


class Filter:
    __profile_device = Device()
    __device_list = []

    def __init__(self, cap, cap_sum):
        self.cap = cap
        self.cap_sum = cap_sum

    def print_device_list(self):
        print()
        print('{:^62s}'.format("Device List"))
        print('--------------------------------------------------------------')
        print('| {:^3s} | {:^17s} | {:^15s} | {:^14s} |'.format("No.", "MAC", "IP", "Manufacturer"))
        print('--------------------------------------------------------------')
        for i in range(0, len(self.__device_list)):
            print('| {:^3s} | {:^17s} | {:^15s} | {:^14s} |'.format(str(i), str(self.__device_list[i].MAC), str(self.__device_list[i].IP),
                                                                    str(self.__device_list[i].Manufacturer)))
            print('--------------------------------------------------------------')
        print()

    def ask_for_device(self):
        while True:
            try:
                device_number = int(input("Please select the device you want to profile. (Enter device no.) "))
                if device_number < 0 or device_number > len(self.__device_list) - 1:
                    raise ValueError
                self.__profile_device = self.__device_list[device_number]
                print("You selected: " + self.__profile_device.Manufacturer)
                return
            except ValueError:
                print("Invalid input! Please try again.")

    def create_device_list(self):
        device_list_unfiltered = []
        print("Please wait while we generate the device list.")
        mac_parser = manuf.MacParser(update=True)

        for pkt in self.cap:
                for device in device_list_unfiltered:
                    if device.MAC == pkt.eth.src:
                        try:
                            if device.IP == "" and pkt.ip.src != "0.0.0.0" and ipaddress.ip_address(pkt.ip.src).is_private:
                                device.IP = pkt.ip.src
                        except AttributeError:
                            pass
                        break
                else:
                    manufacturer = str(mac_parser.get_manuf(pkt.eth.src))
                    if manufacturer != "None":
                        new_device = Device()
                        new_device.MAC = pkt.eth.src
                        new_device.Manufacturer = manufacturer
                        try:
                            if pkt.ip.src != "0.0.0.0" and ipaddress.ip_address(pkt.ip.src).is_private:
                                new_device.IP = pkt.ip.src
                            else:
                                raise AttributeError
                        except AttributeError:
                            new_device.IP = ""
                        device_list_unfiltered.append(new_device)

                for device in device_list_unfiltered:
                    if device.MAC == pkt.eth.dst:
                        try:
                            if device.IP == "" and pkt.ip.dst != "0.0.0.0" and ipaddress.ip_address(pkt.ip.dst).is_private:
                                device.IP = pkt.ip.dst
                        except AttributeError:
                            pass
                        break
                else:
                    manufacturer = str(mac_parser.get_manuf(pkt.eth.dst))
                    if manufacturer != "None":
                        new_device = Device()
                        new_device.MAC = pkt.eth.dst
                        new_device.Manufacturer = manufacturer
                        try:
                            if pkt.ip.dst != "0.0.0.0" and ipaddress.ip_address(pkt.ip.dst).is_private:
                                new_device.IP = pkt.ip.dst
                            else:
                                raise AttributeError
                        except AttributeError:
                            new_device.IP = ""
                        device_list_unfiltered.append(new_device)

        for device in device_list_unfiltered:
            if device.IP != "":
                self.__device_list.append(device)

    def filter_packets(self):
        filtered_cap = []
        filtered_cap_sum = []
        packet_numbers = []

        print("Now filtering packets", end="", flush=True)

        for pkt in self.cap:
            if self.__profile_device.MAC == pkt.eth.src or self.__profile_device.MAC == pkt.eth.dst:
                filtered_cap.append(pkt)
                packet_numbers.append(pkt.number)

        for pkt in self.cap_sum:
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
        print("Now profiling: " + self.__profile_device.Manufacturer)
        return filtered_cap, filtered_cap_sum

    def get_profile_device_ip(self):
        return self.__profile_device.IP

    def get_profile_device_mac(self):
        return self.__profile_device.MAC


if __name__ == "__main__":
    import pyshark
    import sys

    unfiltered_cap = pyshark.FileCapture(sys.argv[1])  # should not use only_summaries
    unfiltered_cap_sum = pyshark.FileCapture(sys.argv[1], only_summaries=True)
    pkt_filter = Filter(unfiltered_cap, unfiltered_cap_sum)

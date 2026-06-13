import pyshark
#main and useful library for capturing net packets
#project will be developed in classes

class Capture:
    def __init__(self, pcap_path): #define a class in which function will be passed the pcap file path
        self.pcap_path = pcap_path

    def pcap_process(self, pack_l = 10): #function that opens the pcap and read the first 10 packets, for test purpose
        print(f"Analyzing {self.pcap_path}...\n")

        try:
            capture = pyshark.FileCapture(self.pcap_path) #FileCapture function in pyshark, reads the pcap

            pack_c = 0
            for packet in capture:
                if pack_c >= pack_l:
                    break

                if hasattr(packet, "ip"): #verifies that packet has IP level before extracting data - hasattr (has attribute)
                    src_ip = packet.ip.src #assignments
                    dst_ip = packet.ip.dst
                    protocol = packet.highest_layer

                    print(f"[{pack_c + 1}] {src_ip} --> {dst_ip} | Protocol: {protocol}")

                pack_c += 1

            capture.close()
            print("\nBasic analysis completed.")
        
        except FileNotFoundError:
            print(f"Err: file {self.pcap_path} does not exists.")
        except Exception as e:
            print(f"Unexpected error: {e}")
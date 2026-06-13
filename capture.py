import pyshark
import asyncio #manage the asynchronicity
#main and useful library for capturing net packets
#project will be developed in classes
from analyzers.tcp_tracker import TCPTracker
import traceback

class Capture:
    def __init__(self, pcap_path): #define a class in which function will be passed the pcap file path
        self.pcap_path = pcap_path

    def pcap_process(self, pack_l = 10): #function that opens the pcap and read the first 10 packets, for test purpose
        #forcing the Event Loop in order for PyShark to not crash
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        print(f"Analyzing {self.pcap_path}...\n")

        tracker = TCPTracker()
        try:
            capture = pyshark.FileCapture(self.pcap_path, display_filter="tcp") #FileCapture function in pyshark, reads the pcap

            pack_c = 0
            for packet in capture:
                if pack_c >= pack_l:
                    break

                tracker.track_pack(packet)

                pack_c += 1

            capture.close()
            print("\nBasic analysis completed.")
            print(f"Unique TCP sessions detected: {len(tracker.sessions)}")
        
        except FileNotFoundError:
            print(f"Err: file {self.pcap_path} does not exists.")
        except Exception as e:
            print(f"Unexpected error: {type(e).__name__}")
            traceback.print_exc()
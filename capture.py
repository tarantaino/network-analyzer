#main and useful library for capturing net packets
#project will be developed in classes
import pyshark
import asyncio #manage the asynchronicity
import traceback #for managing errors
from analyzers.tcp_tracker import TCPTracker #class imported from the tcp_tracker.py
import sys


class Capture:
    def __init__(self, pcap_path = None, interface = None): #define a class in which functions will be processed the live sniffing
        self.pcap_path = pcap_path
        self.interface = interface

    #function that opens the pcap and read 100 packets
    #forcing the Event Loop in order for PyShark to not crash
    def process_traffic(self, pack_l = 100):
        loop = asyncio.new_event_loop() #new loop for managing ayncs bug
        asyncio.set_event_loop(loop)

        tracker = TCPTracker()
        capture = None
                
        try: #dynamic selection

            if self.pcap_path:
                print(f"Starting static analysis of {self.pcap_path}...\n")
                capture = pyshark.FileCapture(self.pcap_path, keep_packets=False) #FileCapture function in pyshark, reads the pcap
            elif self.interface:
                print(f"Starting LIVE SNIFFING on interface {self.interface}...\n")
                capture = pyshark.LiveCapture(interface=self.interface, eventloop = loop) #livecapture bonds with Windows' net card and new loop injected
            else:
                print("Errore: no target specified (neither file nor interface).")
                return

            pack_c = 0  #same loop as before
            for packet in capture.sniff_continuously(packet_count = pack_l):
                tracker.track_pack(packet)
                pack_c += 1

            
            print("\nCapture completed.")
            print(f"Unique TCP sessions detected in memory: {len(tracker.sessions)}")

            tracker.exp_csv("tcp_report.csv")
        
        except FileNotFoundError:
            print(f"Err: file {self.pcap_path} does not exists.")
        except Exception as e:
            print(f"Unexpected error: {type(e).__name__}")
            traceback.print_exc()
        finally:
            if capture:
               print("\n Killing subprocesses and cleaning memory...")
               try: 
                capture.close()
               except Exception:
                   pass
               
               #we recover all pending asynchronous tasks
               pending_tasks = asyncio.all_tasks(loop=loop)

               #we explicity kill them
               for task in pending_tasks:
                   task.cancel()
                
               #♫we try runnning the loop again to dispose all of the deleting procedures
               if pending_tasks:
                 try:
                   loop.run_until_complete(asyncio.gather(*pending_tasks, return_exceptions=True))
                 except Exception:
                   pass
               
               #now we close the loop without pending tasks
               try:
                   loop.close()
               except Exception:
                   pass

import argparse
from capture import Capture

def main():
    # parser for CLI
    parser = argparse.ArgumentParser(
        description="TCP Analyzer - Static and Live Support",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # user will be asked to add a file or an interface
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-r', '--read', type=str, metavar='FILE',
                       help=".pcap file path to be analyzed")
    group.add_argument('-i', '--interface', type=str, metavar='IFACE',
                       help="Interface name for LiveSniffing (eg. Wi-Fi, Ethernet)")
    
    # optional parameter for limiting packets
    parser.add_argument('-l', '--limit', type=int, default=100, metavar='NUM',
                        help="Limit packets to process (default: 100)")

    # parsing of typed args
    args = parser.parse_args()

    # pass right parameters to the engine
    if args.read:
        start = Capture(pcap_path=args.read)
    elif args.interface:
        start = Capture(interface=args.interface)

    # start analysis
    start.process_traffic(packet_limit=args.limit)

if __name__ == "__main__":
    main()
import argparse #standard library useful to create CLI commands
from capture import Capture

def main():

    parser = argparse.ArgumentParser(description = "Forensic tool based on PyShark")

    parser.add_argument("file", help = ".pcap or .pcapng file path to analyze") #parser to read args via terminal

    args = parser.parse_args()
    
    start = Capture(args.file)
    start.pcap_process()

if __name__ == "__main__":
    main()
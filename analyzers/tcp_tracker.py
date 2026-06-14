import csv



class TCPTracker:
    def __init__(self):
        self.sessions = {}

    def exp_csv(self, output_path="tcp_report.csv"):
        try:
            with open(output_path, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f, delimiter = ";")

                writer.writerow([
                    "Source IP", "Source Port",
                    "Dest. IP", "Dest. Port",
                    "Start_Timestamp", "End_Timestamp",
                    "Duration_Sec", "Session_Status", "Total_Packets"
                ])

                for key, data in self.sessions.items():
                    src_ip, src_port, dst_ip, dst_port = key
                    start_t = data.get("start_time")
                    end_t = data.get("end_time")
                    status = data.get("status")
                    count = data.get("packet_count")

                    if start_t and end_t:
                        duration = f"{(end_t - start_t):.4f}"
                        formatted_end = end_t
                    else:
                        duration = "N/A"
                        formatted_end = "Ongoing"
                    
                    writer.writerow([
                         src_ip, src_port, dst_ip, dst_port,
                         start_t, formatted_end, duration, status, count
                    ])
                
            print(f"CSV dump completed on: {output_path}")
        
        except Exception as e:
            print(f"Critical error during CSV file I/O: {e}")


    def _gen_session_key(self, packet):
        # checks for IPv4 and IPv6 
        if hasattr(packet, "ip"):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
        elif hasattr(packet, "ipv6"):
            src_ip = packet.ipv6.src
            dst_ip = packet.ipv6.dst
        else:
            return None

        src_port = packet.tcp.srcport
        dst_port = packet.tcp.dstport

        # bidrectoinal sorting tracking
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, src_port, dst_ip, dst_port)
        else:
            return (dst_ip, dst_port, src_ip, src_port)
        
    def track_pack(self, packet):
        if not hasattr(packet, "tcp"):
            return
    
        session_key = self._gen_session_key(packet)
        if not session_key:
            return

        timestamp = float(packet.sniff_timestamp)

        # secure extraction, managing errors
        raw_syn = getattr(packet.tcp, 'flags_syn', '0')
        raw_ack = getattr(packet.tcp, 'flags_ack', '0')
        raw_fin = getattr(packet.tcp, 'flags_fin', '0')
        raw_rst = getattr(packet.tcp, 'flags_rst', '0')

        is_syn = str(raw_syn) in ['1', 'True', 'true']
        is_ack = str(raw_ack) in ['1', 'True', 'true']
        is_fin = str(raw_fin) in ['1', 'True', 'true']
        is_rst = str(raw_rst) in ['1', 'True', 'true']

        #new logic to accept Mid-Stream conn
        if session_key not in self.sessions:
            if is_syn and not is_ack:
                self.sessions[session_key] = {
                    "start_time" : timestamp,
                    "end_time": None,
                    "status" : "SYN",
                    "packet_count" : 1
                } 
                print(f"[TCP-START] Detected Handshake between {session_key[0]}:{session_key[1]} e {session_key[2]}:{session_key[3]}")
            else:
                self.sessions[session_key] = {
                    "start_time" : timestamp,
                    "end_time": None,
                    "status" : "MID-STREAM",
                    "packet_count" : 1
                }
                print(f"[TCP-MID] Mid-Stream traffic detected between {session_key[0]}:{session_key[1]} e {session_key[2]}:{session_key[3]}")
        
        else:
            self.sessions[session_key]["packet_count"] += 1

            #print for single packets tracking
            seq_num = getattr(packet.tcp, "seq", "N/A")

            # secure extraction for IPv4 and IPv6
            if hasattr(packet, "ip"):
                current_src = packet.ip.src
                current_dst = packet.ip.dst
            elif hasattr(packet, "ipv6"):
                current_src = packet.ipv6.src
                current_dst = packet.ipv6.dst
            else:
                current_src = "Sconosciuto"
                current_dst = "Sconosciuto"
                
            print(f"  |-> [PKT {self.sessions[session_key]['packet_count']}] {current_src} -> {current_dst} | Seq: {seq_num}")
         
            if is_fin or is_rst:
                self.sessions[session_key]["end_time"] = timestamp
                self.sessions[session_key]["status"] = "CLOSED"
                
                duration = timestamp - self.sessions[session_key]["start_time"]
                print(f"[TCP-END] Session close. Duration: {duration:.4f} sec. Packets: {self.sessions[session_key]['packet_count']}")
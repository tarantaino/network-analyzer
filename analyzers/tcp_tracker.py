class TCPTracker:
    def __init__(self):
        # Dictionary to store active sessions
        self.sessions = {}

    def _gen_session_key(self, packet):
        # checks if is an IPv4 or IPv6 packet
        if hasattr(packet, "ip"):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
        elif hasattr(packet, "ipv6"):
            src_ip = packet.ipv6.src
            dst_ip = packet.ipv6.dst
        else:
            return None # if not one of them, ignore

        src_port = packet.tcp.srcport
        dst_port = packet.tcp.dstport

        # sorting tuple to make it bidirectional
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, src_port, dst_ip, dst_port)
        else:
            return (dst_ip, dst_port, src_ip, src_port)
        
    def track_pack(self, packet):
        # analyzes packets' TCP flags and updates session's status

        if not hasattr(packet, "tcp"):
            return
    
        session_key = self._gen_session_key(packet)
        
        # if session_key is None (no valid IP found), stops
        if not session_key:
            return

        timestamp = float(packet.sniff_timestamp)

        # flags extraction: converts everything in strings and find the matches
        is_syn = str(packet.tcp.flags_syn) in ['1', 'True', 'true']
        is_ack = str(packet.tcp.flags_ack) in ['1', 'True', 'true']
        is_fin = str(packet.tcp.flags_fin) in ['1', 'True', 'true']
        is_rst = str(packet.tcp.flags_rst) in ['1', 'True', 'true']

        if is_syn and not is_ack:
            if session_key not in self.sessions:
                self.sessions[session_key] = {
                    "start_time" : timestamp,
                    "end_time": None,
                    "status" : "SYN",
                    "packet_count" : 1
                } 
                # read IP and port from the new generated key
                print(f"[TCP-START] New session detected between {session_key[0]}:{session_key[1]} and {session_key[2]}:{session_key[3]}")
        
        elif session_key in self.sessions:
            self.sessions[session_key]["packet_count"] += 1
            
            if is_fin or is_rst:
                self.sessions[session_key]["end_time"] = timestamp
                self.sessions[session_key]["status"] = "CLOSED"
                
                duration = timestamp - self.sessions[session_key]["start_time"]
                print(f"[TCP-END] Session close. Duration: {duration:.4f} sec. Total packets: {self.sessions[session_key]['packet_count']}")
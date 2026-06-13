class TCPTracker:
    def __init__(self):
        # Dictionary to store active sessions
        # structure: {unique_tuple: {"start_time": t1, "status": "SYN", ...}}
        self.sessions = {}

    def _gen_session_key(self, packet):
        # generates a sort key for tuples so that A -> B and B -> A flows will be restricted to the same session

        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
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
        # timestamp deve usare la notazione con punto, non underscore in PyShark
        timestamp = float(packet.sniff_timestamp)

        # principal binary flags extraction from PyShark
        # via packet.tcp.flags_* PyShark consents access to single bits
        is_syn = int(packet.tcp.flags_syn) == 1
        is_ack = int(packet.tcp.flags_ack) == 1
        is_fin = int(packet.tcp.flags_fin) == 1
        is_rst = int(packet.tcp.flags_rst) == 1

        if is_syn and not is_ack:
            if session_key not in self.sessions:
                self.sessions[session_key] = {
                    "start_time" : timestamp,
                    "end_time": None,
                    "status" : "SYN",
                    "packet_count" : 1
                } 
                print(f"[TCP-START] New session detected between {packet.ip.src}:{packet.tcp.srcport} and {packet.ip.dst}:{packet.tcp.dstport}")
        
        elif session_key in self.sessions:
            # Aggiunto l'incremento obbligatorio per i pacchetti successivi
            self.sessions[session_key]["packet_count"] += 1
            
            if is_fin or is_rst:
                self.sessions[session_key]["end_time"] = timestamp
                self.sessions[session_key]["status"] = "CLOSED"
                
                # Corretti i typo 'sesssions', '.4f' e la gestione degli apici
                duration = timestamp - self.sessions[session_key]["start_time"]
                print(f"[TCP-END] Session close. Duration: {duration:.4f} sec. Total packets: {self.sessions[session_key]['packet_count']}")
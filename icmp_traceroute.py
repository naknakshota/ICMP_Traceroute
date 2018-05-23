
#*******************************************************************
#                         ICMP_TraceRoute
#                        Author: Shota Nakamura
# Objective: Implement an echo/reply traceroute using ICMP and IP headers
#            
#*******************************************************************

import socket
import struct
import sys
import time

class IcmpTraceroute():

    def __init__(self, src_ip, dst_ip, ip_id, ip_ttl, icmp_id, icmp_seqno):

        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.ip_id = ip_id
        self.max_ttl = 64 #Maximum # of hops
        self.ip_ttl = 1
        self.icmp_id = icmp_id
        self.icmp_seqno = icmp_seqno

        self.run_traceroute()

    def run_traceroute(self):
        #Calculate Checksum
        #checksum_val = self.checksum(self.create_ip_header())
        #checksum_val2 = self.checksum(self.create_icmp_header()) 
        # Create packet
        print("traceroute to" + self.dst_ip + " , 64 hops max")
        while(self.ip_ttl != self.max_ttl):
            ip_header = self.create_ip_header()
            icmp_header = self.create_icmp_header()
            bin_echo_req = ip_header + icmp_header
            
            # Create send and receive sockets
            send_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            recv_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

            # Set IP_HDRINCL flag so kernel not rewrite header fields
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            #Set source ip to your device's IP address
            self.src_ip = '129.133.146.200'

            # Set receive socket timeout to 2 seconds
            recv_sock.settimeout(2.0)

            # Send packet to destination
            send_sock.sendto(bin_echo_req, (self.dst_ip, 0))
            
            #Start a time here to print out
            startTimer = time.time()
            
            #Here we need to make a try except

            try:
                # Receive icmp reply (hopefully)
                [bin_echo_reply, addr] = recv_sock.recvfrom(1024)

                #End the timer
                endTimer = time.time()

                #Measure time
                totaltime = endTimer - startTimer
                # Extract info from ip_header
                #[ip_header_length, ip_identification, ip_protocol, ip_src_addr]  = self.decode_ip_header(bin_echo_reply)

                if(addr=='8.8.8.8'):
                    print(addr[0], totaltime)
                    break
                else:
                    print(addr[0],totaltime)
                    self.ip_ttl += 1
                    #The loop will run again

                # Extract info from icmp_header
                #[icmp_type, icmp_code] = self.decode_icmp_header(bin_echo_reply, ip_header_length)
            
            except:
                self.timeout()
                #We received nothing here so we just increment ttl and let the loop run again.
                self.ip_ttl += 1    
    
    def timeout(self):
        print("Time-to-live Exceeded.")

    def create_ip_header(self):

        # Returned IP header is packed binary data in network order
        ip_version = 4 # 4 bits
        ip_ihl = 5 # 4 bits
        ip_service_type = 0 # 8 bits
        ip_header_length  = 0 # 16 bits 
        ip_identification = self.ip_id # 16 bits
        ip_flags = 0 #3 bits
        ip_fragment_offset = 0 # 13 bits, no fragmentation
        ip_ttl = self.ip_ttl # 8 bits
        ip_protocol = socket.IPPROTO_ICMP # 8 bits
        ip_checksum = 0 # 16 bits
        ip_src = socket.inet_aton(self.src_ip) # 32 bits
        ip_dst = socket.inet_aton(self.dst_ip) # 32 bits

        #b_one contains the version and the ihl
        b_one = (ip_version << 4) + ip_ihl 

        #Pack the ip_header
        ip_header = struct.pack('!BBHHHBBH4s4s',
            b_one,               # B = unsigned char = 8 bits
            ip_service_type,     # B = unsigned char = 8 bits
            ip_header_length,    # H = unsigned char = 16 bits
            ip_identification,   # H = unsigned char = 16 bits
            ip_flags,            # H = unsigned char = 3 bits + 13 bits so 16 bits
            ip_ttl,              # B = unsigned char = 8  bits
            ip_protocol,         # B = unsigned char = 8 bits
            ip_checksum,         # H = unsigned char = 16 bits
            ip_src,              # 4s = unsigned char = 32 bits
            ip_dst)              # 4s = unsigned char = 32 bits 

        return ip_header

    def create_icmp_header(self):

        ECHO_REQUEST_TYPE = 8
        ECHO_CODE = 0

        # ICMP header info from https://tools.ietf.org/html/rfc792
        icmp_type = ECHO_REQUEST_TYPE      # 8 bits
        icmp_code = ECHO_CODE              # 8 bits
        icmp_checksum = 0                  # 16 bits
        icmp_identification = self.icmp_id # 16 bits
        icmp_seq_number = self.icmp_seqno  # 16 bits

        # ICMP header is packed binary data in network order
        icmp_header = struct.pack('!BBHHH', # ! means network order
        icmp_type,           # B = unsigned char = 8 bits
        icmp_code,           # B = unsigned char = 8 bits
        icmp_checksum,       # H = unsigned short = 16 bits
        icmp_identification, # H = unsigned short = 16 bits
        icmp_seq_number)     # H = unsigned short = 16 bits

        return icmp_header

    def decode_ip_header(self, bin_echo_reply):

        # Decode ip_header
        unpack = struct.unpack('!BBHHHBBH4s4s', str(bin_echo_reply))
        # Extract fields of interest
        #(We actually don't use any of the information here later since we only use the src addr)
        ip_header_length = unpack[2]
        ip_identification = unpack[3]
        ip_protocol = unpack[6]
        ip_src_addr = unpack[8]

        return [ip_header_length, ip_identification,
                ip_protocol, ip_src_addr]

    def decode_icmp_header(self, bin_echo_reply, ip_header_length):

        # Decode icmp_header
        unpack = struct.unpack('!BBHHH',str(bin_echo_reply)) #Here we need to unpack after the ip_header length
        # Extract fields of interest (We don't need this information later for our assignment)
        icmp_type = unpack[0] 
        icmp_code = unpack[1]

        return [icmp_type, icmp_code]

def main():

    src_ip = '129.133.146.200' # Your IP addr (e.g., IP address of VM) #
    dst_ip = '8.8.8.8'      # Destination IP address
    ip_id = 111             # IP header in wireshark should have
    ip_ttl = 64             # Max TTL
    icmp_id = 222           # ICMP header in wireshark should have
    icmp_seqno = 1          # Starts at 1, by convention

    if len(sys.argv) > 1:
        src_ip = sys.argv[1]
        dst_ip = sys.argv[2]
        ip_id = int(sys.arv[3])
        ip_ttl = int(sys.argv[4])
        icmp_id = int(sys.argv[5])
        icmp_seqno = int(sys.argv[6])

    traceroute = IcmpTraceroute(
            src_ip, dst_ip, ip_id, ip_ttl, icmp_id, icmp_seqno)
    traceroute.run_traceroute()

if __name__ == '__main__':
    main()


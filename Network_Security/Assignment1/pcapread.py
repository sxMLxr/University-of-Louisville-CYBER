from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP

pcap_file = 'gen-googleopen.pcap'
output_file = '0.txt'

def process_pcap(in_file, out_file):
    f = open(out_file, "w+")
    count = 0
    first_timestamp = 0
    line_list = []
    
    # Looping through all the packets in the PCAP
    for (pkt_data, pkt_metadata,) in RawPcapReader(in_file):
        ether_pkt = Ether(pkt_data)
        ip_pkt = ether_pkt
        src = ip_pkt.src # Get the source IP
        dst = ip_pkt.dst # Get the destination IP
        
        print(f'src = {src} \t ===> {dst} ')
        # Calculate the relative timestamp of packets compared to the first packet
        timestamp = pkt_metadata.sec + (pkt_metadata.usec)/1000000
        if count == 0:
            first_timestamp = timestamp
            relative_timestamp = 0.0
        else:
            relative_timestamp = timestamp - first_timestamp
        
        pkt_size = pkt_metadata.caplen # Get packet size
        count += 1
        line = src + " " + dst + " " + str(round(relative_timestamp, 6)) + " " + str(pkt_size) + " " + str(ip_pkt.proto) + " " + str(ip_pkt.sport) + " " + str(ip_pkt.dport) + "\n"
        line_list.append(line)
    
    f.writelines(line_list)
    f.close()



def main():
    process_pcap(pcap_file, output_file)



if __name__ == "__main__":    
    main()
    
    

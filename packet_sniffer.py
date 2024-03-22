from scapy.all import *
import pandas as pd

def packet_callback(pkt):
    try:
        # Check if the packet has an IP layer
        if IP in pkt:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst

            # Check if the packet has a TCP layer and filter based on source or destination IP
            if TCP in pkt and (ip_src.startswith("192.168.") or ip_dst.startswith("192.168.")):
                tcp_sport = pkt[TCP].sport
                tcp_dport = pkt[TCP].dport

                # Append packet data to a DataFrame
                packet_data.append({"Source IP": ip_src, "Source Port": tcp_sport, "Destination IP": ip_dst, "Destination Port": tcp_dport})
    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffing():
    try:
        # Create an empty DataFrame to store packet data
        global packet_data
        packet_data = pd.DataFrame(columns=["Source IP", "Source Port", "Destination IP", "Destination Port"])

        # Start the packet sniffer
        sniff(prn=packet_callback, filter='tcp', store=0, count=10)

        # Save packet data to an Excel file
        packet_data.to_excel("packet_data.xlsx", index=False)
        print("Packet data saved to packet_data.xlsx")
    except KeyboardInterrupt:
        print("Sniffing stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    start_sniffing()

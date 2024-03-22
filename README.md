Packet Sniffer with TCP Filtering and Excel Output

This Python script utilizes Scapy and pandas libraries to sniff TCP packets and filter based on source or destination IP addresses starting with "192.168.". The filtered packet data is then stored in an Excel file for further analysis.
Features:

    Sniffs TCP packets using Scapy.
    Filters packets based on source or destination IP addresses.
    Captures source IP, source port, destination IP, and destination port of filtered packets.
    Saves packet data to an Excel file for easy viewing and analysis.

Usage:

    Ensure you have Python installed along with the required libraries (scapy, pandas).
    Run the script to start packet sniffing and filtering.
    Press Ctrl+C to stop the sniffing process.
    The script will save the filtered packet data to an Excel file named "packet_data.xlsx" in the current directory.

Dependencies:

    Python 3.x
    Scapy library (pip install scapy)
    pandas library (pip install pandas)

Notes:

    Customize the filtering criteria in the packet_callback function as per your network requirements.
    Modify the Excel file output path and name (packet_data.xlsx) as needed.

Feel free to contribute, report issues, or suggest improvements.

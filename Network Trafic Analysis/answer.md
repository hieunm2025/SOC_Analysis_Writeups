# Tcpdump fundamentals
1.Utilizing the output shown in question-1.png, who is the server in this communication? (IP Address) 
 174.143.213.184
2.Were absolute or relative sequence numbers used during the capture? (see question-1.zip to answer) 
 relative
3.If I wish to start a capture without hostname resolution, verbose output, showing contents in ASCII and hex, and grab the first 100 packets; what are the switches used? please answer in the order the switches are asked for in the question. 
  -nvXc 100
4. Given the capture file at /tmp/capture.pcap, what tcpdump command will enable you to read from the capture and show the output contents in Hex and ASCII? (Please use best practices when using switches) 
 sudo tcpdump -Xr /tmp/capture.pcap
 5. What TCPDump switch will increase the verbosity of our output? ( Include the - with the proper switch ) 
  -v
6. What built in terminal help reference can tell us more about TCPDump?
  man
7.What TCPdump switch let me write my output to a file?
  -w
# Fundamentals Lab
1.What Tcpdump switch will allow us to pipe the contents of a pcap file out to another function such as 'grep'
-l
2.True or False: The filter "port" looks at source and destination traffic
true
3.If we wished to filter out ICMP traffic from our capture, what filter could we use?
not icmp
4.What command will show you where/if TCPDump is installed?
which tcpdump
5. What switch will provide more verbosity in your input?
-v
6.What switch will your capture output a pcap file?
-w
7.What switch will read a capture from a .pcap file?
-r
8.What switch will show the contents of a capture in Hex and ASCII?
-X
# TCPdump Packet Filtering
1.What filter will allow me to see traffic coming from or destined to the host with an ip of 10.10.20.1?
host 10.10.20.1
2.What filter will allow me to capture based on either of two options?
or
3.True or False: TCPDump will resolve IPs to hostnames by default.
true
# Interrogating Network Traffic with Capture and Display Filters
1.What are the client and server port numbrse used in first full TCP three-way handshake?
80 43806
2. Based on the traffic seen, who is the DNS server in this network segment?
172.16.146.1

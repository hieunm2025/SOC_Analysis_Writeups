# HTB-Working-With-IDS-IPS
This is a compilation of my notes for this module

## Intro to IDS/IPS
### Notes
IDS vs IPS
- Intrusion Detection System:
  - Monitors network traffic for suspicious activity
  - Alerts security teams when a threat is detected
  - Passive – doesn’t stop threats, just reports them.
  - Operates in 2 modes:
    - Signature-based detection (matches known threats): accurate but only detects known threats
    - Anomaly-based detection (spots unusual behavior): can detect new threats but may give false alarms
- IPS (Intrusion Prevention System):
  - Also monitors network traffic
  - Active – blocks threats as they are detected
  - Sits inline in the network (directly on the data path)
  - Uses both signature-based and anomaly-based methods
  - Can drop bad packets, block traffic, or reset connections
 
Where
- Both are usually placed behind the firewall to catch threats that get past it
    - IDS is placed to monitor traffic
    - IPS is placed inline to block threats in real time.
- They can also be installed on individual devices (hosts):
  - Host-based IDS (HIDS)
  - Host-based IPS (HIPS)

Why is it Important?
- Part of a defense-in-depth strategy (multiple layers of security)
- Provide visibility and control over network traffic
- Help detect and stop attacks early

IDS/IPS Maintenance
- Regular updates are needed:
  - Threat signatures must stay current
  - Anomaly detection needs tuning to reduce false positives
- Requires ongoing effort by the security team.

Role of SIEM
- SIEM (Security Information and Event Management) systems:
  - Collect and analyze logs from IDS, IPS, and other sources
  - Correlate events to detect advanced or coordinated attacks
  - Provide a centralized view of network security

## Suricata Fundamentals
### Notes
What is it?
- An open-source tool for network security
- Used in IDS, IPS, and Network Security Monitoring (NSM)
- Developed by the Open Information Security Foundation (OISF), a non-profit, community-led organization

What does it do?
- Monitors all network traffic to detect signs of attacks or suspicious activity
- Can analyze both overall network behavior and specific app-layer traffic (like HTTP, DNS, etc.)
- Uses a set of rules to identify threats, determine what to look for and define its response process

Why is it effective?
- Works on both standard computers and specialized hardware
- Designed for high-speed performance, making it suitable for busy networks
- Flexible and powerful, thanks to community-driven rule updates and support

Operation Modes
- IDS Mode:
  - Monitors traffic quietly without taking action
  - Detects and flags suspicious activity
  - Helps improve network visibility and speeds up incident response
  - Does not block or prevent attacks
- IPS Mode:
  - Actively blocks threats before they enter the internal network
  - All traffic is inspected before it's allowed in
  - Increases security, but may cause latency (slower traffic)
  - Requires deep knowledge of the network to avoid blocking safe traffic
  - Rules must be carefully tested to prevent false positives
- IDPS Mode (Intrusion Detection and Prevention System):
  - A hybrid of IDS and IPS
  - Monitors traffic passively, but can send RST packets (reset connections) when threats are found
  - Offers a balance of protection and performance (less latency than IPS)
  - Good for environments that need some blocking ability without full inline inspection
- NSM Mode (Network Security Monitoring):
  - Focuses only on logging network data
  - No active blocking or alerting—just records everything
  - Useful for investigating incidents later
  - Generates a large volume of data
 
Suricata Inputs and Outputs
- Inputs
  - Offline
    - Reads PCAP files - saved packet captures
    - Useful for:
      - Post-incident analysis (looking at past traffic)
      - Testing rule sets and configurations safely
  - Live
    - Reads real-time traffic from network interfaces.
    - Methods include:
      - LibPCAP:
        - Standard method, but limited performance
        - No load-balancing, not ideal for high-speed networks.
      - NFQ (Netfilter Queue):
        - Linux-specific method for inline IPS mode
        - Works with IPTables to send packets to Suricata
        - Needs drop rules to block threats
      - AF_PACKET:
        - Better performance than LibPCAP
        - Supports multi-threading
        - Can’t be used inline if the machine also routes packets
        - May not work on older Linux systems
    - Note: There are also other, advanced input methods not commonly used.
- Outputs
  - Generates: alerts, logs, detailed network data (DNS queries, network flows, HTTP, TLS, SMTP metadata, etc.)
  - Output Formats
    - EVE JSON:
      - Main and most flexible output format
      - Includes events like: alerts, HTTP/DNS/TLS metadata, network flows, dropped packets
      - Works well with tools like Logstash for analysis.
    - Unified2 Format:
      - Snort-compatible binary alert format
      - Useful for integration with Snort-based tools
      - Can be viewed using the u2spewfoo tool

Configuring Suricata & Custom Rules
- After accessing the Suricata instance via SSH, you can view all rule files with a simple command
  - ls -lah /etc/suricata/rules/
- Rules are listed clearly and can be read or inspected to understand what they do
  - more /etc/suricata/rules/emerging-malware.rules
- Some rules might be commented out, meaning:
  - They are not active
  - This usually happens when the rule is outdated or replaced
- Rules often use variables like:
  - $HOME_NET: Your internal network
  - $EXTERNAL_NET: External traffic (like the internet).
- These variables are defined in the suricata.yaml file and can be customized for your own network
  - more /etc/suricata/suricata.yaml
  - Can also create your own variables for better flexibility
  - To load your own custom rules (like local.rules), you need to:
    - Run this command: sudo vim /etc/suricata/suricata.yaml
    - Add /home/htb-student/local.rules to rule-files:
    - Press the Esc key
    - Enter :wq and then, press the Enter key

Hands-on With Suricata Inputs
- Offline Mode
  - Run Suricata with a PCAP file (e.g., suspicious.pcap) to test detection
    - suricata -r /home/htb-student/pcaps/suspicious.pcap
  - Suricata will generate logs like:
    - eve.json (detailed events)
    - fast.log (quick alert summary)
    - stats.log (performance info)
  - You can use flags like:
    - -k to skip checksum checks
    - -l to set a custom output log directory
    - suricata -r /home/htb-student/pcaps/suspicious.pcap -k none -l .
- Live Mode
  - LibPCAP mode: Captures packets live from a network interface
    - Run: ifconfig
      - To find ports to listen to
    - Run: sudo suricata --pcap=ens160 -vv
  - NFQ (Inline IPS mode):
    - Run: sudo iptables -I FORWARD -j NFQUEUE
      - sudo suricata -q 0
    - Requires a specific setup to intercept and analyze live traffic
    - Used for actively blocking malicious packets.
  - AF_PACKET (IDS mode):
    - Run either one:
      - sudo suricata -i ens160
      - sudo suricata --af-packet=ens160
    - Passive monitoring without blocking
    - Supports multi-threading for better performance.
- Observing Live Traffic
  - Open a second SSH session and use tcpreplay to replay PCAP traffic (e.g., from suspicious.pcap) into the live Suricata session
    - sudo  tcpreplay -i ens160 /home/htb-student/pcaps/suspicious.pcap
  - After the test, stop both tcpreplay and Suricata
  - You can find the logs at: /var/log/suricata

Hands-on With Suricata Outputs
- Suricata stores log files in: /var/log/suricata
- Root access is needed to view or manipulate these logs
- Key log files include:
  - eve.json – detailed and versatile (main log)
    - This is an example: less /var/log/suricata/old_eve.json
    - Suricata’s main log file, formatted in JSON
    - Contains rich data like: timestamp, event_type, flow_id, etc.
    - Can be filtered using the jq command
      - View only alert events: cat /var/log/suricata/old_eve.json | jq -c 'select(.event_type == "alert")'
      - Find the first DNS event: cat /var/log/suricata/old_eve.json | jq -c 'select(.event_type == "dns")' | head -1 | jq .
      - Can also filter by TLS, SSH, etc.
    - flow_id:
      - A unique identifier for each network connection ("flow")
      - Helps track and correlate related events in eve.json
      - Useful for understanding everything related to a single communication session
    - pcap_cnt:
      - A packet counter that increments as Suricata processes packets
      - Shows the order of packet processing
      - Helpful for tracing when and where an alert happened in a packet stream.
  - fast.log – quick summary of alerts
    - Run this: cat /var/log/suricata/old_fast.log
    - A quick and readable alert log (text format)
    - Records only alerts
    - Enabled by default.
  - stats.log – performance and diagnostic stats
    - Run this: cat /var/log/suricata/old_stats.log
    - Shows performance statistics and system-level data
    - Useful for debugging or tuning Suricata.
- You can disable the eve.json log if needed and enable specific logs instead
- Example: Enable http-log to get detailed HTTP events
  - When active, a new http.log file is generated every time HTTP traffic is detected.

Hands-on With Suricata Outputs - File Extraction
- Suricata can extract and save files transferred over network protocols (e.g., HTTP)
- This is useful for: threat hunting, forensics and data analysis

How to Enable File Extraction
- Edit suricata.yaml Configuration File
  - Find the file-store section
  - Update the following options:
    - version: 2
    - enabled: yes
    - force-filestore: yes
  - Set the dir option to specify where extracted files will be saved.
- Testing
  - Create a Custom Rule
    - Add this rule to local.rules: alert http any any -> any any (msg:"FILE store all"; filestore; sid:2; rev:1;)
    - This tells Suricata to extract all HTTP-transferred files.
  - Run Suricata on a PCAP File
    - Test with: suricata -r /home/htb-student/pcaps/vm-2.pcap
    - Suricata will: analyze the PCAP, log events, extract files
- Where Files are Stored
  - Extracted files are saved in a folder named filestore
  - Files are stored based on SHA256 hash of their contents
  - Example:
    - File hash starts with f9bc6d...
    - File path will be: /var/log/suricata/filestore/f9/f9bc6d...
- File Inspection
  - Use tools like xxd to inspect file contents in hex format: xxd /var/log/suricata/filestore/21/21742fc6...

Live Rule Reloading
- This feature allows updating rules without restarting Suricata
- Ensures continuous traffic inspection with no downtime

How to Enable Live Rule Reloading
- Edit suricata.yaml:
  - Find the detect-engine section
  - Set the reload option to true:
    - detect-engine:
    - reload: true
- Apply Rule Reloading Without Restarting:
  - Run this command to trigger a ruleset refresh: sudo kill -USR2 $(pidof suricata)

Updating Suricata Rulesets
- Basic Ruleset Update:
  - Run: sudo suricata-update
  - This fetches the latest rules from: https://rules.emergingthreats.net/open/
  - Saves rules to: /var/lib/suricata/rules/
- View Available Ruleset Sources: sudo suricata-update list-sources
- Enable a Specific Ruleset Source (e.g., et/open): sudo suricata-update enable-source et/open
- Fetch & Apply the Enabled Ruleset: sudo suricata-update
- Restart might be needed: sudo systemctl restart suricata
- Before applying changes, test if the config file is valid: sudo suricata -T -c /etc/suricata/suricata.yaml
  - This checks for errors or missing files in the config
  - If Succesful:
    - Suricata runs in test mode
    - Confirmation message: "Configuration provided was successfully loaded. Exiting."

Documentation Recommendation
- Suricata has extensive official documentation
- It’s highly recommended for exploring advanced features and proper configuration
- https://docs.suricata.io/

Key Features
- Deep Packet InspectionL: inspects traffic down to the protocol level.
- Anomaly Detection: flags unusual traffic patterns for analysis.
- IDS/IPS Capabilities: Intrusion Detection, Intrusion Prevention, and hybrid (IDPS) mode.
- Lua Scripting: for writing custom detection logic.
- GeoIP Support: identifies geographic locations of IP addresses.
- IPv4 & IPv6 Support
- IP Reputation: can block or alert based on known malicious IPs.
- File Extraction: extracts files from network traffic for forensics.
- Advanced Protocol Inspection: handles complex protocols (e.g., TLS, HTTP/2, etc.)
- Multitenancy: supports environments with multiple clients or networks.

Extra Note: Detecting Anomalies
- Suricata can detect non-standard or abnormal network traffic
- Refer to the Protocol Anomalies Detection section in Suricata’s docs
- This improves visibility and security against protocol misuse.

### Walkthrough
Q1. Filter out only HTTP events from /var/log/suricata/old_eve.json using the the jq command-line JSON processor. Enter the flow_id that you will come across as your answer.
- Open Powershell and SSH to the target, once in, enter the password
  - ssh htb-student@<Target IP>
- Filter for HTTP event in Suricata
  - cat /var/log/suricata/old_eve.json | jq -c 'select(.event_type == "http")'
- You will see from the returned data, all have the same flow_id
- Answer is: 1252204100696793

Q2. Enable the http-log output in suricata.yaml and run Suricata against /home/htb-student/pcaps/suspicious.pcap. Enter the requested PHP page as your answer. Answer format: _.php
- Open Powershell and SSH to the target, once in, enter the password
  - ssh htb-student@<Target IP>
- Enable the http-log output in suricata.yaml
  - sudo nano /etc/suricata/suricata.yaml
  - Scroll down until you find the 'http-log:' section and change 'enabled:' from no to yes
  - Ctrl+S to save
  - Ctrl+X to exit
- Restart Suricata for apply changes
  - sudo systemctl restart suricata
- Run Suricata
  - suricata -r /home/htb-student/pcaps/suspicious.pcap
- Type 'ls' and there should ba a 'http.log' file generated
- Open the 'http.log' file
  - cat http.log
  - Read through the logs to see the .php page that's requested.
- Answer is: app.php

## Suricata Rule Dev Pt. 1
### Notes
Suricata Rules
- Suricata rules instruct the engine to watch for specific patterns in network traffic
- They’re used for:
  - Detecting malicious behavior
  - Providing contextual network insights (e.g., tracking specific activity)
- Rules can be broad or specific depending on detection goals
- Well-crafted rules balance detection coverage vs. false positives
- Rule creation often relies on threat intelligence and community-shared indicators
- Each rule consumes system resources (CPU & RAM)

Suricata Rule Anatomy
- General Rule Format: action protocol from_ip port -> to_ip port (rule options)
- Header Section: The header of a rule defines the action, protocol, IP addresses, ports, and traffic direction for how the rule should be applied.
  - action: tells Suricata what to do if contents match
    - alert: generates alert
    - log: log traffic without an alert
    - pass: ignore the packet
    - drop: drop packet in IPS mode
    - reject: send TCP RST packets
  - protocol: tcp, udp, icmp, http, dns, etc.
  - directionality: ->, <-, <>
    - Uses rule host variables: $HOME_NET, $EXTERNAL_NET
    - Example:
      - Outbound: $HOME_NET any -> $EXTERNAL_NET 9090
      - Inbound: $EXTERNAL_NET any -> $HOME_NET 8443
      - Bidirectional: $EXTERNAL_NET any <> $HOME_NET any
    - Rule ports define the ports at which the traffic for this rule will be evaluated
- Rule Message & Content: The message and content section specifies the alert message to display when a rule is triggered and defines the traffic patterns considered important for detection.
  - Message: shown when rule is triggered. Should describe malware name/type or behavior.
    - Flow: specifies the initiator and responder of the connection and ensures the rule monitors only established TCP sessions
      - E.g. alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Potential HTTP-based attack"; flow:established,to_server; sid:1003;)
    - DSize: matches based on the payload size of a packet, using the TCP segment length, not the total packet length
      - E.g. alert http any any -> any any (msg:"Large HTTP response"; dsize:>10000; content:"HTTP/1.1 200 OK"; sid:2003;)
  - Rule Content: contains unique values used to identify specific traffic, which Suricata matches in packet payloads for detection
    - Rule Buffers: limit content matching to specific parts of a packet, improving efficiency by reducing unnecessary searches
      - E.g. alert http any any -> any any (http.accept; content:"image/gif"; sid:1;)
        - http.accept: Sticky buffer to match on the HTTP Accept header. Only contains the header value. The \r\n after the header are not part of the buffer.
    - Rule Options: act as additional modifiers to aid detection, helping Suricata locate the exact location of contents
      - nocase: ensures rules are not bypassed through case changes
      - offset: informs Suricata about the start position inside the packet for matching
        - E.g. alert tcp any any -> any any (msg:"Detect specific protocol command"; content:"|01 02 03|"; offset:0; depth:5; sid:3003;)
          - This rule alerts when a specific byte sequence (|01 02 03|) is found at the start of the TCP payload.
          - The offset:0 keyword sets the content match to start from the beginning of the payload, and depth:5 specifies a length of five bytes to be considered for matching
      - distance: tells Suricata to look for the specified content 'n' bytes relative to the previous match
        - E.g. alert tcp any any -> any any (msg:"Detect suspicious URL path"; content:"/admin"; offset:4; depth:10; distance:20; within:50; sid:3001;)
          - This rule alerts when the string /admin is found in the TCP payload, starting at byte 5 (offset:4) within a 10-byte window (depth:10).
          - It uses distance:20 to skip 20 bytes after a prior match and within:50 to ensure the match happens within the next 50 bytes.
  - Rule Metadata
    - reference: links the rule to its original source
    - sid: is a unique identifier for managing and distinguishing rules
    - revision: shows the rule's version history and any updates made
- Pearl Compatible Regular Expression (PCRE): uses regular expressions for advanced matching, written between forward slashes with optional flags at the end. Use anchors for position control and escape special characters as needed. Avoid creating rules that rely only on PCRE.
  - E.g. alert http any any -> $HOME_NET any (msg: "ATTACK [PTsecurity] Apache Continuum <= v1.4.2 CMD Injection"; content: "POST"; http_method; content: "/continuum/saveInstallation.action"; offset: 0; depth: 34; http_uri; content: "installation.varValue="; nocase; http_client_body; pcre: !"/^\$?[\sa-z\\_0-9.-]*(\&|$)/iRP"; flow: to_server, established;sid: 10000048; rev: 1;)
    - Rule triggers on HTTP traffic (alert http) from any source and destination to any port on the home network (any any -> $HOME_NET any)
    - The msg field gives a description of what the alert is for, namely ATTACK [PTsecurity] Apache Continuum <= v1.4.2 CMD Injection
    - The rule checks for the POST string in the HTTP method using the content and http_method keywords. The rule will match if the HTTP method used is a POST request
    - The content keyword with http_uri matches the URI /continuum/saveInstallation.action, starting at offset 0 with a depth of 34, targeting a specific Apache Continuum endpoint
    - Another content keyword searches for installation.varValue= in the HTTP client body, using nocase for case-insensitive matching, potentially detecting command injection payloads
    - PCRE in this case was used to implement Perl Compatible Regular Expressions
      - ^ marks the start of the line
      - \$? checks for an optional dollar sign at the start
      - [\sa-z\\_0-9.-]* matches zero or more (*) of the characters in the set. The set includes:
        - \s a space
        - a-z any lowercase letter
        - \\ a backslash
        - _ an underscore
        - 0-9 any digit
        - . a period
        - '-' a hyphen
          - Speech marks shouldn't be there. Only done since it messes up formatting
        - (\&|$) checks for either an ampersand or the end of the line
        - /iRP at the end indicates this is an inverted match (meaning the rule triggers when the match does not occur), case insensitive (i), and relative to the buffer position (RP).
    - The flow keyword specifies that the rule triggers on established, inbound traffic directed toward the server.
- Refer to: https://docs.suricata.io/en/latest/rules/index.html
  - For more info on Suricata rules

IDS/IPS Rule Development Approaches
Creating IDS/IPS rules involves both technical expertise and threat awareness
- Signature-based detection uses known patterns, like commands or strings, to identify specific malware with high accuracy, but can't detect new threats
- Behavior-based detection looks for anomalous activity (e.g., unusual response sizes or traffic patterns) to catch unknown or zero-day attacks, but may produce more false positives
- Stateful protocol analysis tracks protocol state and flags unexpected behavior, offering deeper insight into malicious activity within normal-looking traffic.

### Walkthrough
Q1. In the /home/htb-student directory of this section's target, there is a file called local.rules. Within this file, there is a rule with sid 2024217, which is associated with the MS17-010 exploit. Additionally, there is a PCAP file named eternalblue.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to MS17-010. What is the minimum offset value that can be set to trigger an alert?
- Open the rules and adjust the offset. Hint: go lower.
  - sudo nano /home/htb-student/local.rules
- Reset Suricata so the rules will apply.
  - sudo systemctl restart suricata
- Run Suricata on the .pcap file
  - sudo suricata -r /home/htb-student/pcaps/eternalblue.pcap -k none -l .
- Check the fast.log file to see if the alarm raised or not
  - sudo cat /var/log/suricata/fast.log
- Keep playing around until alarm is not raised anymore and the minimum is found.
- Answer is: 4

## Suricata Rule Dev Pt. 2
### Notes
Although encryption hides payloads, valuable metadata remains visible. Two key tools for detecting threats in encrypted traffic are:
- SSL/TLS Certificate Analysis
  - SSL certificates (shared during the handshake) contain unencrypted metadata like issuer, subject, and expiration
  - Suspicious domains often have odd or uncommon certificate details, which can be used to write detection rules
- JA3 Fingerprinting
  - JA3 generates a unique fingerprint of SSL/TLS client behavior from the Client Hello packet
  - Malware often uses distinct JA3 hashes, making them useful for identifying malicious encrypted traffic
- These techniques help craft Suricata rules that detect threats even without decrypting the traffic.

### Walkthrough
Q1. There is a file named trickbot.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to a certain variation of the Trickbot malware. Enter the precise string that should be specified in the content keyword of the rule with sid 100299 within the local.rules file so that an alert is triggered as your answer.
- Get the JA3 Digest of trickbot.pcap
  - ja3 -a --json /home/htb-student/pcaps/trickbot.pcap
- Answer is: 72a589da586844d7f0818ce684948eea

## Snort Fundamentals
### Notes
What is Snort?
Snort is an open-source Intrusion Detection and Prevention System (IDS/IPS) that can also operate as a packet sniffer or logger. Like Suricata, it inspects network traffic in depth using custom rule sets that define what to detect and how to respond.

Modes of Operation:
- Passive IDS: Observes traffic without interfering
  - -r (read from pcap) or -i (interface) → Passive by default
- Inline IDS/IPS: Can detect and block malicious traffic
  - -Q → Enables Inline mode (if supported, e.g., with afpacket on Linux)
- NIDS: Analyzes traffic across the network
- HIDS: Technically possible, but not recommended

Snort Architecture Components:
- Packet Decoder – Extracts and understands raw packet data
- Preprocessors – Analyze and categorize traffic (e.g., HTTP parsing, port scan detection)
- Detection Engine – Compares traffic against rule sets for matches
- Logging & Alerting System – Records alerts/logs when matches are found
- Output Modules – Define how and where to store alerts (e.g., syslog, unified2, database).

Snort Configuration Basics
- Snort 3 uses two main configuration files to help users get started quickly:
  - snort.lua – The main configuration file and contains the following files
    - Network Variables – Define IP ranges or interfaces to monitor
    - Decoder Configuration – Controls how raw packets are interpreted
    - Detection Engine – Sets rules and logic for identifying threats
    - Dynamic Libraries – Loads additional Snort modules/plugins
    - Preprocessors – Analyze specific protocols or behaviors
    - Output Plugins – Manage how alerts/logs are stored
    - Rule Set Customization – Tailor which rules are active
    - Decoder/Preprocessor Rule Customization – Fine-tune specific rule behaviors
    - Shared Object Rules – Allow dynamic loading of compiled rules.
  - snort_defaults.lua – Provides default settings used by snort.lua
- These files offer a ready-made framework to help set up Snort efficiently

Snort Inputs
- -r: tells Snort to read and analyze a saved packet capture file instead of monitoring live network traffic
  - This is useful for offline analysis, rule testing, or troubleshooting
  - Runs Snort in passive mode — it inspects packets but doesn't block or interfere
  - Ideal for learning, debugging rules, and analyzing captured incidents
  - E.g. sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r /home/htb-student/pcaps/icmp.pcap
- -i: specifies which network interface(s) Snort should monitor
  - This puts Snort into real-time detection mode, analyzing packets as they pass through the interface
  - Enables live traffic inspection, allowing Snort to alert (or block) based on rule matches in real time
  - Useful for production IDS/IPS setups or real-time testing
  - E.g. sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -i ens160
 
Snort Rules
- Snort rules consist of two main parts: a rule header and rule options, and are structurally similar to Suricata rules
- Despite the similarities, it is recommended to study Snort-specific rule writing from:
  - Snort Documentation: https://docs.snort.org/
  - Suricata’s Differences from Snort: https://docs.suricata.io/en/latest/rules/differences-from-snort.html
- Sources for the latest rules:
  - Official Snort website
  - Emerging Threats website
 
Managing Rules in Snort Deployments
Rules can be managed flexibly in Snort by embedding rules in the snort.lua file using the ips module (e.g., local.rules located at /home/htb-student)
- sudo vim /root/snorty/etc/snort/snort.lua

Command-Line Rule Integration Options
To load a single rule file:
- Use the -R option: snort -c snort.lua -R /path/to/rules/file.rules
To load a directory of rule files:
- Use the --rule-path option: snort -c snort.lua --rule-path /path/to/rules/directory

Snort Outputs
- Basic Statistics (Generated on Shutdown)
  - Packet Statistics: shows counts from DAQ and decoders (e.g., total received packets, UDP packets)
  - Module Statistics: peg counts indicating how often each module observes or performs certain actions (e.g., processed HTTP GET requests)
  - File Statistics: breaks down file types, total bytes, and detected signatures
  - Summary Statistics: includes runtime duration, packets processed per second, and profiling data if enabled
- Alerts
  - Must enable alert output with the -A option to see detection events
  - Available alert formats:
    - -A cmg: Combines -A fast -d -e to show alert info, packet headers, and payload
    - -A u2: Uses the Unified2 format for logging alerts and packets in binary format (for post-processing)
    - -A csv: Outputs in CSV format; great for custom analysis and automation
  - To list all available alert output types:
    - snort --list-plugins | grep logger
- Performance Statistics
  - perf_monitor module: captures peg counts during runtime, helpful for real-time external monitoring
  - profiler module: tgracks CPU/memory usage per module/rule. Output appears in Summary Statistics at shutdown and is used for performance tuning.
- View alerts in cmg format using a pcap file:
  - sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r /home/htb-student/pcaps/icmp.pcap -A cmg
- Use a .rules file that is not included in snort.lua:
  - sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r /home/htb-student/pcaps/icmp.pcap -R /home/htb-student/local.rules -A cmg

Snort Key Features
Key features that bolster Snort's effectiveness include:
- Deep packet inspection, packet capture, and logging
- Intrusion detection
- Network Security Monitoring
- Anomaly detection
- Support for multiple tenants
- Both IPv6 and IPv4 are supported

### Walkthrough
Q1. There is a file named wannamine.pcap in the /home/htb-student/pcaps directory. Run Snort on this PCAP file and enter how many times the rule with sid 1000001 was triggered as your answer.
- Run this command:
  - sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r /home/htb-student/pcaps/wannamine.pcap -A u2
- Scroll down to 'Detection' section
- Answer is: 234
- Note
  - A better method is to output to a file and run this command to return to right number of times the alarm is triggered. In this task only the sid:1000001 was triggered and no other alerts.
    - grep "sid:1000001" /var/log/snort/alert_fast.log | wc -l

## Snort Rule Development
### Notes
- Snort rules are used to detect and flag potentially malicious activity in network traffic
- They are made up of two parts: a rule header and rule options
- Snort rules are similar to Suricata rules, but there are important differences
- It is recommended to study Snort rule writing using official resources:
  - Snort Documentation: https://docs.snort.org/
  - Suricata documentation on rule differences: https://docs.suricata.io/en/latest/rules/differences-from-snort.html
 
Snort Rule Development Example 1: Detecting Ursnif (Inefficiently)
- alert tcp any any -> any any (msg:"Possible Ursnif C2 Activity"; flow:established,to_server; content:"/images/", depth 12; content:"_2F"; content:"_2B"; content:"User-Agent|3a 20|Mozilla/4.0 (compatible|3b| MSIE 8.0|3b| Windows NT"; content:!"Accept"; content:!"Cookie|3a|"; content:!"Referer|3a|"; sid:1000002; rev:1;)
  - Detects certain variants of Ursnif malware
  - Considered inefficient due to missing HTTP sticky buffers
- Breakdown:
  - flow:established,to_server;
    - Matches established TCP connections where data flows from client to server
  - content:"/images/", depth 12;
    - Looks for "/images/" within the first 12 bytes of the payload
  - content:"_2F"; and content:"_2B";
    - Searches for the strings "_2F" and "_2B" anywhere in the payload
  - content:"User-Agent|3a 20|Mozilla/4.0 (compatible|3b| MSIE 8.0|3b| Windows NT";
    - Detects a specific User-Agent string, |3a 20| = : and |3b| = ;
  - content:!"Accept"; content:!"Cookie|3a|"; content:!"Referer|3a|";
    - Ensures the absence of standard HTTP headers, Accept, Cookie: and Referer:

Exercise
- The rule is found in: /home/htb-student/local.rules
- To test:
  - Uncomment the rule in local.rules
  - Run Snort with the following command: sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -R /home/htb-student/local.rules -r /home/htb-student/pcaps/ursnif.pcap -A cmg
- Examine both the ursnif.pcap file in Wireshark and the Snort rule itself

Snort Rule Development Example 2: Detecting Cerber
- alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible Cerber Check-in"; dsize:9; content:"hi", depth 2, fast_pattern; pcre:"/^[af0-9]{7}$/R"; detection_filter:track by_src, count 1, seconds 60; sid:2816763; rev:4;)
  - Detects Cerber ransomware check-in activity using UDP payload characteristics
- Breakdown:
  - $HOME_NET any -> $EXTERNAL_NET any
    - Applies to UDP traffic from any port in the home network to any port on external networks
  - dsize:9;
    - Matches UDP datagrams with exactly 9 bytes of payload data.
  - content:"hi", depth 2, fast_pattern;
    - Looks for the string "hi" in the first 2 bytes of the payload
    - fast_pattern tells Snort to use this match as the initial search, improving performance
  - pcre:"/^[af0-9]{7}$/R";
    - Uses a Perl Compatible Regular Expression to match:
      - Exactly 7 characters (from the set a-f and 0-9),
      - Beginning to end of the payload after "hi".
  - detection_filter:track by_src, count 1, seconds 60;
    - Controls alerting to avoid noise:
      - Tracks by source IP
      - Alert only if more than 1 event occurs within 60 seconds from the same source


Snort Rule Development Example 3: Detecting Patchwork
- alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"OISF TROJAN Targeted AutoIt FileStealer/Downloader CnC Beacon"; flow:established,to_server; http_method; content:"POST"; http_uri; content:".php?profile="; http_client_body; content:"ddager=", depth 7; http_client_body; content:"&r1=", distance 0; http_header; content:!"Accept"; http_header; content:!"Referer|3a|"; sid:10000006; rev:1;)
  - Detects Patchwork APT malware C2 beaconing activity
  - Uses HTTP sticky buffers to more accurately parse HTTP elements
- Breakdown
  - flow:established,to_server;
    - Targets established connections with data flowing from client to server.
  - http_method; content:"POST";
    - Matches HTTP requests using the POST method.
  - http_uri; content:".php?profile=";
    - Looks for URIs containing the string .php?profile=.
  - http_client_body; content:"ddager=", depth 7;
    - Searches in the HTTP request body for ddager= within the first 7 bytes.
  - http_client_body; content:"&r1=", distance 0;
    - Searches for &r1= immediately after the previous match (distance 0).
  - http_header; content:!"Accept";
    - Ensures absence of the Accept HTTP header.
  - http_header; content:!"Referer|3a|";
    - Ensures absence of the Referer: header (|3a| = :)
   
Snort Rule Development Example 4: Detecting Patchwork (SSL)
- alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Patchwork SSL Cert Detected"; flow:established,from_server; content:"|55 04 03|"; content:"|08|toigetgf", distance 1, within 9; classtype:trojan-activity; sid:10000008; rev:1;)
  - Detects Patchwork APT activity based on SSL certificate patterns.
  - Specifically looks for malicious Common Name (CN) field content in X.509 certificates
- Breakdown
  - flow:established,from_server;
    - Targets established TCP flows where traffic is coming from the server.
  - content:"|55 04 03|";
    - Looks for the hex sequence 55 04 03, which is the ASN.1 tag for the Common Name field in X.509 SSL/TLS certificates.
  - content:"|08|toigetgf", distance 1, within 9;
    - Searches for the string toigetgf following the Common Name tag.
    - |08|: denotes the length prefix (8 bytes).
    - distance 1: means the search begins 1 byte after the previous match.
    - within 9 limits the match to 9 bytes forward from the start of this content.

### Walkthrough
Q1. There is a file named log4shell.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to log4shell exploitation attempts, where the payload is embedded within the user agent. Enter the keyword that should be specified right before the content keyword of the rule with sid 10000098 within the local.rules file so that an alert is triggered as your answer. Answer format: [keyword];
- Refer to the previous http example
- Answer is: http_header;

## Zeek Fundamentals
### Notes
What is Zeek?
- An open-source network traffic analyzer
- Primarily used to inspect all network traffic for suspicious or malicious activity.
- Also useful for:
  - Troubleshooting network issues
  - Performing network measurements

Capabilities & Output
- Upon deployment, it generates a wide range of log files valuable to blue teams
- Logs include: connection records, DNS queries and responses, HTTP sessions, other application-layer activities

Scripting Language
- Enables creation of custom Zeek scripts, similar to writing Suricata rules.
- Allows: custom logic development, intrusion detection strategies, extensive platform customization and extension

Why Zeek Stands Out
- Not a traditional signature-based IDS.
- Supports: semantic misuse detection, anomaly detection, behavioral analysis
- Can run on standard hardware, making it accessible and flexible.

Operation Modes
- Fully passive traffic analysis
- libpcap interface for packet capture
- Real-time and offline (e.g., PCAP-based) analysis
- Cluster support for large-scale deployments

Architecture Overview
- Comprised of two main components:
  - Event Engine (Core)
    - Converts raw packet streams into high-level events
    - Events are:
      - Policy-neutral (descriptive, not interpretive).
      - Represent network activities (e.g., an HTTP request becomes an http_request event).
    - Does not analyze or judge the event’s security implications (e.g., whether a port is suspicious).
  - Script Interpreter
    - Processes events using Zeek scripts written in Zeek’s scripting language.
    - Responsible for:
      - Evaluating and responding to events
      - Implementing the site’s security policies
      - Defining event handlers to trigger actions on specific events

Event Handling Workflow
- Events are:
  - Queued in order (first-come, first-served)
  - Passed to the script interpreter for processing
 
Event Definitions
- Most events are defined in .bif files
- Located in: /scripts/base/bif/plugins/
- For a full list of available events: https://docs.zeek.org/en/stable/scripts/base/bif/

Logging
- When analyzing PCAP files offline, logs are stored in the current directory
- Zeek produces a wide range of logs, each focused on different protocols or activities
  - conn.log – Records connection details (IP, TCP, UDP, ICMP)
  - dns.log – Logs DNS queries and responses
  - http.log – Captures HTTP requests and responses
  - ftp.log – Contains FTP session details
  - smtp.log – Logs SMTP transactions (e.g. sender/recipient info)
- For full focumentation on logs: https://docs.zeek.org/en/master/logs/index.html

Log Compression & Storage
- Logs are gzip-compressed every hour by default
- Older logs are moved to folders named with the format YYYY-MM-DD/
- To handle compressed logs:
  - Use gzcat to print them.
  - Use zgrep to search through them.
- For more examples: https://blog.rapid7.com/2016/06/02/working-with-bro-logs-queries-by-example/

Working with Zeek Logs
- Use standard Unix tools like: cat or grep
- Zeek also provides zeek-cut, a specialized utility to:
  - Extract specific columns from log files
  - Work with stdin, pipelines, or redirected input
 
Resources
- Examples and scripting basics: https://docs.zeek.org/en/stable/examples/index.html
- Quick start guide: https://docs.zeek.org/en/stable/quickstart/index.html

Key Features
- Comprehensive logging of network activities
- Analysis of application-layer protocols (irrespective of the port, covering protocols like HTTP, DNS, FTP, SMTP, SSH, SSL, etc.)
- Ability to inspect file content exchanged over application-layer protocols
- IPv6 support
- Tunnel detection and analysis
- Capability to conduct sanity checks during protocol analysis
- IDS-like pattern matching
- Powerful, domain-aware scripting language that allows for expressing arbitrary analysis tasks and managing network state over time
- Interfacing that outputs to well-structured ASCII logs by default and offers alternative backends for ElasticSearch and DataSeries
- Real-time integration of external input into analyses
- External C library for sharing Zeek events with external programs
- Capability to trigger arbitrary external processes from within the scripting language

## Intrusion Detection with Zeek
### Notes
Zeek Overview (Final Summary)
- Zeek (formerly Bro) is a powerful network security monitoring tool.
- Enables deep inspection of network traffic to uncover valuable insights.

Key Strengths
- Flexible and extensible, making it ideal for:
  - Intrusion detection
  - Network investigation
- Provides:
  - A rich set of logs
  - Advanced scripting capabilities
 
Benefits
- Highly customizable to match specific detection needs.
- Supports continuous improvement of your security posture over time.

Intrusion Detection With Zeek Example 1: Detecting Beaconing Malware

What is Beaconing?
- A technique used by malware to communicate with C2 servers.
- Typically involves regular, patterned outbound connections.
- Common goals: receive instructions and exfiltrate data.

Detecting Beaconing
- Analyze connection logs (conn.log) for:
  - Repetitive connections to the same IP/domain.
  - Consistent data sizes in sent packets.
  - Regular connection intervals (e.g., every 5 seconds).
- These signs may indicate beaconing behavior.

Zeek Command for Analysis
- /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/psempire.pcap
  - Processes the psempire.pcap file with Zeek in offline mode.

View the Logs
- cat conn.log
  - Examines connection-level logs for suspicious patterns.

Observed Behavior
- Regular connections to 51.15.197.127:80 every ~5 seconds.
- This pattern is a strong indicator of beaconing.
- The traffic is associated with PowerShell Empire, which beacons every 5 seconds by default.

Next Steps
- Use Wireshark to further inspect the psempire.pcap file.

Intrusion Detection With Zeek Example 2: Detecting DNS Exfiltration

Detecting Data Exfiltration
- Data exfiltration often resembles normal traffic, making it hard to detect.
- Zeek enables deep analysis to uncover suspicious patterns and behaviors.

Useful Zeek Logs
- files.log:
  - Detects large file transfers to unusual destinations or non-standard ports.
- http.log & dns.log:
  - Help spot covert exfiltration methods like:
    - HTTP POSTs to shady domains.
    - DNS tunneling using encoded data in subdomains.

File Reassembly
- Zeek can reassemble files transferred over the network.
- Useful to identify what type of data is being exfiltrated, regardless of protocol.

Analysis Command
- /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/dnsexfil.pcapng
  - Analyzes the dnsexfil.pcapng file using Zeek in offline mode.

View DNS Log
- cat dns.log
  - Reveals DNS queries and responses in the capture.

Extract Queried Domains
- cat dns.log | /usr/local/zeek/bin/zeek-cut query | cut -d . -f1-7
  - Filters and extracts (sub)domain patterns from DNS queries.

Behavioral Observation
- Domain letsgohunt.online is queried via numerous subdomains.
- Pattern is unusual and not typical for normal DNS behavior.
- Suggests potential DNS-based data exfiltration.

Next Steps
- Open the PCAP in Wireshark for deeper packet inspection.

Intrusion Detection With Zeek Example 3: Detecting TLS Exfiltration

Process
- Run Zeek on the PCAP file: /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/tlsexfil.pcap
- Check the connection logs: cat conn.log
- Use a one-liner to analyze data exfiltration: cat conn.log | /usr/local/zeek/bin/zeek-cut id.orig_h id.resp_h orig_bytes | sort | grep -v -e '^$' | grep -v '-' | datamash -g 1,2 sum 3 | sort -k 3 -rn | head -10
  - Breakdown:
    - cat conn.log
      - Displays all Zeek connection logs (details of network connections).
    - /usr/local/zeek/bin/zeek-cut id.orig_h id.resp_h orig_bytes
      - Extracts the source IP, destination IP, and bytes sent by the source.
    - sort
      - Sorts the lines (default: ascending by source IP).
    - grep -v -e '^$'
      - Removes any empty lines from the output.
    - grep -v '-'
      - Removes lines containing dashes (missing values).
    - datamash -g 1,2 sum 3
      - Groups by source and destination IPs, and sums the total bytes sent.
    - sort -k 3 -rn
      - Sorts results by total bytes sent (descending order).
    - head -10
      - Displays the top 10 results (most data sent).

Observation
- Roughly 270 MB of data were sent to the IP 192.168.151.181.

### Walkthrough
Q1. There is a file named printnightmare.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to the PrintNightmare (https://labs.jumpsec.com/printnightmare-network-analysis/) vulnerability. Enter the zeek log that can help us identify the suspicious spooler functions as your answer. Answer format: _.log
- SSH to the machine
- Run Zeek
  - /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/printnightmare.pcap
- There should be logs now in the main folder, run 'ls' to see what kind of logs Zeek generated
- Check them one by one but only dce_rpc will identify the suspicious spooler functions - RpcEnumPrinterDrivers and RpcAddPrinterDriverEx
- Answer is: dce_rpc.log

Q2. There is a file named revilkaseya.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to the REvil ransomware Kaseya supply chain attack. Enter the total number of bytes that the victim has transmitted to the IP address 178.23.155.240 as your answer.
- SSH to the machine
- Run Zeek
  - /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/revilkaseya.pcap
- There should be logs now in the main folder, run 'ls' to see what kind of logs Zeek generated
- Check them on by one, but the log you need is conn.log, but since there's large volume of data, it can't print it all
  - Run this to see all the traffic to 178.23.155.240
    - cat conn.log | /usr/local/zeek/bin/zeek-cut id.orig_h id.resp_h orig_bytes
- There should be two entries, one with 1702 bytes and the other with 609 bytes
- Answer is: 2311

## Skills Assessment - Suricata
### Notes
Suricata Rule Development Exercise: Detecting WMI Execution (Through WMIExec)
- PCAP Source: [GitHub - elcabezzonn/Pcaps](https://github.com/elcabezzonn/Pcaps)
- Attack Description & Detection Reference: https://labs.withsecure.com/publications/attack-detection-fundamentals-discovery-and-lateral-movement-lab-5

What is WMI (Windows Management Instrumentation)?
- A Windows OS feature for:
  - Managing system components.
  - Executing code locally or remotely.
- Highly attractive for attackers seeking stealthy remote execution methods.

Attacker Techniques (WMI Abuse Example)
- Use of wmiexec to execute commands remotely.
- Typically relies on SMB and DCOM protocols to:
  - Communicate with remote systems.
  - Trigger WMI operations over the network.

Example WMI Abuse (Creating a Remote Process)
- The attacker:
  - Creates a Win32_ProcessStartup instance.
  - Sets its properties (e.g., environment for execution).
  - Calls the Create method to spawn a new process such as:
    - cmd.exe
    - powershell.exe

Detection Focus
- Monitor SMB/DCOM traffic for anomalies or unexpected usage.
- Look for patterns of remote process creation via Win32_Process.

### Walkthrough
Q1. There is a file named pipekatposhc2.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to WMI execution. Add yet another content keyword right after the msg part of the rule with sid 2024233 within the local.rules file so that an alert is triggered and enter the specified payload as your answer. Answer format: C____e
- SSH to the machine
- Read up on the resoure link for WMIExec
  - Go to the additional link within the article, expanding on the Win32_ProcessStartup object
  - You will see the answer there.
- The rule can be found with: sudo nano /home/htb-student/local.rules
- To apply the answer.
- Answer is: Create

## Skills Assessment - Snort
### Notes
Snort Rule Development Exercise: Detecting Overpass-the-Hash
- PCAP: [GitHub - elcabezzonn/Pcaps](https://github.com/elcabezzonn/Pcaps)
- Attack details: [labofapenetrationtester.com](http://www.labofapenetrationtester.com/2017/08/week-of-evading-microsoft-ata-day2.html)

Attack: Overpass-the-Hash (a.k.a. Pass-the-Key)
- An attacker uses a stolen NTLM hash or Kerberos key instead of the user's plaintext password.
- The goal is to create a valid Kerberos TGT (Ticket-Granting Ticket) and gain access to Active Directory resources.
- The attacker crafts a Kerberos AS-REQ (Authentication Service Request) using the stolen hash.

How the Attack Works
- Normally, a Kerberos AS-REQ includes:
  - A PRE-AUTH field with an Enc-Timestamp encrypted using the user's password hash.
- In this attack:
  - The attacker bypasses the Enc-Timestamp process.
  - The NTLM hash is directly used to build the Kerberos AS-REQ.

Detection Opportunity
- Legitimate AS-REQ from modern Windows:
  - Uses AES256-CTS-HMAC-SHA1-96 encryption for the Enc-Timestamp.
- Overpass-the-Hash attack:
  - Uses RC4-HMAC encryption (an older method) because it's compatible with NTLM hashes.
- Therefore, seeing AS-REQs using RC4-HMAC in environments where AES is expected may indicate a possible Overpass-the-Hash attack.

### Walkthrough
Q1. There is a file named wannamine.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to the Overpass-the-hash technique which involves Kerberos encryption type downgrading. Replace XX with the appropriate value in the last content keyword of the rule with sid XXXXXXX within the local.rules file so that an alert is triggered as your answer.
- SSH to the machine
- Look for the 'local.rules', use 'ls'
- Open the local.rules
  - sudo nano local.rules
- Edit the rules for the Kerberos Downgrade attack, by removing the XX in the content: “|A0 03 02 01 XX|” to ensure that it will still look for similar hex codes when it triggers the alert
  - alert tcp $HOME_NET any → any 88 (msg: “Kerberos Ticket Encryption Downgrade to RC4 Detected”; flow: no_stream, established, to_server; content: “|A1 03 02 01 05 A2 03 02 01 0A|”, offset 12, depth 10; content: “|A1 03 02 01 02|”, distance 5, within 6; content: “|A0 03 02 01 XX|”, distance 6, within 6; content: “krbtgt”, distance 0; sid:9999999;)
- Uncomment the Kerberos Downgrade attack and comment the other to make sure it's the only active rule.
- Run snort
  - sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -R /home/htb-student/local.rules -r /home/htb-student/pcaps/wannamine.pcap -v -A cmg
- Scan all the similar hex codes in snort.raw[315]
- Answer is: 17

## Skills Assessment - Zeek
### Notes
Intrusion Detection With Zeek: Detecting Gootkit's SSL Certificate
- PCAP Source: https://www.malware-traffic-analysis.net/2016/07/08/index.html
- Threats Involved:
  - Neutrino Exploit Kit: Initial infection vector.
  - Gootkit Trojan: Follow-up payload; a banking trojan using SSL/TLS for communication.

Detection Opportunity: SSL Certificate
- After exploitation, Gootkit uses encrypted SSL/TLS traffic.
- The SSL certificate in use is self-signed or from an untrusted CA.
- Key details:
  - The certificate’s Common Name (CN) is "My Company Ltd."
  - This generic name stands out and can be used as a detection signature.

Why This Matters
- Cybercriminals often use:
  - Self-signed certificates or
  - Certificates with bogus details
- This behavior offers a chance for detection via Zeek's ssl.log.

Zeek Use Case
- Use Zeek to analyze SSL/TLS certificates in network traffic.
- Search for certificates with - Common Name: "My Company Ltd."
- This can help flag Gootkit-related infections when traditional payload inspection fails (due to encryption).

### Walkthrough
Q.1 There is a file named neutrinogootkit.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to the Neutrino exploit kit sending Gootkit malware. Enter the x509.log field name that includes the "MyCompany Ltd." trace as your answer.
- SSH to machine
- Run Zeek on the .pcap file
  - /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/neutrinogootkit.pcap
- Search for the x509.log with 'ls'
- Open the file but try to format it so it's easier to understand
  - sudo cat x509.log | sed 's/\t/\n/g'
- Answer is: certificate.subject
  - Based on extra material, this should also be the same for certificate.issuer since it's a self-issued certificate

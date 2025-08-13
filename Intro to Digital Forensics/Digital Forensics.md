# Intro-to-Digital-Forensics

## Intro
Digital Forensics
- A.K.A computer forensics or cyber forensics
- Involves collection, preservation, analysis, and presentation of digital evidence to investigate cyber incidents, criminal activities, and security breaches.
- Applies forensic techniques to digital artifacts in computers, servers, mobile devices, networks, and storage media
- Aims to reconstruct timelines, identify malicious activities, assess the impact of incidents, and provide evidence for legal or regulatory proceedings.
- Important to incident response process, contributing crucial insights and support at various stages.

Key Concepts
- Electronic Evidence: Includes files, emails, logs, databases, and network traffic from sources like computers, mobile devices, and cloud services.
- Preservation of Evidence: Evidence must be preserved with integrity, following strict procedures to maintain authenticity and a proper chain of custody.
- Forensic Process Stages:
  - Identification: Locate potential evidence.
  - Collection: Acquire data using secure, forensic methods.
  - Examination: Inspect data for relevant details.
  - Analysis: Interpret findings to understand events.
  - Presentation: Clearly report results for legal or organizational use.
- Types of Cases:
  - Cybercrime (e.g., hacking, data theft)
  - Intellectual property theft
  - Internal investigations (e.g., employee misconduct)
  - Incident response and data breaches
  - Legal proceedings and litigation support

Basic Steps
- Create a Forensic Image
- Document the System's State
- Identify and Preserve Evidence
- Analyze the Evidence
- Timeline Analysis
- Identify Indicators of Compromise (IOCs)
- Report and Documentation

Digital Forensics for SOC Analysts
- Post-Incident Analysis: Digital forensics offers a detailed retrospective view of security incidents, helping trace attacker behavior, techniques, and possibly their identity.
- Rapid Threat Identification: Forensic tools quickly analyze large datasets to identify the time of compromise, affected systems, and attack vectors—enabling swift containment.
- Legal Evidence Collection: Forensics ensures evidence is preserved in a legally admissible way (hashed, timestamped, and logged), supporting legal action post-breach.
- Threat Hunting Enablement: Insights from past attacks (IoCs and TTPs) help SOC teams proactively search for signs of compromise across systems.
- Improved Incident Response: Understanding the full scope of an attack allows for more targeted and thorough responses, reducing risks of lingering threats or repeated breaches.
- Continuous Learning & Defense Improvement: Each incident provides valuable lessons, enabling SOC analysts to anticipate new threats and strengthen defenses over time.
- Proactive Security Posture: Digital forensics transforms from a reactive function into a proactive capability that enhances overall SOC effectiveness and organizational resilience.

## Windows Forensic Overview
NTFS (New Technology File System)
- Introduced with Windows NT 3.1 in 1993 as a proprietary file system and is now the default for modern Windows OS versions
- Replaced the older FAT (File Allocation Table) system, overcoming many of its limitations
- Includes features like journaling and error recovery to enhance data integrity.
- Designed to manage large volumes efficiently with faster access and better disk space utilization.
- Supports file-level permissions and encryption to control access and protect data.
- Capable of handling large files and partitions, making it suitable for both desktop and enterprise environments.

NTFS Forensic Artifacts
- File Metadata
  - Stores creation, modification, access times, and file attributes (e.g., read-only, hidden).
  - Helps establish user activity timelines.
- Master File Table (MFT)
  - Central structure storing metadata for all files and folders.
  - Deleted files’ MFT entries may still contain recoverable data.
- File Slack & Unallocated Space
  - May hold remnants of deleted files or leftover data fragments.
  - Useful for data recovery during forensic analysis.
- File Signatures
  - Identifies file types via headers, even if extensions are altered.
  - Aids in reconstructing hidden or renamed files.
- USN Journal
  - Logs changes to files and directories (creations, deletions, modifications).
  - Supports timeline reconstruction and change tracking.
- LNK Files (Shortcuts)
  - Contain paths and metadata of linked files.
  - Reveal accessed or executed programs/files.
- Prefetch Files
  - Log information about program executions for performance optimization.
  - Help identify what apps ran and when.
- Registry Hives
  - Hold critical system and user configuration data.
  - Forensic clues often left by malware or unauthorized changes.
- Shellbags
  - Record folder view settings and accessed directory paths.
  - Show which folders were browsed by users.
- Thumbnail Cache
  - Stores previews of image/doc files.
  - Reveal recently viewed content even if originals are deleted.
- Recycle Bin
  - Temporarily stores deleted files.
  - Useful for recovering user-deleted content and tracking deletions.
- Alternate Data Streams (ADS)
  - Hidden data streams attached to files.
  - Often abused by attackers to hide malicious data.
- Volume Shadow Copies
  - Backup snapshots of the file system.
  - Aid in historical analysis and recovery of changed/deleted files.
- Security Descriptors and ACLs
  - Define user permissions on files/folders.
  - Help identify unauthorized access or privilege misuse.

Windows Event Logs
- Core component of Windows OS used to log events from the system, applications, services, and ETW (Event Tracing for Windows) providers
- Essential for tracking system activity and errors.
- Logs application errors, security incidents, system diagnostics, and more. Useful for real-time monitoring and historical analysis.
  - Also capture a wide range of adversarial tactics such as: initial compromise (e.g., malware, exploits), credential access, privilege escalation and lateral movement (often using built-in Windows tools)
  - Specific logs provide valuable insight into system behavior and attacker actions.
  - Logs can be accessed directly for offline or forensic analysis.

Windows Execution Artifacts
- Traces left behind when programs run on a Windows system
- Helps reconstruct timelines of program execution.
- Allows identification of malicious activity and unauthorized software.
- Aids in understanding user behavior and system interactions.

Common Windows Execution Artifacts
- Prefetch Files
  - Store metadata on executed applications (file paths, execution count, timestamps).
  - Reveal which programs ran and in what order.
- Shimcache (AppCompatCache)
  - Logs executed programs for compatibility.
  - Includes file paths, timestamps, and execution flags.
- Amcache
  - Database of executables and installed apps (since Windows 8).
  - Records file metadata, digital signatures, and execution timestamps.
- UserAssist
  - Registry key tracking user-executed programs.
  - Records app names, execution counts, and timestamps.
- RunMRU Lists
  - Registry-based list of most recently run programs (e.g., from Run dialog).
  - Indicates what was executed and when.
- Jump Lists
  - Store recently accessed files/tasks for specific apps.
  - Reveal user activity and frequently used files.
- Shortcut (LNK) Files
  - Contain paths, timestamps, and user interaction metadata.
  - Show context of program or file execution.
- Recent Items
  - Folder storing shortcuts to recently opened files.
  - Useful for tracking recent user activity.
- Windows Event Logs
  - Include Security, System, and Application logs.
  - Record process creation, termination, crashes, and other events.

Windows Persistence Artifacts
- Windows persistence uses techniques to maintain long-term access to a compromised system after the initial intrusion.
  - Allows attackers to survive reboots and avoid detection.
  - Ensures they can continue malicious activities over time.
  - Helps sustain remote control or ongoing data access/exfiltration.

Windows Registry
- A centralized database in Windows that stores critical system and user configuration settings.
  - Stores user account security configurations via the Security Accounts Manager (SAM).
  - Controls startup behavior and system services.
  - Modifies system behavior based on registry keys and values.
- Covers settings for: Devices, Services, Security policies, Installed applications, User profiles
- Why?
  - High-value target for persistence and privilege escalation.
  - Adversaries modify autorun keys to launch malware at system startup.
  - Registry changes can be stealthy and difficult to detect.
- Defense
  - Regularly inspect Autorun Keys
    - Run/RunOnce Keys
      - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
      - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
      - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
      - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
      - HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\
    - Keys used by WinLogon Process
      - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
      - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
    - Startup Keys
      - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
      - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
      - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
      - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User
  - Monitor unauthorized modifications or suspicious entries.
  - Use tools like Sysinternals Autoruns or registry auditing for analysis.

Schtasks
- Built-in Windows feature that allows automation of programs or commands.
- Used for:
  - Running scripts or updates at specific times
  - Performing system maintenance
  - Automating repetitive processes
- Where?
  - Scheduled tasks are located in: C:\Windows\System32\Tasks
  - Each task is saved as an XML file that contains:
    - Creator/user
    - Trigger details (when the task runs)
    - Path to the executable/command
- Why it Matters?
  - Scheduled tasks can be used to:
    - Maintain persistence
    - Re-execute malware on reboot or at intervals
    - Evade detection using legitimate system features
- How to Investigate?
  - Examine XML content to check for:
    - Unusual or unknown creators
    - Suspicious paths or commands
    - Irregular or high-frequency triggers

Windows Services
- What is it?
  - Background processes that run without user interaction.
  - Critical for system functionality (e.g., networking, updates, security).
  - Automatically start on boot, triggered, or manual.
- Why it Matters?
  - Allows attackers to:
    - Maintain persistence
    - Automatically launch malware or backdoors
    - Operate stealthily under trusted system behavior
- Location
  - Malicious services are often configured in: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
  - This registry path stores: service names, start type (auto/manual), executable paths and configs
- Look For
  - Unexpected or suspicious service names
  - Executables pointing to non-standard directories
  - Services configured to auto-start with unknown binaries

Web Browser Forensics
- A forensic discipline focused on analyzing browser artifacts to understand user activity, online behavior, and potential malicious interactions.
- Look For:
  - Browsing History: URLs, page titles, timestamps, and visit frequency.
  - Cookies: Session data, preferences, and authentication tokens.
  - Cache: Stored web content (pages, images) that may persist even after history is cleared.
  - Bookmarks/Favorites: Saved links showing user interests or frequently accessed sites.
  - Download History: File names, timestamps, and source URLs.
  - Autofill Data: Auto-entered form data: names, addresses, emails, passwords.
  - Search History: Search engine queries and associated timestamps.
  - Session Data: Information about current and recent browsing sessions, tabs, and windows.
  - Typed URLs: Manually entered web addresses.
  - Form Data: User-entered data in web forms (credentials, queries).
  - Saved Passwords: Stored login credentials for websites.
  - Web Storage: Data stored locally by websites (e.g., HTML5 local storage).
  - Favicons: Website icons that indicate visited domains.
  - Tab Recovery Data: Restorable session/tab data after a crash.
  - Extensions and Add-ons: Installed browser tools and their configurations, which may be legitimate or malicious.

SRUM (System Resource Usage Monitor)
- What is it?
  - Introduced in Windows 8+.
  - Logs application and resource usage over time.
  - Stores data in a SQLite database file: sru.db located at: C:\Windows\System32\sru
- Look For
  - Application Profiling
    - Logs executed applications and processes.
    - Includes executable names, paths, timestamps, and usage data.
    - Useful for identifying malicious or unauthorized software.
  - Resource Consumption
    - Tracks CPU, memory, and network usage per process.
    - Helps detect unusual resource spikes or performance anomalies.
  - Timeline Reconstruction
    - Allows creation of detailed timelines based on app usage and system activity.
    - Critical for tracing events, behaviors, and attack sequences.
  - User & System Context
    - Includes user identifiers, linking activities to specific accounts.
    - Helps attribute actions to legitimate users or intruders.
  - Malware Detection
    - Detects signs of malicious behavior:
      - Unusual app usage
      - High resource consumption
      - Suspicious install patterns
  - Incident Response
    - Offers rapid access to recent activity logs during an investigation.
    - Supports quick threat identification and containment decisions.

## Evidence Acquisition Techniques & Tools
Evidence Acquisition
- The process of collecting digital artifacts from systems to preserve them for forensic analysis
- Integrity, authenticity, and admissibility of the data are ensured with specialized tools and methods
- Common Techniques
  - Forensic Imaging
  - Extracting Host-based Evidence & Rapid Triage
  - Extracting Network Evidence

### Forensic Imaging
Forensic Imaging
- Creation of bit-by-bit copies of storage devices.
- Preserves all data, including deleted or hidden files.
  - Allows investigation of evidence and atat in its original state
- Maintains original evidence integrity using hashes (e.g., MD5, SHA-1).
  - Ensures evidence admissibility

Common Forensic Imaging Tools
- FTK Imager
  - Developed by AccessData (now Exterro)
  - Widely used for disk imaging and analysis
  - Preserves evidence integrity and allows data viewing without modification
- AFF4 Imager
  - Free, open-source imaging tool
  - Supports compression, volume segmentation, and file extraction by timestamp
  - Compatible with multiple file systems
- DD & DCFLDD
  - Command-line tools on Unix-based systems
  - DD is default on most Unix systems
  - DCFLDD extends DD with forensic-specific features (e.g., hashing)
- Virtualization Tools
  - Used for evidence collection in virtualized environments
  - Methods include:
    - Pausing VMs and copying storage directories
    - Using VM snapshot features for consistent state capture

### Extracting Host-based Evidence & Rapid Triage
Host-based Evidence
- Digital artifacts generated by OSs and applications during regular operation
  - Such as: file edits, user account creation, application execution
 
Data Volatility
- Volatile data disappears after power-off or logoff
  - Stored in RAM
- Active memory (RAM) is especially valuable in malware investigations.
- Memory analysis can reveal live malware, processes, network activity, and more.
  - Can find many RAM or memory-based attacks

Non-Volatile Data
- Stored on HDD/SSD, and presists through shutdowns
- Includes
  - Registry
  - Windows Event Log
  - System-related artifacts (e.g., Prefetch, Amcache)
  - Application-specific artifacts (e.g., IIS logs, Browser history)

Memory Acquisition Tools
- FTK Imager (https://www.exterro.com/ftk-imager)
  - Commonly used for memory and disk imaging
  - Preserves data integrity for analysis
- WinPmem (https://github.com/Velocidex/WinPmem)
  - Open-source memory acquisition tool
  - Originally part of the Rekall project
- DumpIt (https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/)
  - Simple utility for dumping memory on Windows and Linux
  - Combines 32- and 64-bit memory spaces into a single output file
- MemDump (http://www.nirsoft.net/utils/nircmd.html)
  - Command-line tool for capturing RAM
  - Lightweight and ideal for malware or forensic investigations
- Belkasoft RAM Capturer (https://belkasoft.com/ram-capturer)
  - Effective even against anti-debugging techniques
  - Captures full RAM from live Windows systems
- Magnet RAM Capture (https://www.magnetforensics.com/resources/magnet-ram-capture/)
  - Free tool by Magnet Forensics
  - Simple interface for volatile memory capture
- LiME - Linux Memory Extractor (https://github.com/504ensicsLabs/LiME)
  - Designed for Linux systems
  - Transparent and stealthy, useful for avoiding anti-forensics detection

Rapid Triage
- A targeted forensic approach focused on quickly collecting high-value data from potentially compromised systems.
  - Prioritizes systems likely affected by an incident, as attackers may implement anti-forensic measures and erase data and evidence
- The goal is to centralize and streamline analysis to identify systems with the most evidentiary value, enabling faster and deeper forensic investigation.
  - Centralizes key forensic artifacts for efficient indexing and searching.

Rapid Triage Tool - KAPE (Kroll Artifact Parser and Extractor)
- Developed by Kroll (formerly Magnet Forensics).
- Parses and extracts forensic artifacts rapidly from Windows systems.
  - Speeds up evidence collection from large data sets.
- Works well with mounted images (e.g., using Arsenal Image Mounter).
- Supports both collection (Targets) and processing (Modules) phases.
- Highly customizable and effective in incident response and deep forensics.
  - Extracts critical forensic artifacts (e.g., event logs, browser data, registry keys).
  - Offers automation, efficiency, and broad artifact coverage.

<img width="1579" height="419" alt="image" src="https://github.com/user-attachments/assets/39ced873-2729-4ce9-b074-ff4303b390ed" />

KAPE Operation
- Operates based on the principles of Targets and Modules
  - Targets: specific artifacts KAPE aims to extract from an image or system and duplicated in an output directory
    - Has the '.tkape' extension on output files
  - Compound Targets: amalgamations of multiple targets, gathering multiple files defined across various targets in a single run
- It duplicates specific forensic-related files to a designated output directory, all while maintaining the metadata of each file

EDR (Endpoint Detection and Response)
- Powerful tools used by incident response analysts to remotely detect, investigate, and collect digital evidence from endpoints across a network
- Significantly accelerates investigation and response efforts in large environments.

Rapid Triage Tool - Velociraptor
- Open-source endpoint visibility and response tool.
- Uses Velociraptor Query Language (VQL) to query and collect host data.
- Supports running Hunts across endpoints to gather targeted artifacts.
- Often uses Windows.KapeFiles.Targets artifact to mimic KAPE logic.
- KAPE is not open-source, but its collection logic is available via the KapeFiles project (YAML-based).
  - Velociraptor leverages this logic to efficiently gather high-value forensic artifacts.
- Enables rapid triage and large-scale evidence gathering.
- Improves visibility across all systems.
- Reduces time and resource cost during incident response.
- Velociraptor adds flexibility and customization via open-source tooling.

### Extracting Network Evidence
- Foundational task for SOC analysts
- Involves collecting and analyzing data from network traffic to identify malicious behavior, track threats, and support incident response.
  - Packet Capture & Analysis
    - Traffic capture offers a detailed snapshot of all data transmissions within a network.
    - Tools: Wireshark, tcpdump
    - Enables deep inspection of network conversations and protocol behavior.
  - IDS/IPS Data
    - IDS detects suspicious or known-malicious traffic patterns and generate alerts.
    - IPS goes further by automatically blocking malicious activity.
    - This data is crucial for real-time threat detection and validation.
  - Flow Data (NetFlow/sFlow)
    - Offers a high-level overview of traffic behavior and communication patterns between systems.
    - Lacks payload detail but is excellent for:
      - Identifying large data transfers
      - Spotting unusual communication flows
      - Detecting lateral movement
  - Firewall Logs
    - Modern firewalls do more than block/allow traffic:
      - Identify applications
      - Attribute traffic to specific users
      - Detect and block advanced threats
    - Firewall log analysis helps detect:
      - Exploitation attempts
      - Unauthorized access
      - Malicious communications

### Walkthrough
Q1. Visit the URL "https://127.0.0.1:8889/app/index.html#/search/all" and log in using the credentials: admin/password. After logging in, click on the circular symbol adjacent to "Client ID". Subsequently, select the displayed "Client ID" and click on "Collected". Initiate a new collection and gather artifacts labeled as "Windows.KapeFiles.Targets" using the _SANS_Triage configuration. Lastly, examine the collected artifacts and enter the name of the scheduled task that begins with 'A' and concludes with 'g' as your answer.
- RDP to the machine
  - xfreerdp /u:Administrator /p:password /v:TARGET_IP /dynamic-resolution
- Follow the instructions on the question.
- Download the collected data, move it to desktop and extract all .json files there.
- Open PowerShell and change directory to Desktop
  - cd Desktop
- Run this command to search for the scheduled task
  - Get-Content "Windows.KapeFiles.Targets%2FUploads.json" | ConvertFrom-Json | Where-Object { $_.SourceFile -like "C:\Windows\System32\Tasks\A*g" }
    - Get-Content ".\Windows.KapeFiles.Targets%2FUploads.json"
      - We want to open the 'Windows.KapeFiles.Targets%2FUploads.json'
      - Get-Content: retrieves the text inside the .json file
    - ConvertFrom-Json
      - Converts the raw JSON text into PowerShell objects, makes it easier to read
    - Where-Object { $_.SourceFile -like "C:\Windows\System32\Tasks\A*g" }
      - Filters the objects, returning only those where the SourceFile property matches the given pattern, a string that starts with 'A' and ends with 'g'
      - $_ .SourceFile: accesses only the .SourceFile property of the JSON object.
      - -like: a PowerShell operator for wildcard pattern matching.
- Answer is: AutorunsToWinEventLog

## Memory Forensics
### Notes
Memory Forensics Definition & Process
- Memory Forensics: A.K.A. volatile memory analysis.
  - Detects malicious processes running in memory.
  - Helps uncover IoCs
- A branch of digital forensics focused on analyzing a system’s RAM
  - Memory forensics captures the live state of a system at a specific point in time.
  - Also allows recovery of data that might otherwise be lost, such as encryption keys or active sessions.
    - Can reconstruct malware behavior.

Data Types in RAM
- Network connections (active or recently closed)
- File handles and open files
- Open registry keys
- Running processes
- Loaded modules and device drivers
- Command history and console sessions
- Kernel-level data structures
- User information and credentials
- Malware artifacts (e.g., injected code, unpacked payloads)
- System configuration settings
- Process memory regions

SANS 6-Step Method
1. Process Identification and Verification
- List all running processes on the system.
- Verify process origins within the operating system.
- Compare with legitimate system processes (e.g., using hash lookups or known-safe lists).
- Identify anomalies, such as:
  - Misspelled or misleading process names (e.g., expl0rer.exe instead of explorer.exe).
  - Unexpected parent-child process relationships.
2. Deep Dive into Process Components
- Focus on Dynamic Link Libraries (DLLs) and open handles used by suspicious processes.
- Steps include:
  - Review DLLs loaded by suspicious processes.
  - Look for unauthorized or uncommon DLLs.
  - Check for DLL injection or DLL hijacking signs.
3. Network Activity Analysis
- Analyze network-related data stored in memory to identify communication patterns.
- Actions:
  - Review active and recent network connections.
  - Document external IPs/domains contacted by processes.
  - Determine if connections involve: C2 servers and/or data exfiltration attempts
  - Assess:
    - Whether the process should normally have network activity.
    - The parent process and its legitimacy.
4. Code Injection Detection
- Look for memory manipulation techniques used by attackers.
- Focus areas:
  - Detect process hollowing, unmapped memory regions, or anomalous memory use.
  - Flag processes exhibiting unexpected memory behavior or abnormal execution flow.
5. Rootkit Discovery
- Investigate signs of deep OS-level compromise.
- Techniques include:
  - Scanning for hidden drivers or stealthy system changes.
  - Identifying privileged processes or kernel-level manipulations.
  - Detecting components designed to evade traditional security tools.
6. Extraction of Suspicious Elements
- Isolate and preserve suspicious data for deeper analysis.
- Steps:
  - Dump suspect processes, DLLs, or drivers from memory.
  - Securely store artifacts for analysis using tools like:
    - Static malware analysis platforms
    - Sandboxes
    - Reverse engineering tools

Volatility Framework
- What is it? (https://www.volatilityfoundation.org/releases)
  - Volatility is a leading open-source memory forensics tool, used to analyze RAM dumps (memory images).
  - Built on Python, making it cross-platform compatible (can run on Windows, Linux, macOS).
  - Designed to extract and analyze detailed memory artifacts using a wide variety of plugins.
- Features
  - Plugin-based architecture allows focused and modular analysis.
  - Can analyze memory from multiple operating systems: Windows (XP through Server 2016), macOS, Linux distributions
- Why Volatility?
  - Open-source and widely supported by the forensics community.
  - Offers deep visibility into memory — useful for detecting malware, suspicious processes, and system behavior.
  - Supports automation and integration with custom analysis workflows via Python scripting.
- Common Modules
  - pslist: Lists the running processes.
  - cmdline: Displays process command-line arguments
  - netscan: Scans for network connections and open ports.
  - malfind: Scans for potentially malicious code injected into processes.
  - handles: Scans for open handles
  - svcscan: Lists Windows services.
  - dlllist: Lists loaded DLLs (Dynamic-link Libraries) in a process.
  - hivelist: Lists the registry hives in memory.
- Documentation
  - Volatility v2: https://github.com/volatilityfoundation/volatility/wiki/Command-Reference
  - Volatility v3: https://volatility3.readthedocs.io/en/latest/index.html
  - Cheatsheet: https://blog.onfvp.com/post/volatility-cheatsheet/

Volatility V2 Fundamentals
- Identifying the Profile
  - Profiles are essential, needed to interpret the memory data correctly
  - Use the imageinfo plugin to get profile that mathes the OS of memory dump
- Identifying Running Processes
  - List running process via the pslist plugin.
    - This is to confirm if the profile from rpevious step is valid
    - Volatility may provide correct output even if entering a different profile
- Identifying Network Artifacts
  - The netscan plugin can be used to scan for network artifacts
  - To find _TCPT_OBJECT structures using pool tag scanning, use the connscan command.
    - Can find artifacts from previous connections that are terminated, in addition to the active ones.
- Identifying Injected Code
  - The malfind plugin is used to identify and extract injected code and malicious payloads from memory of a running process
- Identifying Handles
  - The handles plugin is used for analyzing the handles (file and object references) held by a specific process within a memory dump
  - Understanding the handles associated with a process is important. It will reveal the resources and objects a process is interacting with
- Identifying Windows Services
  - The svcscan plugin is used for listing and analyzing Windows services running on a system within a memory dump
- Identifying Loaded DLLs
  - The dlllist plugin is used for listing the dynamic link libraries (DLLs) loaded into the address space of a specific process within a memory dump
- Identifying Hives
  - The hivelist plugin in Volatility is used for listing the hives (registry files) present in the memory dump of a Windows system

Rootkit Analysis with Volatility v2
- Understanding the EPROCESS Structure
  - EPROCESS: a data structure in the Windows kernel that represents a process.
  - Each running process in Windows has its own EPROCESS block in kernel memory
  - EPROCESS analysis allows understanding of running processes on a system, identifying parent-child relationships and determining which processes were active at the time of the memory capture
- FLINK and BLINK
  - Doubly-linked List: a type of linked list where each node (record) contains two references or pointers
    - Next Pointer: points to the next node in the list, allowing list transversal in a forward direction.
    - Previous Pointer: points to the previous node in the list, allowing list transversal in a backward direction.
  - In EPROCESS structure, the ActiveProcessLinks is a doubly-linked list which contains the flink field and the blink field
    - flink: forward pointer, points to the ActiveProcessLinks list entry of the _next_ EPROCESS structure in the list of active processes
    - link: backward pointer, points to the ActiveProcessLinks list entry of the _previous_ EPROCESS structure in the list of active processes.
  - Used by the Windows kernel to quickly iterate through all running processes on the system.
- Identifying Rootkit Signs
  - DKOM (Direct Kernel Object Manipulation): a sophisticated technique used by rootkits and advanced malware to manipulate the Windows OS's kernel data structures to hide malicious processes, drivers, files, and other artifacts from detection by security tools and utilities running in userland (i.e., in user mode).
    - Redirects the Flink and Blink pointers so tool can't detect the process that was a part of the EPROCESS
  - The psscan plugin is used to enumerate running processes
    - It scans the memory pool tags associated with each process's EPROCESS structure
    - Can help identify processes that may have been hidden or unlinked by rootkits, as well as processes that have been terminated but have not been removed from memory yet

Memory Analysis Using Strings
- Strings often contain valuable information, such as text messages, file paths, IP addresses, and even passwords
  - Windows: use the Strings tool from the Sysinternals suite
  - Linux: use the strings command from Binutils
- Identifying IPv4 Addresses
  - strings /home/htb-student/MemoryDumps/MemDumpName.vmem | grep -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"
- Identifying Email Addresses
  - strings /home/htb-student/MemoryDumps/MemDumpName.vmem | grep -oE "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}\b"
- Identifying Command Prompt or PowerShell Artifacts
  - strings /home/htb-student/MemoryDumps/MemDumpName.vmem | grep -E "(cmd|powershell|bash)[^\s]+"

### Walkthrough
Q1. Examine the file "/home/htb-student/MemoryDumps/Win7-2515534d.vmem" with Volatility. Enter the parent process name for @WanaDecryptor (Pid 1060) as your answer. Answer format: _.exe
- SSH to the machine
- Look for the WanaDecryptor process with pslist
  - vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 pslist | grep WanaDecryptor
  - This should return it's PID and the parent process PID (PPID), which is 1792
- Look for the specified PID - 1792
  - vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 pslist | grep " 1792"
  - This will show the parent process for WanaDecryptor
- Answer is: tasksche.exe

Q2. Examine the file "/home/htb-student/MemoryDumps/Win7-2515534d.vmem" with Volatility. tasksche.exe (Pid 1792) has multiple file handles open. Enter the name of the suspicious-looking file that ends with .WNCRYT as your answer. Answer format: _.WNCRYT
- Run handles using the PID found on previous step
  - vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 handles -p 1792 --object-type=File
    - --object-type=File: will limit returned objects to 'File' types
- Answer is: hibsys.WNCRYT

Q3. Examine the file "/home/htb-student/MemoryDumps/Win7-2515534d.vmem" with Volatility. Enter the Pid of the process that loaded zlib1.dll as your answer.
- Since dlllist would show a corrupted output and won't show the PID for process that loadedzlib1.dll, use ldrmodules instead
  - vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 ldrmodules | grep -i zlib1.dll -B 10
    - THis shows that taskhsvc.exe is the process that loaded the DLL along with its PID
- Answer is: 3012

## Disk Forensics
Disk Forensics
- Follows the order of volatility — disk data is analyzed after volatile memory.
- Critical for uncovering subtle traces left by attackers.
- Shifts focus from memory forensics to disk image examination and analysis.

Disk Forensic Tools Features
- File Structure Insight
  - Navigate and explore disk's file hierarchy.
  - Enables quick access to target files in known system locations.
- Hex Viewer
  - Allows low-level inspection of file contents.
  - Essential for identifying customized malware or exploits.
- Web Artifacts Analysis
  - Extracts browser history, cookies, and cache.
  - Helps reconstruct how a user accessed malicious websites.
- Email Carving
  - Retrieves deleted or hidden email data.
  - Useful for insider threat or social engineering investigations.
- Image Viewer
  - Displays pictures stored on the system.
  - Useful for compliance checks or deeper behavioral analysis.
- Metadata Analysis
  - Reveals creation dates, hashes, and disk location of files.
  - Crucial for correlating events (e.g., app launches with malware alerts).

Autopsy - Open-Source Forensic Suite
- Built on The Sleuth Kit (TSK).
- User-friendly interface.
- Offers features similar to commercial tools:
  - Timeline analysis
  - Keyword searches
  - Web/email artifact extraction
  - Filtering based on known malicious file hashes

## Rapid Triage Examination & Analysis Tools
Tools List: https://ericzimmerman.github.io/#!index.md
- Compileed list by Eric Zimmerman

MAC(b) Times in NTFS
- MAC(b) times: a series of timestamps linked to files or objects
  - Could reveal chronology of events/actions
  - Modified, Accessed, Changed, and (b) Birth times
    - Modified Time (M)
      - Records the last time the file's content was modified.
      - Updates whenever the file’s data is edited.
    - Accessed Time (A)
      - Logs the last time the file was read or opened.
      - Updates on file access, even without changes.
    - Changed Time (C)
      - Captures changes to the file's metadata or MFT record.
      - Can update if the file is moved, copied, or renamed (especially on NTFS).
      - May also reflect the file’s creation time, depending on the system.
    - Birth Time (b)
      - Indicates the exact moment the file was created on the file system.
      - Crucial in digital forensics to verify the file’s original creation.
      - Not always used in all filesystems

General Rules for Timestamps in the Windows NTFS File System
- Yes: actions influences timestamp
- No: actions doesn't influence timestamp
- File Create
  - (M) - Yes: reflects time of file creation.
  - (A) - Yes: reflects the time file was accessed at the time of creation.
  - (b) - Yes: set to the time of file creation
- File Modify
  - (M) - Yes: reflects the time when the file's content or attributes were last modified
  - (A) - No: not updated when the file is modified
  - (b) - No: not updated when the file is modified.
- File Copy
  - (M) - No: typically not updated when a file is copied. Usually inherits the timestamp from the source file
  - (A) - Yes: reflect when the file was accessed at the time of copying
  - (b) - Yes: updated to the time of copying, indicating when the copy was created
- File Access
  - (M) - No: not updated when the file is accessed
  - (A) - Yes: reflects the time of access
  - (b) - No: not updated when the file is accessed
- These timestamps are found in the $MFT file, located at the root of the system drive
  - Either:
    - $STANDARD_INFORMATION
    - $FILE_NAME

Timestomping Investigation
- Timestomping: timestamp manipulation
  - MITRE ATT&CK (T1070.006): https://attack.mitre.org/techniques/T1070/006/
  - Obfuscate the sequence of file activities
- Tools like MFT Explorer may output different file timestamp from file explorer
  - Timestamps in file explorer originate from $STANDARD_INFORMATION attribute
  - Cross-verify with the timestamps from the $FILE_NAME attribute through MFTEcmd
- In some file systems like Windows NFTS, regular users don't have permissions to modify timestamps in $FILE_NAME
  - Modifications done through the system kernel

MFT File
- $MFT (Master File Table): https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table
  - Important in NFTS
  - Organizes and catalogues files and directories on an NTFS volume
    - Each file and directory has an entry
  - Has granular records of file and directory activities on the system, encompassing actions like file creation, modification, deletion, and access
  - Can retain metadata about files and directories, even post deletion from the filesystem.
    - This makes MFT very important in forensic analysis and data recovery
  - MFT is strategically positioned at the root of the system drive
  - MFT records, once created, aren't discarded. Instead, new records of new files and directories are added to the MFT.

Structure of MFT File Record
- Each MFT record adheres to a structured format, with attributes and details about the associated file or directory.
- File Components:
  - File Record Header
    - Contains metadata about the file record itself.
    - Includes fields like signature, sequence number, and other administrative info.
  - Standard Information Attribute Header
    - Stores standard file metadata such as:
      - Timestamps (e.g., created, modified)
      - File attributes
      - Security identifiers
  - File Name Attribute Header
    - Contains information about the filename, including:
      - Length
      - Namespace
      - Unicode characters
  - Data Attribute Header
    - Describes how file content is stored:
      - Resident (within the MFT) for small files
      - Non-resident (points to external disk clusters) for larger files
  - File Data (File Content)
    - Holds the actual file content or references to where it's stored.
    - Small files (<512 bytes) may be stored directly in the MFT (resident).
    - Larger files are stored outside the MFT (non-resident).
  - Additional Attributes (Optional)
    - NTFS may include extra attributes like:
      - Security descriptors (SD)
      - Object IDs (OID)
      - Volume name (VOLNAME)
      - Index info, and more

File Record Header
- Includes the following information:
  - Signature: A four-byte signature, usually "FILE" or "BAAD," indicating whether the record is in use or has been deallocated.
  - Offset to Update Sequence Array: An offset to the Update Sequence Array (USA) that helps maintain the integrity of the record during updates.
  - Size of Update Sequence Array: The size of the Update Sequence Array in words.
  - Log File Sequence Number: A number that identifies the last update to the file record.
  - Sequence Number: A number identifying the file record. The MFT records are numbered sequentially, starting from 0.
  - Hard Link Count: The number of hard links to the file. This indicates how many directory entries point to this file record.
  - Offset to First Attribute: An offset to the first attribute in the file record.
- Active@ Disk Editor: https://www.disk-editor.org/index.html
  - Freeware disk editing tool
  - Facilitates the viewing and modification of raw disk data, including the Master File Table of an NTFS system

Zone.Identifier Data in MFT File Record
- Zone.Identifier: a specialized file metadata attribute in the Windows OS, signifies the security zone where file is sourced
  - Part of Windows AES
  - Determines how Windows processes files from uintrusted sources
    - If file is from internet, Windows gives it a ZoneId with a value of '3', meaning the internet zone
    - Starts off with 'Stream' field with 'Zone.Identifier' value
      - To get the content of Zone.Identifier: Get-Content * -Stream Zone.Identifier -ErrorAction SilentlyContinue
- Mark of the Web (MotW): differentiates files sourced from the internet or other potentially dubious sources from those originating from trusted or local contexts
  - Acts as a defense layer for apps
  - If an app opens a file with MotW, it will run a specific security measure based on MotW's presence
    - E.g. Word's Protected View mode that isolates the document that may contain malicious macros from the system
  - Can be used in forensics to analyze the file's download method

Analyzing with Timeline Explorer
- Timeline Explorer: a digital forensic tool developed by Eric Zimmerman which is used to assist forensic analysts and investigators in creating and analyzing timeline artifacts from various sources
- Timeline artifacts can reconstruct events sequentially
  - Can filter data based on date & time range, event types

USN Journal
- Update Sequence Number (USN): a change journal feature that meticulously logs alterations to files and directories on an NTFS volume
  - Can monitor operations such as File Creation, Rename, Deletion, and Data Overwrite.
- In Windows, USN Journal file is designated as $J
- Output: C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$Extend

Analyzing the USN Journal Using MFTECmd
- MFTECmd can also be instrumental in analyzing the USN Journal
- Entries in the USN Journal often allude to modifications to files and directories that are documented in the MFT

Windows Event Logs Investigation
- When KAPE is executed, it duplicates the original event logs, ensuring their pristine state is preserved as evidence
- Output: <KAPE_output_folder>\Windows\System32\winevt\logs
  - Full of various .evtx files based on Security, Application, System, Sysmon (if activated) and more
  - Pay attention on: event IDs, timestamps, source IPs, usernames, and other pertinent log details
  - Identify known TTPs
  - Correlate events from diverse log sources

Windows Event Logs Parsing Using EvtxECmd (EZ-Tool)
- EvtxECmd: a tool that can extract specific event logs or a range of events from an EVTX file, converting them into more digestible formats like JSON, XML, or CSV

Maps in EvtxECmd
- Maps transform customized data into standardized fields in the CSV (and JSON) data
- Standard Field Maps
  - UserName: Contains information about user and/or domain found in various event logs
  - ExecutableInfo: Contains information about process command line, scheduled tasks etc.
  - PayloadData1,2,3,4,5,6: Additional fields to extract and put contextual data from event logs
  - RemoteHost: Contains information about IP address
- EvtxECmd:
  - Converts the unique part of an event (EventData) into a clear, human-readable format.
  - Ensures map files are tailored to specific event logs (e.g., Security, Application, or custom logs) to handle variations in event structure.
  - Uses the Channel element to identify which event log the map file applies to.
    - Prevents confusion when event IDs are reused in different logs.
- To ensure the most recent maps are in place before converting the EVTX files to CSV/JSON, run this: .\EvtxECmd.exe --sync

Investigating Windows Event Logs with EQL
- Endgame's Event Query Language (EQL): a tool for sifting through event logs, pinpointing potential security threats, and uncovering suspicious activities on Windows systems
  - Can query and correlate events across multiple log sources, including the Windows Event Logs
- In EQL's repository (C:\Users\johndoe\Desktop\eqllib-master), there's a PowerShell module with essential functions tailored for parsing Sysmon events from Windows Event Logs
  - It's in the utils directory of eqllib, and is named scrape-events.ps1

Windows Registry
- Contains the computer's name, Windows version, owner's name, and network configuration
- Registry-related files harvested from KAPE are in: <KAPE_output_folder>\Windows\System32\config
- Registry Explorer: tool offers a streamlined interface to navigate and dissect the contents of Windows Registry hives

RegRipper
- A command-line utility adept at swiftly extracting information from the Registry
- Has various plugins, to find run this command: .\rip.exe -l -c > rip_plugins.csv
- To retrieve:
  - Computer Name: .\rip.exe -r "C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Windows\System32\config\SYSTEM" -p compname
  - Timezone: .\rip.exe -r "C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Windows\System32\config\SYSTEM" -p timezone
  - Network Config: .\rip.exe -r "C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Windows\System32\config\SYSTEM" -p nic2
  - Installer Execution: .\rip.exe -r "C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Windows\System32\config\SOFTWARE" -p installer
  - Recently Accessed Folders/Docs: .\rip.exe -r "C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Users\John Doe\NTUSER.DAT" -p recentdocs
  - Autostart - Run Key Entries: .\rip.exe -r "C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Users\John Doe\NTUSER.DAT" -p run

Program Execution Artifacts
- Execution Artifacts: traces and evidence left behind on a computer system or device when a program runs.
  - Can give information on the activities and behaviors of software, users, and even those with malicious intent
- Common Execution Artifacts
  - Prefetch
  - ShimCache
  - Amcache
  - BAM (Background Activity Moderator)

Investigation of Prefetch
- A Windows OS feature that helps optimize the loading of applications by preloading certain components and data
- Prefetch files are created for every program that runs on Windows. both installed applications and standalone executables
- Naming: <PROCESSNAME>.EXE-<HEX VALUE OF PATHFILE>.pf
- Prefetch shows which applications have been run, how often they were executed, and when they were last run
- PECmd will analyze the prefetch file and show relevant info:
  - First and last execution timestamps.
  - Number of times the application has been executed.
  - Volume and directory information.
  - Application name and path.
  - File information, such as file size and hash values.

Investigation of ShimCache (Application Compatibility Cache)
- ShimCache / AppCompatCache: a Windows mechanism that identifies application compatibility issues
- This database records information about executed applications, and is stored in the Windows Registry
- Used by developers to track compatibility issues with executed programs
- Reveals Info:
  - Full file paths
  - Timestamps
    - Last modified time ($Standard_Information)
    - Last updated time (Shimcache)
  - Process execution flag
  - Cache entry position
- Found in: HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\ControlSet001\Control\Session Manager\AppCompatCache

Investigation of Amcache
- AmCache: a Windows registry file which is used to store evidence related to program execution
  - It contains include the execution path, first executed time, deleted time, and first installation. It also provides the file hash for the executables

Investigation of Windows BAM (Background Activity Moderator)
- BAM: a Windows component that tracks and logs the execution of certain types of background or scheduled tasks

Analyzing Captured API Call Data
- (.apmx64) files are generated by API Monitor, which records API call data
- API Monitor captures and displays API calls initiated by applications and services

Registry Persistence via Run Keys
- Adversaries maintain unauthorized access to a compromised system by inserting an entry into the run keys within the Windows Registry

PowerShell Activity
- Logs both the commands issued and their respective outputs during a PowerShell session
- Take note of:
  - Unusual Commands: Look for commands not typical in your environment or associated with malicious behavior (e.g., Invoke-WebRequest, registry edits, scheduled task creation).
  - Script Execution: Watch for execution of PowerShell scripts, especially if unsigned or from untrusted sources.
  - Encoded or Obfuscated Commands: Detect use of Base64-encoded or otherwise obfuscated commands to hide intent.
  - Privilege Escalation: Identify commands trying to escalate privileges, change permissions, or perform admin-level actions.
  - File Operations: Monitor creation, movement, or deletion of files—especially in system or sensitive directories.
  - Network Activity: Watch for network-related commands, like HTTP requests or outbound connections, which may indicate C2 (Command & Control) activity.
  - Registry Manipulation: Be alert to modifications of the Windows Registry, a common method for persistence or configuration changes.
  - Use of Uncommon Modules: Suspicious use of non-standard or uncommon modules could indicate malicious intentions.
  - User Account Activity: Detect creation, modification, or deletion of user accounts—a possible sign of privilege abuse or persistence.
  - Scheduled Task Manipulation: Investigate PowerShell use to create or alter scheduled tasks, often used for automated persistence.
  - Repeated or Unusual Command Patterns: Look for repeated, identical, or unusual sequences of commands that may signal automation or scripted attacks.
  - Unsigned Script Execution: Flag execution of unsigned scripts, especially when policy settings are expected to restrict this behavior.

### Walkthrough
Q1. During our examination of the USN Journal within Timeline Explorer, we observed "uninstall.exe". The attacker subsequently renamed this file. Use Zone.Identifier information to determine its new name and enter it as your answer.
- RDP to the machine
- Run 'Timeline Explorer' and open 'MFT_backup.csv'
- Notice that 'uninstall.exe' has a 'File Size' value of '2305902'
- Clear out all current filters and set it to only that specific 'File Size'
  - Set 'Extensions' to contain '.exe'
  - Since it's just a rename, then the file size should remain the same even after rename.
- Answer is: microsoft.windowskits.feedback.exe

Q2. Review the file at "C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx" using Timeline Explorer. It documents the creation of two scheduled tasks. Enter the name of the scheduled task that begins with "M" and concludes with "r" as your answer.
- RDP to the machine
- Run powershell, need to convert the .evtx file to a readable format, a .csv file
  - Change to the directory to the EvtxCmd to access it
    - cd C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\EvtxeCmd
  - Change the format from .evtx to .csv
    - .\EvtxECmd.exe -f "C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx" --csv "C:\Users\johndoe\Desktop\forensic_data\event_logs\csv_timeline" --csvf Q2_event_log.csv
- Run the Timeline Explorer
  - Open folder in 'Desktop' directory and search for 'timeline'
- Open the output .csv file with the Timeline Explorer
- Run these filters:
  - Event ID = 1
    - This indicates procvess creation, which the automated tasks should start off with
  - Payload Contains 'schtasks'
    - The schtasks is an attribute for a scheduled task, will be typed out in the CMD line
  - There should only be 2 events after filter takes effect
- Look the 'Executable Info' column
- Answer is: Microsoft-Windows-DiagnosticDataCollector

Q3. Examine the contents of the file located at "C:\Users\johndoe\Desktop\forensic_data\APMX64\discord.apmx64" using API Monitor. "discord.exe" performed process injection against another process as well. Identify its name and enter it as your answer.
- RDP to the machine
- Go to the pathfile and open the file by double-clicking. It will automatically open the API Monitor
- In the 'Monitored Processes' tab, expand the 'C\Temp\discord\discord.exe' got to 'Modules' and filter only for 'discord.exe'
- Go to the 'Summary' tab, click the 'Find' icon and look for 'CreateProcess' keyword
  - The first word will be an example from the lesson
    - Look at the IpCommandLine field, this will show the process that discord.exe was trying to inject
    - Look at the dwCreationFlags, this will have 'CREATE_SUSPENDED' value, indicating that the new process's primary thread starts in a suspended state and remains inactive until the ResumeThread function gets invoked
    - Look at the following entries directly below it, discord.exe will be running injection related functions such as OpenProcess, VirtualAllocEx, WriteProcessMemory and CreateRemoteThread
  - There's only one other process that has these indicators of process injection.
- Answer is: cmdkey.exe

## Practical Digital Forensics Scenario
### Notes
#### Memory Analysis with Volatility v3
Identifying the Memory Dump's Profile
- Get the OS & kernel details of the Windows memory sample being analyzed. Use Volatility's windows.info plugin
  - python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.info

Identifying Injected Code
- Volatility's windows.malfind plugin is used to list process memory ranges that potentially contain injected code
  - python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.malfind
- When a process allocates a memory page with PAGE_EXECUTE_READWRITE permissions, it wants to run code in that memory page with the flexibility to change that code as it runs
  - Legitimate applications typically have separate memory regions for code execution and data writing.
    - Ensures data isn't inadvertently executed or executable regions aren't tampered with unexpectedly
- Most malware, and those using code injection techniques, need the ability to write their payload into memory and then execute it
- Not every instance of PAGE_EXECUTE_READWRITE is malicious, but it should be scrutinized

Identifying Running Processes
- List the processes present in this particular Windows memory image through Volatility's windows.pslist plugin
  - python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.pslist
- To list processes in a tree based on their parent process ID, it's done through Volatility's windows.pstree plugin
  - python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.pstree

Identifying Process Command Lines
- Volatility's windows.cmdline plugin can provide a list of process command line arguments
  - python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.cmdline

Dumping Process Memory & Leveraging YARA
- To extract all memory resident pages in a process into an individual file we can use Volatility's windows.memmap plugin
  - python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.memmap --pid 3648 --dump
- To glean more details about the process with ID 3648, we can employ YARA
  - Use a Powershell loop to scan the process dump using all available rules of the YARA rules repository
    - https://github.com/Neo23x0/signature-base/tree/master
    - $rules = Get-ChildItem C:\Users\johndoe\Desktop\yara-4.3.2-2150-win64\rules | Select-Object -Property Name
    - foreach ($rule in $rules) {C:\Users\johndoe\Desktop\yara-4.3.2-2150-win64\yara64.exe C:\Users\johndoe\Desktop\yara-4.3.2-2150-win64\rules\$($rule.Name) C:\Users\johndoe\Desktop\pid.3648.dmp}
  - It should return hits related to the Cobalt Strike framework

Identifying Loaded DLLs
- Scrutinize the command lines, the identified arguments point to payload.dll for process 3648, with the Start function serving as a clear sign of payload.dll's execution
  - Use Volatility's windows.dlllist plugin to gain better understanding
    - python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.dlllist --pid 3648
  - The 'payload.dll' came from E: directory, meaning an external directory or a mounted USB

Identifying Handles
- Identify the files and registry entries accessed by the suspicious process using Volatility's windows.handles plugin
  - python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.handles --pid 3648
- When a process needs to read/write to a file, it doesn't directly interact with the file's data on the disk.
  - The process requests the OS to open the file, and in return, the OS provides a file handle
    - This handle is a ticket that grants the process permission to perform operations on that file.
    - Every subsequent operation the process performs on that file is done through this handle
    - Handles contain a lot of information for forensic analysts, will provide insights on malware behaviour, how it interacts with other files/processes

Identifying Network Artifacts
- Volatility's windows.netstat plugin can traverse network tracking structures to help analyze connection details within a memory image.
  - python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.netstat
- For a more exhaustive network analysis, use Volatility's windows.netscan plugin
  - python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.netscan
  - The suspicious process (PID 3648) has been communicating with 44.214.212.249 over port 80.

#### Disk Image/Rapid Triage Data Examination & Analysis
Searching for Keywords with Autopsy
- Open Autopsy and access the case from C:\Users\johndoe\Desktop\MalwareAttack.
  - Initiate a search for the payload.dll keyword, prioritizing results by their creation time
    - Focus on Finance08062023.iso file in the Downloads directory
    - Extract this file for subsequent scrutiny, by right-clicking and selecting Extract File(s)
    - The file's presence in the Downloads folder and a Chrome cache file (f_000003) pointing to similar strings, it's possible that the ISO file was fetched via a browser.

Identifying Web Download Information & Extracting Files with Autopsy
- To extract web download details, we'll harness the capabilities of ADS
  - Within Autopsy, access the Downloads directory to locate the file.
    - The .Zone.Identifier information, due to Alternate Data Stream (ADS) file attributes, is invaluable.
      - It reveals the file's internet origin, and pinpoint the HostUrl from which the malicious ISO was sourced.
    - Findings from Autopsy's Web Downloads artifacts confirm that Finance08062023.iso was sourced from letsgohunt[.]site
  - Upon mounting the extracted ISO file, it shows that it houses both a DLL and a shortcut file, which uses rundll32.exe to activate payload.dll.

Extracting Cobalt Strike Beacon Configuration
- Extract the beacon configuration via the CobaltStrikeParser script
  - Change directory to: C:\Users\johndoe\Desktop\CobaltStrikeParser-master\CobaltStrikeParser-master
  - python parse_beacon_config.py E:\payload.dll

Identifying Persistence with Autoruns
- For persistence mechanisms, inspect the C:\Users\johndoe\Desktop\files\johndoe_autoruns.arn file using the Autoruns tool.
  - In the Logon section, notice the LocalSystem entry with the following details:
    - Registry path: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    - Image path: C:\ProgramData\svchost.exe
    - Timestamp: Thu Aug 10 11:25:51 2023 (this is a local timestamp, UTC: 09:25:51)
    - Also an odd photo433.exe executable has been flagged
      - Identify its SHA256 through Powershell or Autopsy and check it in VirusTotal website
        - Get-FileHash -Algorithm SHA256 "C:\Users\johndoe\Desktop\kapefiles\auto\C%3A\Users\johndoe\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\photo443.exe"
- Navigate to the Scheduled Tasks tab of the Autoruns tool, to uncover another persistence mechanism

Analyzing MFT Data with Autopsy
- Using the Autoruns tool to search for persistence, it comes across the image path C:\ProgramData\svchost.exe
  - Use Autopsy to find this file
- Accessing the file's metadata (File Metadata tab), pinpoint the MFT (Master File Table) attributes, which will reveal the genuine modification date, Time Stomping.
  - There's a discrepancy when comparing the $FILE_NAME MFT Modified value with the $STANDARD_INFORMATION File Modified value
  - $STANDARD_INFORMATION File Modified timestamp is what a user usually sees in OS file system
  - $FILE_NAME MFT Modified holds the original timestamp, revealing the file's actual history

Analyzing SRUM Data with Autopsy
- The malicious executable had an open handle directed at the Desktop folder.
- Through Autopsy we notice a file named users.db.
  - The attacker might be aiming to siphon this data from the system
- Validate the hypothesis, sift through Data Artifacts and access the Run Programs section.
  - Focus for network metadata analysis rests on SRUDB.dat
  - 430526981 bytes may have been exfiltrated.

Analyzing Rapid Triage Data - Windows Event Logs (Chainsaw)
- Use Chainsaw to pinpoint key events that transpired during our incident timeline
  - chainsaw_x86_64-pc-windows-msvc.exe hunt "..\kapefiles\auto\C%3A\Windows\System32\winevt\Logs" -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/ --csv --output output_csv
- Examine sigma.csv, observe the following alerts:
  - Cobalt Strike Load by rundll32
  - Cobalt Strike Named Pipe
    - Pipe functionality enables covert communication between adversaries C2 servers and compromised systems
  - UAC (User Account Control) Bypass/Privilege Escalation by Abusing fodhelper.exe
  - LSASS Access
  - Windows PowerShell Execution
- Based on account_tampering.csv, a new user was created (Admin) and added to the Administrators group.
  - Can also find evidence of this through Autopsy

Analyzing Rapid Triage Data - Prefetch Files (PECmd)
- Find the system's execution history by analyzing the prefetch files with PECmd.exe

Analyzing Rapid Triage Data - USN Journal (usn.py)
- In the USN journal identify all files that were either created or deleted during the incident.
  - python C:\Users\johndoe\Desktop\files\USN-Journal-Parser-master\usnparser\usn.py -f C:\Users\johndoe\Desktop\kapefiles\ntfs\%5C%5C.%5CC%3A\$Extend\$UsnJrnl%3A$J -o C:\Users\johndoe\Desktop\usn_output.csv -c
- Suspicious activities took place approximately between 2023-08-10 09:00:00 and 2023-08-10 10:00:00.
  - View the CSV using PowerShell in alignment with our timeline
    - $time1 = [DateTime]::ParseExact("2023-08-10 09:00:00.000000", "yyyy-MM-dd HH:mm:ss.ffffff", $null)
    - $time2 = [DateTime]::ParseExact("2023-08-10 10:00:00.000000", "yyyy-MM-dd HH:mm:ss.ffffff", $null)
    - Import-Csv -Path C:\Users\johndoe\Desktop\usn_output.csv | Where-Object { $_.'FileName' -match '\.exe$|\.txt$|\.msi$|\.bat$|\.ps1$|\.iso$|\.lnk$' } | Where-Object { $_.timestamp -as [DateTime] -ge $time1 -and $_.timestamp -as [DateTime] -lt $time2 }
  - Notice that flag.txt was deleted.

Analyzing Rapid Triage Data - MFT/pagefile.sys (MFTECmd/Autopsy)
- Use MFT to try to recover flag.txt
  - Unfortunately, the affected machine's MFT table is not available.
  - Work on another system's MFT table where flag.txt was also deleted.
- Run MFTEcmd to parse the $MFT file, followed by searching for flag.txt within the report
  - C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\MFTECmd.exe -f C:\Users\johndoe\Desktop\files\mft_data --csv C:\Users\johndoe\Desktop\ --csvf mft_csv.csv
    - Output provides the location of flag.txt on the system
- Access the MFT file and on the Desktop, within the reports folder, the flag.txt is marked with the 'Is deleted' attribute
  - When files are deleted from an NTFS file system volume, their MFT entries are marked as free and may be reused, but the data may remain on the disk until overwritten.
  - In the case of the compromised system it was overwritten, but portions of its content were preserved in pagefile.sys.

Constructing an Execution Timeline
- Incident occurred between 09:13 and 09:30, use Autopsy to map out the attacker's actions chronologically.
  - Autopsy employs Plaso (https://github.com/log2timeline/plaso)
  - Limit event types to:
    - Web Activity: All
    - Other: All
  - Set Display Times in: GMT / UTC
    - Start: Aug 10, 2023 9:13:00 AM
    - End: Aug 10, 2023 9:30:00 AM

The Actual Attack Timeline
### Walkthrough
Q1. Extract and scrutinize the memory content of the suspicious PowerShell process which corresponds to PID 6744. Determine which tool from the PowerSploit repository (accessible at https://github.com/PowerShellMafia/PowerSploit) has been utilized within the process, and enter its name as your answer.
- RDP to the machine
- Open Powershell and find the CMD lines used
  - python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.cmdline
  - Will show that there's an encoded command being run on powershell.exe, the command was encrypted with Base64
    - "PowerShell.exe" -nop -w hidden -encodedcommand [ENCRYPTED_COMMAND_STRING]
- Decode the Base64 string
  - $encoded = [ENCRYPTED_COMMAND_STRING]
    - Saves the encrypted string in the $encoded variable
  - $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
    - Saves the decoding process in the $decoded, to be run later to get the decoded string
- It will reveal the string was a GZip Compressed Data, another layer of obfuscation
  - Extract the GZip Compressed Data and save it in a variable
    - $gzip = [$decoded output]
- Convert it from Base64 and decompress
  - $bytes = [Convert]::FromBase64String($gzip)
  - $stream = New-Object IO.MemoryStream(,$bytes)
  - $gzipStream = New-Object IO.Compression.GzipStream($stream, [IO.Compression.CompressionMode]::Decompress)
  - $reader = New-Object IO.StreamReader($gzipStream)
  - $decompressedScript = $reader.ReadToEnd()
- The '$decompressedScript' to get the true script
- Analyze the script, there should be some keywords relating to domain and address, indicating something network related
- Search up the tool in the repository, there should only be one word relating to 'domain'
- Answer is: PowerView

Q2. Investigate the USN Journal located at "C:\Users\johndoe\Desktop\kapefiles\ntfs\%5C%5C.%5CC%3A\$Extend\$UsnJrnl%3A$J" to determine how "advanced_ip_scanner.exe" was introduced to the compromised system. Enter the name of the associated process as your answer. Answer format: _.exe
- RDP to the machine
- Run Powershell and change directory to the USN Journal
  - cd C:\Users\johndoe\Desktop\files\USN-Journal-Parser-master\usnparser
    - This is where the USN Journal python script is stored
- Run the USN Journal
  - python usn.py -f 'C:\Users\johndoe\Desktop\kapefiles\ntfs\%5C%5C.%5CC%3A\$Extend\$UsnJrnl%3A$J' -o C:\Users\johndoe\Desktop\usn_output.csv -c
- Open the .csv file and filter for the 'advanced_ip_scanner.exe' in the FileName column
  - There are 4 entries at line 220577 - 220580, all entries happen consecutively at 'FILE_CREATE', 'DATA_EXTEND FILE_CREATE', 'DATA_EXTEND FILE_CREATE BASIC_INFO_CHANGE' and 'DATA_EXTEND FILE_CREATE BASIC_INFO_CHANGE CLOSE', at the reason column
  - Date & Time Range: 2023-08-10 09:20:26.465120 to 2023-08-10 09:20:26.480509
- Run Volatility and identify the running process during that time range using windows.pslist
  - Look for process running before the creation of 'advanced_ip_scanner.exe'
- Answer is: rundll32.exe

## Skill Assessment
### Walkthrough
Q1. Using VAD analysis, pinpoint the suspicious process and enter its name as your answer. Answer format: _.exe
- RDP to the target
- Extract one of the .zip file on Desktop: Collection-J0seph-personal_localdomain-2023-09-06T21_07_52_02_00
- Run Powershell and change directory to the results folder after extraction
  - cd C:\Users\Administrator\Desktop\results
- Open the 'Windows.Packs.Persistence%2FStartup Items.json' file
  - Get-Content "Windows.Packs.Persistence%2FStartup Items.json" | ConvertFrom-Json
  - There will be a suspiciously named process there, indicating a reverse shell
- Answer is: reverse.exe

Q2. Determine the IP address of the C2 (Command and Control) server and enter it as your answer.
- RDP to the target
- Extract one of the .zip file on Desktop: Collection-J0seph-personal_localdomain-2023-09-06T21_07_52_02_00
- Run Powershell and change directory to the results folder after extraction
  - cd C:\Users\Administrator\Desktop\results
- Open the 'Windows.Network.Netstat.json' file
  - Get-Content "Windows.Network.Netstat.json" | ConvertFrom-Json
  - This is due to the outbound C2 server communications, focus on network activity
- Analyse the entries, focus on rundll32.exe, it will be flagged as suspicious on other logs
  - It will be using TCP on port 80, which is insecure, the default port for HTTP traffic. This puts the TCP handshake under the risk to be hijacked.
- Look at the Raddr IP, this is the C2 server address it's communicating to.
- Answer is: 3.19.219.4
  
Q3. Determine the registry key used for persistence and enter it as your answer.
- RDP to the target
- Extract one of the .zip file on Desktop: Collection-J0seph-personal_localdomain-2023-09-06T21_07_52_02_00
- Run Powershell and change directory to the results folder after extraction
  - cd C:\Users\Administrator\Desktop\results
- Open the 'Windows.Packs.Persistence%2FStartup Items.json' file
  - Get-Content "Windows.Packs.Persistence%2FStartup Items.json" | ConvertFrom-Json
  - This log focuses on persistence artifacts
- Answer is: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  - This key is commonly used for persistence on Windows systems

Q4. Determine the folder that contains all Mimikatz-related files and enter the full path as your answer.
- RDP to the target
- Open the browser and run Velociraptor according to the instructions from above
- Create a new collection, and focus on Windows.Detection.BinaryRename artifacts
  - A common obfuscation tactic, to make it difficult for defense team to detect the presence of malicious software
- There will be an entry regarding Mimikatz
- Answer is: C:\Users\j0seph\AppData\Local\mimik

Q5. Determine the Microsoft Word document that j0seph recently accessed and enter its name as your answer. Answer format: _.DOCX
- RDP to the target
- Open the browser and run Velociraptor according to the instructions from above
- Create a new collection, and focus on Windows.Registry.RecentDocs artifacts
  - This will target artifacts regarding all users when those accounts access a file, both read and write.
- Look at Results tab, there is only one recently accessed .DOCX file.
  - The .DOCX files should be accessed only user 'j0seph'
- Answer is: insurance.DOCX

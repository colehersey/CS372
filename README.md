# CS372
A collection of all of my python programs for Computer Networks (CS372) @ Oregon State

PROGRAMMING ASSIGNMENT 1:
The goal of this programming assignment was to build and create low-level http clients/servers from scratch to get a better understanding of what happens when we open a website or use an internet browser. While this same objective can be achieved by using high-level python libraries like requests, the assignment wanted us to manually interact with GET requests and responses over TCP. Abstraction is key to understanding the heirarchies of computer networks, understanding what is going on at a low-level is equally as important as being able to find this information using high-level libraries. 
The pinnacle of this assignment was to create a basic HTTP server that responds to browser requests with simple HTML messages to demonstrate how data actually moves across the internet. 

 PROGRAMMING ASSIGNMENT 2:
 The main goal of this project was to implement a Reliable Data Transmission (RDT) layer that would provide reliable communication over an unreliable network channel that simulated a real world situation. The assignment required developing a protocol that would handle packet loss, corruption, delays, and out-of-order delivery while maintaining efficiency and correctness. I chose to try and handle the project as efficiently as possible by implementing a Selective Repeat ARQ protocol that had the following key features:
-	Pipelining: Multiple packets in flight per 15 character window
-	Selective Retransmission: Only retransmit the packets that have timed out
-	Flow Control: Used both sender and receiver windows to manage the flow of data
-	Error Detection: Checksum verification to maintain data integrity.
-	Timeout Threshold: Iteration based timeout that was optimized for efficiency.

PORTFOLIO PROJECT - TRACEROUTE ASSIGNMENT
This project extends a basic ICMP skeleton framework into a professional network diagnostic tool, implementing the critical missing functions for comprehensive packet-level network analysis.
Key Additions:
•	Packet Validation System: Built complete data integrity verification comparing sequence numbers, identifiers, and payload data between sent/received packets
•	ICMP Error Handling: Human-readable translation for Types 0, 3, and 11 responses with error code lookup
•	Traceroute Algorithm: Developed TTL-based path discovery using incremental Time-To-Live manipulation to map networks
•	Statistics Engine: Created real-time calculation of min/max/average RTT, packet loss percentages, and performance metrics
•	Response Processing: Added logic to handle diverse network scenarios including timeouts, unreachable destinations, and OS-level errors
Results: Successfully traces international routes (16-hop US -> Japan paths), validates packet integrity in noisy networks, and provides professional-grade network diagnostics comparable to industry-standard tools.
## How to run the program:
- Language: Python
- Command: IcmpHelperLibrary.py
- Requirements: Admin privileges may be required for raw socket access
- Dependencies: Standard python libs (socket, struct, time, select, os)

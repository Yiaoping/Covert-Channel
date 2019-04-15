'''

File: Server.py

Programmer: Yiaoping Shu

Date: September 22 2018

Notes:
This program listens for covert traffic that is coming in. The traffic 
that comes in is checked to see whether or not there's the proper flag.
If the proper flag is displayed, it parses the packet and reads from
the port.	
'''

import sys
from scapy.all import *

'''
Function: decode(pkt)

Programmer: Yiaoping Shu

Date: September 22 2018

Notes: This function listens and filters for covert traffic. It checks for
TCP traffic and if the packet has the CWE flag of 0x80, it decodes it
reading the character from the source port.
'''
def decode(pkt):

	flag=pkt['TCP'].flags	
	if flag == 0x80:
		char = chr(pkt['TCP'].sport)
		print(char, end='', flush=True)



'''
Function: decode(pkt)

Programmer: Yiaoping Shu

Date: September 22 2018

Notes: 
The main function is waiting and listening for messages from the client. Once traffic is received,
it checks to see whether it is TCP or IP. If not, it does not read it. If it is, it invokes the
decode message and parses it there if it has the correct flag.
'''

def main():
	print("Waiting for message")
	sniff(filter="ip and tcp", prn=decode)

if __name__ == '__main__':
	main()


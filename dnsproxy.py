
#__version__ = "0.0.0.0.4"

from multiprocessing import Process, Manager, Lock, Value
import multiprocessing
import socket

import configparser
import timeit
from time import sleep
#sudo pip install dnslib
from dnslib import *
import sys
import re

RegExList = ""
WhiteList = ""


BlockListDict = { 'initialval':'initial' }


ClientMutex = Lock()
ServerMutex = Lock()

# reporting globals
PrintSummary = False
#PrintBlocked = False
#PrintServed = False
#PrintTime = False


def addToFile(filename, data):
	target = open(filename, 'a')
	target.write(data) 
	target.write("\n")  
	target.close()
	
 
def readFile(filename):
	target = open(filename, 'r')
	data = target.read()
	target.close()
	return data
	

def loadBlockList(filename):
	i = 0
	data = readFile(filename)
	data=[_f for _f in data.split('\n') if _f] 
	for line in data: #Simple checking for hostname match
		BlockListDict[line] = 0
		i = i + 1
	print("Loaded " + str(i) + " urls to block")



def loadWhiteList(filename):
	global WhiteList
	WhiteList = readFile(filename)
	WhiteList = [_f for _f in WhiteList.split('\n') if _f] 
	print("Loaded White List")


def isBlocked(host):

	if host.startswith("www."):
		host = host.replace("www.", "") # no longer in host files
	
	
	if (checkCache(host)): 
		if (checkWhiteList(host)):
			return False
		return True
	if (checkRegEx(host)):
		if (checkWhiteList(host)): 
			return False
		return True
	return False


def checkWhiteList(host):
	for line in WhiteList: #Simple checking for hostname match
		if line in host:
			print("White List " + line + " matches " + host)
			return True
	return False
	


def checkRegEx(host):
	if re.match(RegExList, host):
		print("Blocking Regex " + host)
		BlockListDict[host] = 0
		addToFile("regexblock", host)
		return True
	return False
	

def checkCache(host):
	ittr = host.count('.') # how far do we go 
	# check if ittr is too high, if so bail because it bogus
	if ittr > 10: return True # more then 10 dots in the request address is bogus, fail.
	while ittr > 0:
		if BlockListDict.get(host) is not None:
			#print "URL in list " + host
			return True
		temp, host = host.split('.', 1)
		ittr = ittr - 1
	return False;


def sendFailedLookup(s, datagram, addr):
	temp=datagram.find('\x00',12)
	packet=datagram[:2] + '\x81\x83' + datagram[4:6] +  '\x00\x00\x00\x00\x00\x00' + datagram[12:temp+5]
	s.sendto(packet, addr)



def handleClientSocket(client_socket, dns_socket, pending_requests_dict, blocked_urls, served_urls, counter_lock):
	totaltime = 0
	totaltrans = 0

	loadBlockList("blocklist")
	loadWhiteList("whitelist")
	
	clientmutex = ClientMutex # Locals are faster then globals
	
	status = ''
	
	#print "Handle DNS side socket"
	while 1:
		
		clientmutex.acquire()
		try:
			datagram, addr = client_socket.recvfrom(1024) # overkill for buffer size for DNS, still should only get 1 packet
			starttime = timeit.default_timer()
			clientmutex.release() #Got the response from the socket, release the mutex and process packet
			host=str(DNSRecord.parse(datagram).q.qname)[0:-1]
			if (isBlocked(host)): 
				printsting = "Blocked URL " + host   #printsting = "Blocked URL %(host)s"   
				sendFailedLookup(client_socket, datagram, addr)
				
				if PrintSummary:
					with counter_lock: #costly operation
						blocked_urls.value += 1 #costly operation
			else :
				# Not blocked so send the packet to the configured DNS server
				# TODO Add caching later. 
				sent = dns_socket.send(datagram)
				printsting = "Served URL  " + host
				lookupval = datagram[0:2].encode('hex') + host
				lookupvalip = lookupval + ":ip"
				lookupvalport = lookupval + ":port"
				ipport = addr[0] + "::" + str(addr[1])

				pending_requests_dict[lookupval] = ipport
				if PrintSummary: 
					with counter_lock: #costly operation
						served_urls.value += 1 #costly operation
			
			transactiontime = timeit.default_timer() - starttime
			print(printsting, " for ", addr[0], " with transaction time of ", transactiontime)
		except Exception as e:
			print("!!!BAD READ. Error", e) # Sometimes the parser cannot handle the incoming packet

	clientmutex.release()
	return


def handleDNSSocket(client_socket, dns_socket, pending_requests_dict):
	
	servermutex = ServerMutex # locals are faster then globals
	
	while 1:
		
		servermutex.acquire()
		current = multiprocessing.current_process()
		
		try:
			datagram, addr = dns_socket.recvfrom(1024) # overkill for buffer size for DNS, still should only get 1 packet
		except socket.error as e:
			servermutex.release()
			print("SYSTEM ERROR caught on handleDNSSocket.dns_socket.recvfrom ", e)
		else: 			
			servermutex.release() #Got data from the DNS socket, release mutex so others can get and respond dns items
			
			host=str(DNSRecord.parse(datagram).q.qname)[0:-1]
			
			lookupval = datagram[0:2].encode('hex') + host
			
			lookupvalip = lookupval + ":ip"
			lookupvalport = lookupval + ":port"
			returnaddr = pending_requests_dict.get(lookupval)
			if returnaddr is None:
				print("SYSTEM ERROR. No dict entry for ADDR: " + lookupval)
				
			else:
				try: # a few potentially dangerous calls here
					returnaddr = returnaddr.split('::')
					#make sure values are right - validate
					addr = returnaddr[0], int(returnaddr[1])
					client_socket.sendto(datagram, addr)
					del pending_requests_dict[lookupval]
				except Exception as e:
					del pending_requests_dict[lookupval]
					print("SYSTEM ERROR. caught around handleDNSSocket.client_socket.sendto ", e) # need to log
	servermutex.release()
	return

def printStats(blocked_urls, served_urls):
	print("Served " +  str(served_urls) + " URLS, Blocked " + str(blocked_urls) + " attempts so far") 
				

# Main entry point
if __name__ == "__main__":

	# get config file info
	config = configparser.ConfigParser()
	config.read('config')
	# What IP Address to bind to
	listen_address = config.get('config', 'LOCALADDR').split(',', 1)
	# DNS Server to use if a request isn't found
	target_address = config.get('config', 'TARGETDNS').split(',', 1)
	
	# Number threads/processes to serve incoming client requests. Min 2
	client_proc_count = config.getint('config', 'INPROC')
	# Number of threads/process to serve DNS responses back to clients. Min 1
	dns_proc_count = config.getint('config', 'OUTPROC')
	
	# sanity check the process count
	if (client_proc_count < 2) or (client_proc_count > 10):
		client_proc_count = 2
	if (dns_proc_count < 1) or (dns_proc_count > 5):
		dns_proc_count = 1
	
	print(client_proc_count, " ", dns_proc_count)
		
	if 'True' in config.get('reporting', 'SUMMARY'): PrintSummary = True
	
	RegExList = config.get('regex', 'REGEXLIST')
	
	
	mgr = Manager()
	pending = mgr.dict() # so multiple processes can share the same structure for simple MPI
	blocked_urls = Value('i', 0)  # defaults to 0
	served_urls = Value('i', 0)  # defaults to 0
	counter_lock = Lock()

	
	target = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	target.connect((target_address[0], int(target_address[1])))
	client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		client.bind((listen_address[0], int(listen_address[1])))
	except socket.error as err:
		print("Couldn't bind server on %r" % (listen_address, ))
		time.sleep(1)
		raise SystemExit

	
	for i in range(0,client_proc_count):
		process = Process(target=handleClientSocket, args=(client, target, pending, blocked_urls, served_urls, counter_lock))
		process.start()

	for i in range(0,dns_proc_count):	
		process = Process(target=handleDNSSocket, args=(client, target, pending))
		process.start()

	while 1:
		if PrintSummary: printStats(blocked_urls.value, served_urls.value)
		sleep(30)
	
	print("Done")

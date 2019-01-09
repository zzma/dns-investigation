import sys
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR

types = {0: 'ANY', 255: 'ALL',1: 'A', 2: 'NS', 3: 'MD', 4: 'MD', 5: 'CNAME',
         6: 'SOA', 7:  'MB',8: 'MG',9: 'MR',10: 'NULL',11: 'WKS',12: 'PTR',
         13: 'HINFO',14: 'MINFO',15: 'MX',16: 'TXT',17: 'RP',18: 'AFSDB',
         28: 'AAAA', 33: 'SRV',38: 'A6',39: 'DNAME'}

dns_packets = rdpcap(sys.argv[1])

for packet in dns_packets:
    #print(packet)
    if packet.haslayer(DNS):
        pkt_time = packet.sprintf('%sent.time%')
        dst = packet[IP].dst
        src = packet[IP].src
        dns = packet.getlayer(DNS)
        
        values = [pkt_time, src, dst]
        dns_fields = [dns.id, dns.qr, dns.opcode, dns.aa, dns.tc, dns.rd, dns.ra, dns.z, dns.rcode]
        values.extend([str(x) for x in dns_fields])

        if DNSQR in packet:
            qr = packet[DNSQR] # DNS query
            qtype_field = qr.get_field('qtype')
            qclass_field = qr.get_field('qclass')
            qtype = qtype_field.i2repr(qr, qr.qtype)
            qclass = qclass_field.i2repr(qr, qr.qclass)
            query_fields = [qr.qname, qtype, qclass]
            values.extend([str(x) for x in query_fields])
        if DNSRR in packet:
            rr = packet[DNSRR] # DNS response
            rtype_field = qr.get_field('type')
            rclass_field = qr.get_field('class')
            rtype = rtype_field.i2repr(rr, rr.get_field('type'))
            rclass = rclass_field.i2repr(rr, rr.get_field('class'))
            rr_fields = [rr.name, rtype, rclass]
            values.extend([str(x) for x in rr_fields])

        print "|".join(values)

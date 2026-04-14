#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

struct pcap_pkthdr {
    struct timeval ts;   // 캡처 시간
    bpf_u_int32 caplen;  // 실제 캡처된 길이
    bpf_u_int32 len;     // 원본 패킷 길이
};

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, 65535, 1, 1, errbuf); 		// 65535 바이트를 허용 -> 모든 패킷 읽기
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	EthArpPacket s_packet;	// sending packet 1. 우선, 제대로된 패킷을 보내서 상대의 mac주소를 확인함.
    	struct pcap_pkthdr* header;	// 2. reply를 통해 victim의 mac주소를 알아내야함.
	const u_char* r_packet;	

	s_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");	// target(victim)의 mac address
	s_packet.eth_.smac_ = Mac("90:de:80:09:9a:56");	// source(attacker)의 mac address 일단은 내 mac주소.
	s_packet.eth_.type_ = htons(EthHdr::Arp);	// type eth

	s_packet.arp_.hrd_ = htons(ArpHdr::ETHER);	// Hardware type을 ETHER로 지정
	s_packet.arp_.pro_ = htons(EthHdr::Ip4);	// Protocol type을 IPv4로 지정
	s_packet.arp_.hln_ = Mac::Size;			// Hardware length를 Mac의 size(6바이트)로 지정
	s_packet.arp_.pln_ = Ip::Size;			// Protocol length를 IPv4의 size(4바이트)로 지정
	s_packet.arp_.op_ = htons(ArpHdr::Request);	// Operation ARP를 request로 지정
	s_packet.arp_.smac_ = Mac("90:de:80:09:9a:56");	// source(attacker)의 mac address
	s_packet.arp_.sip_ = htonl(Ip("172.20.10.1"));	// source(attacker)의 ip address
	s_packet.arp_.tmac_ = Mac("ff:ff:ff:ff:ff:ff");	// target(victim)의 mac
	s_packet.arp_.tip_ = htonl(Ip("172.20.10.5"));	// target(victim)의 ip

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}

	res = pcap_next_ex(pcap, &r_header, &r_packet);
	if (res != 1) {
		pcap_close(pcap);
		return 0;
	}
	r_header.eth_ eth = (r_header.eth_*)r_packet;
	r_header.arp_ arp = (r_header.arp_*)(r_packet+sizeof(r_header.eth_));

	eth.smac = 




	pcap_close(pcap);
}

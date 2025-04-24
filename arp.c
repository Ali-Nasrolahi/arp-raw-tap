/**
 * @file arp.c
 * @author Ali Nasrolahi (A.Nasrolahi01@gmail.com)
 * @date 2025-04-22
 * @brief A lightweight C program that demonstrates ARP packet crafting using a Linux TAP device.
 */
/*
 *   Topology Diagram:
 *   +----------------------------+
 *   |          Host              |
 *   |   +----------------+       |       +----------------+       +----------------+
 *   |   | Internal Port  |-------|-------|  OVS Bridge   |-------|   TAP Device   |
 *   |   |    (int0)      |       |       |     (br0)     |       |    (tap0)      |
 *   |   | 172.16.60.157  |       |       |               |       | 172.16.60.250  |
 *   |   +----------------+       |       +----------------+       +----------------+
 *   +----------------------------+
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define INET_ADDR_LEN 4

#define DEVICE    "tap0"
#define DEVICE_IP "172.16.60.250"
#define TARGET_IP "172.16.60.157"

#define MODE 0  // Modes: 0. wait_n_reply, 1. req_n_wait

#define ASSERT(val, tag) \
    if (val) {           \
        perror(tag);     \
        exit(1);         \
    }

struct __attribute__((packed)) arp_hdr {
    __be16 arp_hd;
    __be16 arp_pr;
    __u8 arp_hdl;
    __u8 arp_prl;
    __be16 arp_op;                 // opcode: request, reply
    __u8 arp_sha[ETHER_ADDR_LEN];  // src hw mac
    __u8 arp_spa[INET_ADDR_LEN];   // arp_sip, ARP source IP
    __u8 arp_dha[ETHER_ADDR_LEN];  // dst hw mac
    __u8 arp_dpa[INET_ADDR_LEN];   // arp_tip, ARP target IP
};

// arp for ethernet
struct __attribute__((packed)) arp_packet {
    struct ethhdr ethhdr;
    struct arp_hdr arphdr;
};

static void print_mac(const uint8_t *mac)
{
    printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4],
           mac[5]);
}

static void print_eth_hdr(struct ethhdr *packet)
{
    printf("Ethernet type: 0x%x\n", __be16_to_cpu(packet->h_proto));
    printf("Destination ");
    print_mac(packet->h_dest);
    printf("Source ");
    print_mac(packet->h_source);
}

static void print_arp_hdr(struct arp_hdr *packet)
{
    char ip[INET_ADDRSTRLEN];
    printf("Hardware address space: 0x%x\n", __be16_to_cpu(packet->arp_hd));
    printf("Protocol address space: 0x%x\n", __be16_to_cpu(packet->arp_pr));
    printf("Opcode 0x%x\n", __be16_to_cpu(packet->arp_op));
    inet_ntop(AF_INET, packet->arp_spa, ip, sizeof(ip));
    printf("Src IP:%s", ip);
    inet_ntop(AF_INET, packet->arp_dpa, ip, sizeof(ip));
    printf("\nDst IP:%s", ip);
    printf("\n");
}

static void print_arp_packet(struct arp_packet *p)
{
    print_eth_hdr((struct ethhdr *)p);
    print_arp_hdr((struct arp_hdr *)&p->arphdr);
    printf("\n");
}

static void wait_n_reply(int tapfd, __u8 mac[ETHER_ADDR_LEN])
{
    printf("Wait and reply mode!\nThis mode sends back an ARP reply to any request!\n");

    while (1) {
        __u8 pckt_buf[1500];  // packet place holder, for MTU size of 1500
        ASSERT(read(tapfd, pckt_buf, sizeof(pckt_buf)) < 0, "read packet");

        // Drop everything but ARP packets
        if (((struct ethhdr *)pckt_buf)->h_proto != __cpu_to_be16(ETH_P_ARP)) continue;

        struct arp_packet *req_packet = (struct arp_packet *)pckt_buf;  // request packet
        struct arp_packet rep_packet;                                   // reply packet

        static int num;
        printf("Packet ARP Request #%d.1\n", num);
        print_arp_packet(req_packet);

        memcpy(&rep_packet, req_packet, sizeof(struct arp_packet));  // to keep same fields in place

        /* Few helper pointers */
        const __u8 *sender_mac = req_packet->arphdr.arp_sha;  // who-is-asking's MAC
        const __u8 *sender_ip = req_packet->arphdr.arp_spa;   // who-is-asking's IP
        const __u8 *recv_mac = mac;                           // my hw address
        const __u8 *recv_ip = req_packet->arphdr.arp_dpa;     // my IP

        {
            /* 1. update ethhdr */
            memcpy(rep_packet.ethhdr.h_source, recv_mac, ETHER_ADDR_LEN);
            memcpy(rep_packet.ethhdr.h_dest, sender_mac, ETHER_ADDR_LEN);
        }

        {
            /* 2.update arphdr */
            rep_packet.arphdr.arp_op = __cpu_to_be16(ARPOP_REPLY);
            memcpy(rep_packet.arphdr.arp_sha, recv_mac, ETHER_ADDR_LEN);
            memcpy(rep_packet.arphdr.arp_spa, recv_ip, INET_ADDR_LEN);
            memcpy(rep_packet.arphdr.arp_dha, sender_mac, ETHER_ADDR_LEN);
            memcpy(rep_packet.arphdr.arp_dpa, sender_ip, INET_ADDR_LEN);
        }

        /* Print packet's info which goes over the wire */
        printf("Packet ARP Reply #%d.2\n", num++);
        print_arp_packet(&rep_packet);

        ASSERT(write(tapfd, &rep_packet, sizeof(struct arp_packet)) < 0, "write packet");
    }
}

static void req_n_wait(int tapfd, __u8 mac[ETHER_ADDR_LEN])
{
    printf("Request and wait mode!\n");
    printf("This mode sends an ARP request to retrieve MAC of an arbitrary device!\n");
    struct arp_packet req_packet;

    {
        /* 1. ethhdr */
        req_packet.ethhdr.h_proto = __cpu_to_be16(ETH_P_ARP);
        memcpy(req_packet.ethhdr.h_source, mac, ETHER_ADDR_LEN);
        memset(req_packet.ethhdr.h_dest, 0xff, ETHER_ADDR_LEN);  // broadcast
    }

    {
        /* 2. arphdr */
        req_packet.arphdr.arp_hd = __cpu_to_be16(ETH_P_802_3);
        req_packet.arphdr.arp_pr = __cpu_to_be16(ETH_P_IP);
        req_packet.arphdr.arp_hdl = ETHER_ADDR_LEN;
        req_packet.arphdr.arp_prl = INET_ADDR_LEN;
        req_packet.arphdr.arp_op = __cpu_to_be16(ARPOP_REQUEST);
        memcpy(&req_packet.arphdr.arp_sha, mac, ETHER_ADDR_LEN);
        inet_pton(AF_INET, DEVICE_IP, req_packet.arphdr.arp_spa);
        memset(req_packet.arphdr.arp_dha, 0xff, ETHER_ADDR_LEN);
        inet_pton(AF_INET, TARGET_IP, req_packet.arphdr.arp_dpa);
    }

    printf("Packet ARP Request 0.1\n");
    print_arp_packet(&req_packet);

    ASSERT(write(tapfd, &req_packet, sizeof(struct arp_packet)) < 0, "write packet");

    while (1) {
        __u8 pckt_buf[1500];  // packet place holder, for MTU size of 1500
        ASSERT(read(tapfd, pckt_buf, sizeof(pckt_buf)) < 0, "read packet");

        // Drop everything but ARP packets
        if (((struct ethhdr *)pckt_buf)->h_proto != __cpu_to_be16(ETH_P_ARP)) continue;

        struct arp_packet *rep_packet = (struct arp_packet *)pckt_buf;

        printf("Packet ARP Reply 0.2\n");
        print_arp_packet(rep_packet);
        break;
    }
}

int main(void)
{
    struct ifreq ifr;
    strcpy(ifr.ifr_name, DEVICE);
    ifr.ifr_flags = IFF_NO_PI | IFF_TAP;  // raw eth packet, no metadata

    int tapfd = open("/dev/net/tun", O_RDWR);
    ASSERT(tapfd < 0, "tap open");
    ASSERT(ioctl(tapfd, TUNSETIFF, &ifr) < 0, "tap ioctl");
    ASSERT(ioctl(tapfd, SIOCGIFHWADDR, &ifr) < 0, "tap hwaddr");
    print_mac((__u8 *)ifr.ifr_hwaddr.sa_data);

    if (MODE) req_n_wait(tapfd, (__u8 *)ifr.ifr_hwaddr.sa_data);
    else wait_n_reply(tapfd, (__u8 *)ifr.ifr_hwaddr.sa_data);

    close(tapfd);
}
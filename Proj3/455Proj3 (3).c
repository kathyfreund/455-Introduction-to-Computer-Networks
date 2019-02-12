#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h> 

#define SEND 0
#define RECV 1


#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

#define debug(x...) printf(x);printf("\n");
#define info(x...) printf(x);printf("\n");
#define warn(x...) printf(x);printf("\n");
#define err(x...) printf(x);printf("\n");

struct arp_hdr {
    uint16_t ar_hrd;
    uint16_t ar_pro;
    unsigned char ar_hln;
    unsigned char ar_pln;
    uint16_t ar_op;
    unsigned char ar_sha[6];
    unsigned char ar_sip[4];
    unsigned char ar_tha[6];
    unsigned char ar_tip[4];
};


int int_ip4(struct sockaddr *addr, uint32_t *ip)
{
    if (addr->sa_family == AF_INET) 
    {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        *ip = i->sin_addr.s_addr;
        return 0;
    } 
    else 
    {
        err("Not AF_INET");
        return 1;
    }
}


int format_ip4(struct sockaddr *addr, char *out)
{
    if (addr->sa_family == AF_INET) 
    {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        const char *ip = inet_ntoa(i->sin_addr);
        if (!ip) 
        {
            return -2;
        } 
        else 
        {
            strcpy(out, ip);
            return 0;
        }
    } 
    else 
    {
        return -1;
    }
}

int get_if_ip4(int fd, const char *ifname, uint32_t *ip) 
{
    int err = -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    if (strlen(ifname) > (IFNAMSIZ - 1)) 
    {
        err("Too long interface name");
        goto out;
    }

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) 
    {
        perror("SIOCGIFADDR");
        goto out;
    }

    if (int_ip4(&ifr.ifr_addr, ip)) 
    {
        goto out;
    }
    err = 0;
out:
    return err;
}

int send_arp(int fd, int ifindex, const unsigned char *src_mac, uint32_t src_ip, uint32_t dst_ip)
{
    int err = -1;
    unsigned char buffer[BUF_SIZE];
    memset(buffer, 0, sizeof(buffer));

    struct sockaddr_ll socket_address;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_BROADCAST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    struct ethhdr *send_req = (struct ethhdr *) buffer;
    struct arp_hdr *arp_req = (struct arp_hdr *) (buffer + ETH2_HEADER_LEN);
    int index;
    ssize_t ret, length = 0;

    memset(send_req->h_dest, 0xff, MAC_LENGTH);
    memset(arp_req->ar_tha, 0x00, MAC_LENGTH);
    memcpy(send_req->h_source, src_mac, MAC_LENGTH);
    memcpy(arp_req->ar_sha, src_mac, MAC_LENGTH);
    memcpy(socket_address.sll_addr, src_mac, MAC_LENGTH);

    send_req->h_proto = htons(ETH_P_ARP);

    arp_req->ar_hrd = htons(HW_TYPE);
    arp_req->ar_pro = htons(ETH_P_IP);
    arp_req->ar_hln = MAC_LENGTH;
    arp_req->ar_pln = IPV4_LENGTH;
    arp_req->ar_op = htons(ARP_REQUEST);

    debug("Copy IP address to arp_req");
    memcpy(arp_req->ar_sip, &src_ip, sizeof(uint32_t));
    memcpy(arp_req->ar_tip, &dst_ip, sizeof(uint32_t));

    ret = sendto(fd, buffer, 42, 0, (struct sockaddr *) &socket_address, sizeof(socket_address));
    if (ret < 0) 
    {
        perror("sendto():");
        goto out;
    }
    err = 0;
out:
    return err;
}


int get_if_info(const char *ifname, uint32_t *ip, char *mac, int *ifindex)
{
    debug("get_if_info for %s", ifname);
    int err = -1;
    struct ifreq ifr;
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sd <= 0) 
    {
        perror("socket()");
        goto out;
    }
    if (strlen(ifname) > (IFNAMSIZ - 1)) 
    {
        printf("Too long interface name, MAX=%i\n", IFNAMSIZ - 1);
        goto out;
    }

    strcpy(ifr.ifr_name, ifname);
    
    if (ioctl(sd, SIOCGIFINDEX, &ifr) < 0) //assign socket to device
	{
    		perror("SIOCGIFINDEX");
            goto out;
    }   
    *ifindex = ifr.ifr_ifindex;
    printf("interface index is %d\n", *ifindex);

    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) 
    {
        perror("SIOCGIFINDEX");
        goto out;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

    if (get_if_ip4(sd, ifname, ip)) 
    {
        goto out;
    }
    debug("get_if_info OK");

    err = 0;
out:
    if (sd > 0) 
    {
        debug("Clean up temporary socket");
        close(sd);
    }
    return err;
}

int bind_arp(int ifindex, int *fd)
{
    debug("bind_arp: ifindex=%i", ifindex);
    int ret = -1;

    *fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (*fd < 1) 
    {
        perror("socket()");
        goto out;
    }

    debug("Binding to ifindex %i", ifindex);
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    if (bind(*fd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) 
    {
        perror("bind");
        goto out;
    }

    ret = 0;
out:
    if (ret && *fd > 0) 
    {
        debug("Cleanup socket");
        close(*fd);
    }
    return ret;
}

int read_arp(int fd)
{
    debug("read_arp");
    int ret = -1;
    unsigned char buffer[BUF_SIZE];
    ssize_t length = recvfrom(fd, buffer, BUF_SIZE, 0, NULL, NULL);
    int index;
    if (length < 0) 
    {
        perror("recvfrom()");
        goto out;
    }
    struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
    struct arp_hdr *arp_resp = (struct arp_hdr *) (buffer + ETH2_HEADER_LEN);
    if (ntohs(rcv_resp->h_proto) != PROTO_ARP) 
    {
        debug("Not an ARP packet");
        goto out;
    }
    if (ntohs(arp_resp->ar_op) != ARP_REPLY) 
    {
        debug("Not an ARP reply");
        goto out;
    }
    debug("received ARP len=%ld", length);
    struct in_addr sender_a;
    memset(&sender_a, 0, sizeof(struct in_addr));
    memcpy(&sender_a.s_addr, arp_resp->ar_sip, sizeof(uint32_t));
    debug("Sender IP: %s", inet_ntoa(sender_a));

    debug("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X",
          arp_resp->ar_sha[0],
          arp_resp->ar_sha[1],
          arp_resp->ar_sha[2],
          arp_resp->ar_sha[3],
          arp_resp->ar_sha[4],
          arp_resp->ar_sha[5]);

    ret = 0;

out:
    return ret;
}

int test_arping(const char *ifname, const char *ip) 
{
    int ret = -1;
    uint32_t dst = inet_addr(ip);
    if (dst == 0 || dst == 0xffffffff) 
    {
        printf("Invalid source IP\n");
        return 1;
    }

    int src;
    int ifindex;
    char mac[MAC_LENGTH];
    if (get_if_info(ifname, &src, mac, &ifindex)) 
    {
        err("get_if_info failed, interface %s not found or no IP set?", ifname);
        goto out;
    }
    int arp_fd;
    if (bind_arp(ifindex, &arp_fd)) 
    {
        err("Failed to bind_arp()");
        goto out;
    }

    if (send_arp(arp_fd, ifindex, mac, src, dst)) 
    {
        err("Failed to send_arp");
        goto out;
    }

    while(1) //wait for reply
    {
        int r = read_arp(arp_fd);
        if (r == 0) 
        {
            info("Got reply, break out");
            break;
        }
    }

    ret = 0;
out:
    if (arp_fd) 
    {
        close(arp_fd);
        arp_fd = 0;
    }
    return ret;
}

int main(int argc, const char **argv)
{
/*
    int ret = -1;
    int correct = 0;
    int mode;

    if (argc > 1)
    {
		if(strncmp(argv[1],"Send", 4)==0)
        {
			if (argc == 6)
            {
				mode=SEND; 
				correct=1;
			}
		}
		else if(strncmp(argv[1],"Recv", 4)==0)
        {
			if (argc == 3)
            {
				mode=RECV;
				correct=1;
			}
		}
	}

    if(!correct)
    {
		fprintf(stderr, "./455Proj3 Send <InterfaceName> <DestIP> <RouterIP> <Message>\n");
		fprintf(stderr, "./455Proj3 Recv <InterfaceName>\n");
		exit(1);
	}

    if(mode == SEND)
    {
        const char *interfaceName = argv[2];
        const char *ip = argv[3];
        return test_arping(interfaceName, ip);
    }
*/
    int ret = -1;
    if (argc != 3) 
    {
        printf("Usage: %s <INTERFACE> <DEST_IP>\n", argv[0]);
        return 1;
    }
    const char *ifname = argv[1];
    const char *ip = argv[2];
    return test_arping(ifname, ip); 
}
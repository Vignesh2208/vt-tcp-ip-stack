

#include "netdev.h"
#include "ip.h"
#include "basic.h"
#include "syshead.h"
#include "utils.h"
#include "skbuff.h"

static struct netdev netdev;
extern int running;

void netdev_init(uint32_t src_ip_addr) {
    print_debug ("Initializing Net-dev !\n");

    srand(time(0)); 

    netdev.src_ip_addr = ntohl(src_ip_addr);
    netdev.mtu = 1500;
    //netdev.raw_sock_fd = socket (AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_TCP);
    netdev.raw_sock_fd = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);

    int one = 1;
    const int *val = &one;
    if(netdev.raw_sock_fd == -1) {
        //socket creation failed, may be because of non-root privileges
        perror("Netdev: Failed to create raw socket !");
        exit(1);
    }
    if(setsockopt(netdev.raw_sock_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("Netdev: raw socket setsockopt() error !");
        exit(1);
    }

    int fwmark;
    fwmark = 40;
    if(-1 == setsockopt(netdev.raw_sock_fd, SOL_SOCKET, SO_MARK, &fwmark, sizeof (fwmark))) {
        perror("failed setting mark for raw socket packets");
    }
    ip_init(ntohl(src_ip_addr));
    
    netdev.initialized = 1;
    print_debug ("Net-dev initialized !\n");
}

int netdev_transmit(struct sk_buff *skb, struct sockaddr_in * skaddr) {
    int ret = 0;
    assert(netdev.initialized == 1);
    if ((ret = sendto (netdev.raw_sock_fd, (char *)skb->data, skb->len, 0, 
                skaddr, sizeof (struct sockaddr_in)) < 0)) {
        perror ("Send-to Failed !\n");
	}
    return ret;
}

static int netdev_receive(struct sk_buff *skb) {
    ip_rcv(skb);
    return 0;
}

void * netdev_rx_loop() {
    assert (netdev.initialized == 1);
    int packet_size = -1;
    struct sk_buff *skb;
    while (1) {

        if (packet_size <= 0)
            skb = alloc_skb(BUFLEN);
        
        packet_size = recvfrom(
            netdev.raw_sock_fd , (char *)skb->data , BUFLEN , 0 , NULL, NULL);

        if (!running && !num_active_sockets()) {
            free_skb(skb);
            break;
        }

        if (packet_size <= -1) {
            memset(skb->data, 0, BUFLEN);
            packet_size = 1;
            usleep(1000);

            
        } else {
            netdev_receive(skb);
            packet_size = 0;
        }
    }

    return NULL;
}

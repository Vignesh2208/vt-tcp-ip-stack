#ifndef NETDEV_H
#define NETDEV_H
#include "syshead.h"
#include "skbuff.h"
#include "utils.h"

#define BUFLEN 1600
#define MAX_ADDR_LEN 32

#define netdev_dbg(fmt, args...)                \
    do {                                        \
        print_debug("NETDEV: "fmt, ##args);     \
    } while (0)

struct netdev {
    uint32_t src_ip_addr;
    uint32_t mtu;
    int raw_sock_fd;
    int initialized;
};

void netdev_init(uint32_t src_ip_addr);
int netdev_transmit(struct sk_buff *skb, struct sockaddr_in * skaddr);
void *netdev_rx_loop();
#endif

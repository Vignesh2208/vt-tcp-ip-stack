#include "syshead.h"
#include "skbuff.h"
#include "utils.h"
#include "ip.h"
#include "tcp.h"
#include "netdev.h"



void ip_send_check(struct iphdr *ihdr) {
    uint32_t csum = checksum(ihdr, ihdr->ihl * 4, 0);
    ihdr->csum = csum;
}

int ip_output(struct vsock *sk, struct sk_buff *skb) {
    return ip_output_daddr(skb, sk->daddr);
}

int ip_output_daddr(struct sk_buff *skb, uint32_t daddr) {

    struct iphdr *ihdr = ip_hdr(skb);
    struct tcphdr * thdr = tcp_hdr(skb);
    skb_push(skb, IP_HDR_LEN);
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
	sin.sin_port = htons(thdr->dport);
	sin.sin_addr.s_addr = htonl(daddr);

    ihdr->version = IPV4;
    ihdr->ihl = 0x05;
    ihdr->tos = 0x0;
    /*if (thdr->rst)
        ihdr->tos = 0x0;
    else
        ihdr->tos = 0x10;
    */

    ihdr->len = skb->len;
    ihdr->id = ihdr->id;
    ihdr->frag_offset = (uint16_t)0x4000;
      

    ihdr->ttl = 64;
    ihdr->proto = skb->protocol;
    ihdr->saddr = get_my_src_ip();
    ihdr->daddr = daddr;
    ihdr->csum = 0;

    ihdr->len = htons(ihdr->len);
    ihdr->id = htons(ihdr->id);
    ihdr->daddr = htonl(ihdr->daddr);
    ihdr->saddr = htonl(ihdr->saddr);
    ihdr->frag_offset = htons(ihdr->frag_offset);
    ip_send_check(ihdr);
    ip_out_dbg(ihdr);
    

    return netdev_transmit(skb, &sin);
}

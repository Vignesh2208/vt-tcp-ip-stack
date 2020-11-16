#ifndef _SOCK_H
#define _SOCK_H

#include "socket.h"
#include "wait.h"
#include "skbuff.h"

struct vsock;

// protocol specific socket ops
struct net_ops {
    struct vsock* (*alloc_sock) (int protocol);
    int (*init) (struct vsock *sk);
    int (*connect) (struct vsock *sk, const struct sockaddr *addr, int addr_len, int flags);
    int (*disconnect) (struct vsock *sk, int flags);
    int (*write) (struct vsock *sk, const void *buf, int len);
    int (*read) (struct vsock *sk, void *buf, int len);
    int (*recv_notify) (struct vsock *sk);
    int (*close) (struct vsock *sk);
    int (*abort) (struct vsock *sk);
    
	int (*set_port)(struct vsock *sk, unsigned short port);
	int (*listen)(struct vsock *sk, int backlog);
	struct vsock *(*accept)(struct vsock * sk);
};

struct vsock {
    struct vsocket *sock;
    struct net_ops *ops;
    void * proto_sock;
    struct wait_lock send_wait;
    struct wait_lock recv_wait;
    struct wait_lock accept_wait;
    struct sk_buff_head receive_queue;
    struct sk_buff_head write_queue;
    int protocol;
    int state;
    int err;
    short int poll_events;
    uint16_t sport;
    uint16_t dport;
    uint32_t saddr;
    uint32_t daddr;
};

static inline struct sk_buff *write_queue_head(struct vsock *sk) {
    return skb_peek(&sk->write_queue);
}


struct vsock *sk_alloc(struct net_ops *ops, int protocol);
void sock_free(struct vsock *sk);
void sock_init_data(struct vsocket *sock, struct vsock *sk);
void sock_connected(struct vsock *sk);

#endif


#ifndef _INET_H
#define _INET_H

#include "syshead.h"
#include "socket.h"
#include "skbuff.h"

#ifdef DEBUG
#define DEBUG_SOCKET
#endif

#ifdef DEBUG_SOCKET
#define inet_dbg(sock, msg, ...)                                            \
    do {                                                                \
        socket_dbg(sock, "INET "msg, ##__VA_ARGS__);                    \
    } while (0)
#else
#define inet_dbg(msg, th, ...)
#endif

int inet_create(struct vsocket *sock, int protocol);
int inet_write(struct vsocket *sock, const void *buf, int len);
int inet_read(struct vsocket *sock, void *buf, int len);
int inet_close(struct vsocket *sock);
int inet_free(struct vsocket *sock);
int inet_abort(struct vsocket *sock);
int inet_getpeername(struct vsocket *sock, struct sockaddr *restrict address,
                     socklen_t *restrict address_len);
int inet_getsockname(struct vsocket *sock, struct sockaddr *restrict address,
                     socklen_t *restrict address_len);

int inet_listen(struct vsocket * sock, int backlog);
int inet_bind(struct vsocket * sock, struct sockaddr * sockaddr);
struct vsocket * inet_accept(struct vsocket *sock, int * err, struct sockaddr *skaddr);

struct vsock *inet_lookup(struct sk_buff *skb,
                          uint32_t saddr, uint32_t daddr,
                          uint16_t sport, uint16_t dport);
#endif

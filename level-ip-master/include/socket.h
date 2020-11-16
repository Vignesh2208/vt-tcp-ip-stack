#ifndef SOCKET_H_
#define SOCKET_H_

#include "syshead.h"
#include "sock.h"
#include "wait.h"
#include "list.h"
#include <pthread.h>

#ifdef DEBUG
#define DEBUG_SOCKET
#endif

#ifdef DEBUG_SOCKET
#define socket_dbg(sock, msg, ...)                                      \
    do {                                                                \
        print_debug("Socket fd %d state %d sk_state %d flags %d poll %d sport %d dport %d " \
                    "recv-q %d send-q %d: "msg,    \
                    sock->fd, sock->state, sock->sk->state, sock->flags, \
                    sock->sk->poll_events,                              \
                    sock->sk->sport, sock->sk->dport, \
                    sock->sk->receive_queue.qlen, \
                    sock->sk->write_queue.qlen, ##__VA_ARGS__);         \
    } while (0)
#else
#define socket_dbg(sock, msg, ...)
#endif

struct vsocket;

enum socket_state {
    SS_FREE = 0,                    /* not allocated                */
    SS_UNCONNECTED,                 /* unconnected to any socket    */
    SS_CONNECTING,                  /* in process of connecting     */
    SS_CONNECTED,                   /* connected to socket          */
    SS_DISCONNECTING                /* in process of disconnecting  */
};

struct vsock_type {
    struct vsock_ops *sock_ops;
    struct net_ops *net_ops;
    int type;
    int protocol;
};

struct vsock_ops {
    int (*connect) (struct vsocket *sock, const struct sockaddr *addr,
                    int addr_len, int flags);
    int (*write) (struct vsocket *sock, const void *buf, int len);
    int (*read) (struct vsocket *sock, void *buf, int len);
    int (*close) (struct vsocket *sock);
    int (*free) (struct vsocket *sock);
    int (*abort) (struct vsocket *sock);
    int (*poll) (struct vsocket *sock);
    int (*getpeername) (struct vsocket *sock, struct sockaddr *restrict addr,
                        socklen_t *restrict address_len);
    int (*getsockname) (struct vsocket *sock, struct sockaddr *restrict addr,
                        socklen_t *restrict address_len);
    struct vsocket * (*accept)(struct vsocket *sock, int * err,
                               struct sockaddr *skaddr);
	int (*listen)(struct vsocket * sock, int backlog);
	int (*bind)(struct vsocket * sock, struct sockaddr * sockaddr);
};

struct net_family {
    int (*create) (struct vsocket *sock, int protocol);    
};

struct vsocket {
    struct list_head list;
    int fd;
    int refcnt;
    int active;
    enum socket_state state;

    short type;
    int flags;
    uint32_t send_buf_size;
    uint32_t rcv_buf_size;
    struct vsock *sk;
    struct vsock_ops *ops;
    struct wait_lock sleep;
    pthread_rwlock_t lock;
};

int _socket(int domain, int type, int protocol);
int _connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int _write(int sockfd, const void *buf, const unsigned int count);
int _read(int sockfd, void *buf, const unsigned int count);
int _close(int sockfd);
int _poll(struct pollfd fds[], nfds_t nfds);
int _fcntl(int fildes, int cmd, ...);
int _getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen);
int _setsockopt(int sockfd, int level, int option_name,
                const void *option_value, socklen_t option_len);
int _getpeername(int socket, struct sockaddr *restrict address,
                 socklen_t *restrict address_len);
int _getsockname(int socket, struct sockaddr *restrict address,
                 socklen_t *restrict address_len);
int _listen(int socket, int backlog);
int _bind(int socket, struct sockaddr *skaddr);
int _accept(int socket, struct sockaddr *skaddr) ;

struct vsocket *socket_lookup(uint32_t saddr, uint32_t daddr,
                              uint16_t sport, uint16_t dport);
struct vsocket *socket_find(struct vsocket *sock);


int socket_rd_acquire(struct vsocket *sock);
int socket_wr_acquire(struct vsocket *sock);

static inline void inc_socket_ref(struct vsocket *sock) {
    sock->refcnt ++;
}

static inline void dec_socket_ref(struct vsocket *sock) {
    sock->refcnt --;
}

int num_active_sockets();
int socket_release(struct vsocket *sock);
int socket_free(struct vsocket *sock);
int schedule_socket_delete(struct vsocket *sock);
struct vsocket *alloc_socket();

void add_vsocket_to_list(struct vsocket * sock);

void abort_sockets();
void socket_debug();

#endif

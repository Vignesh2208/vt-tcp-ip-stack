#include "syshead.h"
#include "utils.h"
#include "socket.h"
#include "inet.h"
#include "wait.h"
#include "timer.h"
#include "tcp.h"

static int sock_amount = 0;
static int fd = 4097;
static LIST_HEAD(sockets);

// Lock to control allocation of file descriptors and appending allocated vsockets
// to a global list of sockets.
static pthread_rwlock_t slock = PTHREAD_RWLOCK_INITIALIZER;

extern struct net_family inet;

static struct net_family *families[128] = {
    [AF_INET] = &inet,
};

//! Allocates a vsocket and associates a file-descriptor with it. Socket
//  state is initially set to unconnected. Sets socket refcnt to 1
struct vsocket *alloc_socket() {
    // TODO: Figure out a way to not shadow kernel file descriptors.
    // Now, we'll just expect the fds for a process to never exceed this.
    
    struct vsocket *sock = malloc(sizeof (struct vsocket));
    list_init(&sock->list);
    sock->refcnt = 0;
    sock->active = 1;
    sock->send_buf_size = 8192; // linux: default 8kb
    sock->rcv_buf_size = 87380; // linux default 
    pthread_rwlock_wrlock(&slock);
    sock->fd = fd++;
    pthread_rwlock_unlock(&slock);

    sock->state = SS_UNCONNECTED;
    sock->ops = NULL;
    sock->flags = O_RDWR;
    wait_init(&sock->sleep);
    pthread_rwlock_init(&sock->lock, NULL);
    
    return sock;
}

//! Acquires read lock on vsocket
int socket_rd_acquire(struct vsocket *sock) {
    int rc = pthread_rwlock_wrlock(&sock->lock);
    sock->refcnt++;
    return rc;
}

//! Acquires write lock on vsocket
int socket_wr_acquire(struct vsocket *sock) {
    int rc = pthread_rwlock_wrlock(&sock->lock);
    sock->refcnt++;
    return rc;
}

//! Attempts to free a vsocket if nothing references it.
int socket_release(struct vsocket *sock) {
    int rc = 0;
    sock->refcnt--;
    rc = pthread_rwlock_unlock(&sock->lock);

    if (sock->refcnt == 0 && !sock->active) {
        printf ("Freeing socket: %d\n", sock->fd);
        sock->ops->free(sock);
        free(sock);
    }
    return rc;
}

//! Returns number of active sockets
int num_active_sockets() {
    pthread_rwlock_wrlock(&slock);
    int ret = sock_amount;
    pthread_rwlock_unlock(&slock);
    return ret;
}


//! Frees the vsocket and removes it from list of active vsockets.
int socket_free(struct vsocket *sock) {
   
    
    pthread_rwlock_wrlock(&slock);
    socket_wr_acquire(sock);
    list_del(&sock->list);
    sock_amount--;
    sock->active = 0;
    pthread_rwlock_unlock(&slock);

    // triggers wake-up of any process which might still be waiting on
    // sleep condition variable (only processes in connect syscall may be)
    // waiting. vsocket state would have been set to SS_DISCONNECTING
    wait_free(&sock->sleep);
    socket_release(sock);
    
    return 0;
}

//! Called after timer expiry to completely free a socket
static void *socket_garbage_collect(void *arg) {
    struct vsocket *sock = socket_find((struct vsocket *)arg);
    
    if (sock == NULL) 
        return NULL;
    
    socket_free(sock);

    return NULL;
}

//! Sets socket state to disconnecting and starts a one-shot timer to garbage
//  collect the socket after some-time. This is done to give enough time to
//  any waiting processes to resume.
int schedule_socket_delete(struct vsocket *sock) {
    int rc = 0;
    if (sock->state == SS_DISCONNECTING) goto out;
    sock->state = SS_DISCONNECTING;
    timer_oneshot(0, &socket_garbage_collect, sock);

out:
    return rc;
}

//! This function is only called if the entire stack is to be free'ed. It is not
//  invoked during normal operation.
void abort_sockets() {
    struct list_head *item, *tmp;
    struct vsocket *sock;
    list_for_each_safe(item, tmp, &sockets) {
        sock = list_entry(item, struct vsocket, list);
        sock->ops->abort(sock);
    }
}

//! Returns a pointer to a vsocket with matching pid and file descriptor.
static struct vsocket *get_socket(uint32_t fd) {
    struct list_head *item;
    struct vsocket *sock = NULL;

    pthread_rwlock_rdlock(&slock);
    list_for_each(item, &sockets) {
        sock = list_entry(item, struct vsocket, list);
        if (sock->fd == fd) goto out;
    }
    
    sock = NULL;

out:
    pthread_rwlock_unlock(&slock);
    return sock;
}

//! Returns a vsocket associated with a tcp socket in established state. A
//  tcp socket in established state would have src-ip, dst-ip, src-port and
//  dst-port all set to valid values.
struct vsocket *tcp_lookup_sock_establish(
                unsigned int src, unsigned int dst,
				unsigned short src_port, unsigned short dst_port) {
    struct list_head *item;
    struct vsocket *sock = NULL;
    struct vsock *sk = NULL;

    pthread_rwlock_rdlock(&slock);
    
    list_for_each(item, &sockets) {
        sock = list_entry(item, struct vsocket, list);

        if (sock == NULL || sock->sk == NULL) continue;
        sk = sock->sk;

        if (sk->saddr == dst && sk->daddr == src && sk->sport == dst_port
            && sk->dport == src_port) {
            goto found;
        }
    }

    sock = NULL;
    found:
    pthread_rwlock_unlock(&slock);
    return sock;
}

//! Returns a vsocket associated with a tcp socket in listen state. A tcp socket
//  in listen state will only have src-ip and src-port set through a prior bind
//  syscall
static struct vsocket *tcp_lookup_sock_listen(unsigned int addr, unsigned int nport)
{
	struct list_head *item;
    struct vsocket *sock = NULL;
    struct vsock *sk = NULL;

    pthread_rwlock_rdlock(&slock);
    
    list_for_each(item, &sockets) {
        sock = list_entry(item, struct vsocket, list);

        if (sock == NULL || sock->sk == NULL) continue;
        sk = sock->sk;

        if (sk->state == TCP_LISTEN && sk->saddr == addr && sk->sport == nport) {
            goto found;
        }
    }

    sock = NULL;
    found:
    pthread_rwlock_unlock(&slock);
    return sock;
}

//! Returns a matching vsocket which is supposed to process a packet. The arguments
//  are extracted from a received packet. The vsocket may be in established or
//  listen state. So we check both.
struct vsocket *socket_lookup(uint32_t saddr, uint32_t daddr,
                              uint16_t sport, uint16_t dport) {
    
    struct vsocket *sock = NULL;
    sock = tcp_lookup_sock_establish(saddr, daddr, sport, dport);
    if (sock)
        return sock;
    sock = tcp_lookup_sock_listen(daddr, dport);
    return sock;
}

//! Checks if the specified argument vsocket is present in the currently tracked
//  list of sockets.
struct vsocket *socket_find(struct vsocket *find) {
    struct list_head *item;
    struct vsocket *sock = NULL;

    pthread_rwlock_rdlock(&slock);
    list_for_each(item, &sockets) {
        sock = list_entry(item, struct vsocket, list);
        if (sock == find) goto out;
    }
    
    sock = NULL;

out:
    pthread_rwlock_unlock(&slock);
    return sock;
}

#ifdef DEBUG_SOCKET
void socket_debug() {
    struct list_head *item;
    struct vsocket *sock = NULL;

    pthread_rwlock_rdlock(&slock);

    list_for_each(item, &sockets) {
        sock = list_entry(item, struct vsocket, list);
        socket_rd_acquire(sock);
        socket_dbg(sock, "");
        socket_release(sock);
    }

    pthread_rwlock_unlock(&slock);
}
#else
void socket_debug() {
    return;
}
#endif


void add_vsocket_to_list(struct vsocket * sock) {
    if (!sock)
        return;
    pthread_rwlock_wrlock(&slock);
    list_add_tail(&sock->list, &sockets);
    sock_amount++;
    pthread_rwlock_unlock(&slock);
}


//! Allocates a vsocket for a given pid and returns its file descriptor
int _socket(int domain, int type, int protocol) {
    struct vsocket *sock;
    struct net_family *family;

    if ((sock = alloc_socket()) == NULL) {
        print_err("Could not alloc socket\n");
        return -1;
    }

    sock->type = type;
    family = families[domain];

    if (!family) {
        print_err("Domain not supported: %d\n", domain);
        goto abort_socket;
    }
    
    if (family->create(sock, protocol) != 0) {
        print_err("Creating domain failed\n");
        goto abort_socket;
    }

    pthread_rwlock_wrlock(&slock);
    list_add_tail(&sock->list, &sockets);
    sock_amount++;
    pthread_rwlock_unlock(&slock);

    socket_rd_acquire(sock);
    int rc = sock->fd;
    socket_release(sock);

    return rc;

abort_socket:
    socket_free(sock);
    return -1;
}

//! Initiates a connect operation on the provided socket file-descriptor to a remote
//  host which is presumably listening on the specified addr.
int _connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    struct vsocket *sock;

    if ((sock = get_socket(sockfd)) == NULL) {
        print_err("Connect: could not find socket (fd %u)\n", sockfd);
        return -EBADF;
    }

    socket_wr_acquire(sock);
    inc_socket_ref(sock);

    int rc = sock->ops->connect(sock, addr, addrlen, 0);
    switch (rc) {
    case -EINVAL:
    case -EAFNOSUPPORT:
    case -ECONNREFUSED:
    case -ETIMEDOUT:
        dec_socket_ref(sock);
        socket_release(sock);
        socket_free(sock);
        break;
    default:
        dec_socket_ref(sock);
        socket_release(sock);
    }
    
    return rc;
}

//! Writes data present in the buffer to a write queue under the hood for the
//  given socket.
int _write(int sockfd, const void *buf, const unsigned int count) {
    struct vsocket *sock;

    if ((sock = get_socket(sockfd)) == NULL) {
        print_err("Write: could not find socket (fd %u)\n", sockfd);
        return -EBADF;
    }

    socket_wr_acquire(sock);
    inc_socket_ref(sock);
    int rc = sock->ops->write(sock, buf, count);
    dec_socket_ref(sock);
    socket_release(sock);

    return rc;
}

//! Reads from an internal receive queue of the socket and populates the specified
//  buffer.
int _read(int sockfd, void *buf, const unsigned int count) {
    struct vsocket *sock;

    if ((sock = get_socket(sockfd)) == NULL) {
        print_err("Read: could not find socket (fd %u)\n", sockfd);
        return -EBADF;
    }

    socket_wr_acquire(sock);
    inc_socket_ref(sock);
    int rc = sock->ops->read(sock, buf, count);
    dec_socket_ref(sock);
    socket_release(sock);

    return rc;
}

//! If the socket is a tcp socket, indicates there is no more data to send to the
//  remote.
int _close(int sockfd) {
    struct vsocket *sock;

    if ((sock = get_socket(sockfd)) == NULL) {
        print_err("Close: could not find socket (fd %u)\n", sockfd);
        return -EBADF;
    }


    socket_wr_acquire(sock);
    inc_socket_ref(sock);
    int rc = sock->ops->close(sock);
    dec_socket_ref(sock);
    socket_release(sock);

    return rc;
}

//! Polling on a list of socket file descriptors. No timeout support
int _poll(struct pollfd fds[], nfds_t nfds) {
    
    int polled = 0;

    for (int i = 0; i < nfds; i++) {
        struct vsocket *sock;
        struct pollfd *poll = &fds[i];
        if ((sock = get_socket(poll->fd)) == NULL) {
            print_err("Poll: could not find socket (fd %u)\n", poll->fd);
            poll->revents |= POLLNVAL;
            return -1;
        }
        socket_rd_acquire(sock);
        inc_socket_ref(sock);
        poll->revents = 0;
        if ((poll->events & POLLIN) || (poll->events & POLLRDNORM)) {
            poll->revents = sock->sk->poll_events & (poll->events | POLLHUP | POLLERR | POLLNVAL);
        }

        if ((poll->events & POLLOUT) || (poll->events & POLLWRNORM)) {
            if (sock->rcv_buf_size - tcp_sk(sock->sk)->rcv_queue_size > 0) {
                // there is some space left in write buffer
                poll->revents |= ((POLLOUT | POLLWRNORM) & (poll->events));
            }
            if (sock->sk->poll_events & POLLOUT) {
                    poll->revents |= sock->sk->poll_events;
            }
        }
        dec_socket_ref(sock);
        socket_release(sock);

        if (poll->revents > 0) {
            polled++;
        }
    }

    return polled;
}

//! Control flags associated with a socket
int _fcntl(int sockfd, int cmd, ...) {
    struct vsocket *sock;

    if ((sock = get_socket(sockfd)) == NULL) {
        print_err("Fcntl: could not find socket (fd %u)\n", sockfd);
        return -EBADF;
    }

    socket_wr_acquire(sock);
    inc_socket_ref(sock);
    va_list ap;
    int rc = 0;

    switch (cmd) {
    case F_GETFL:
        rc = sock->flags;
        goto out;
    case F_SETFL:
        va_start(ap, cmd);
        sock->flags = va_arg(ap, int);
        va_end(ap);
        rc = 0;
        goto out;
    default:
        rc = -1;
        goto out;
    }

    rc = -1;

out:
    dec_socket_ref(sock);
    socket_release(sock);
    return rc;
}

//! Returns a previously set socket option value
int _getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
    struct vsocket *sock;

    if ((sock = get_socket(sockfd)) == NULL) {
        print_err("Getsockopt: could not find socket (fd %u)\n", fd);
        return -EBADF;
    }

    if (!optval)
        return -EINVAL;

    if (level != SOL_SOCKET)
        return -EPROTONOSUPPORT;


    int rc = 0;

    socket_rd_acquire(sock);
    inc_socket_ref(sock);
    
    switch (optname) {
        case SO_ERROR:
            *optlen = 4;
            *(int *)optval = sock->sk->err;
            rc = 0;
            break;
        case SO_SNDBUF:
            *(int *)optval = sock->send_buf_size;
            break;
        case SO_RCVBUF:
            *(int *)optval = sock->rcv_buf_size;
            break;
        default:
            print_err("Getsockopt unsupported optname %d\n", optname);
            rc =  -ENOPROTOOPT;
            break;
    }
        
    dec_socket_ref(sock);
    socket_release(sock);

    return rc;
}

int _setsockopt(int sockfd, int level, int option_name,
                const void *option_value, socklen_t option_len) {
    struct vsocket *sock;
    if (level != SOL_SOCKET)
        return -EPROTONOSUPPORT;
    if ((sock = get_socket(sockfd)) == NULL) {
        print_err("Setsockopt: could not find socket (fd %u)\n", sockfd);
        return -EBADF;
    }

    if (!option_value)
        return -EINVAL;

    int rc = 0;

    socket_rd_acquire(sock);
    inc_socket_ref(sock);
    switch (option_name) {
        case SO_SNDBUF: sock->send_buf_size = *(int *)option_value;
            print_debug ("Sock: %d, SO_SNDBUF set to: %d\n", sockfd, sock->send_buf_size);
            break;
        case SO_RCVBUF: sock->rcv_buf_size = *(int *)option_value;
            print_debug ("Sock: %d, SO_RCVBUF set to: %d\n", sockfd, sock->rcv_buf_size);
            break;
        default:
            print_err("Setsockopt: Unsupported option %d\n", option_name);
            rc = -ENOPROTOOPT;
            break;
    }
    dec_socket_ref(sock);
    socket_release(sock);

    return rc;
    

}

//! Returns the remote client's ip address and port number
int _getpeername(int sockfd, struct sockaddr *restrict address,
                 socklen_t *restrict address_len) {
    struct vsocket *sock;

    if ((sock = get_socket(sockfd)) == NULL) {
        print_err("Getpeername: could not find socket (fd %u)\n", sockfd);
        return -EBADF;
    }

    socket_rd_acquire(sock);
    inc_socket_ref(sock);
    int rc = sock->ops->getpeername(sock, address, address_len);
    dec_socket_ref(sock);
    socket_release(sock);

    return rc;
}

//! Returns this socket's bind ip address and port number
int _getsockname(int sockfd, struct sockaddr *restrict address,
                 socklen_t *restrict address_len){
    struct vsocket *sock;

    if ((sock = get_socket(sockfd)) == NULL) {
        print_err("Getsockname: could not find socket (fd %u)\n", sockfd);
        return -EBADF;
    }

    socket_rd_acquire(sock);
    inc_socket_ref(sock);
    int rc = sock->ops->getsockname(sock, address, address_len);
    dec_socket_ref(sock);
    socket_release(sock);

    return rc;
}

//! If the socket is of type TCP, then it sets its state to TCP_LISTEN
int _listen(int sockfd, int backlog) {
	int err = -1;
    struct vsocket *sock;

    if ((sock = get_socket(sockfd)) == NULL) {
        print_err("Getsockname: could not find socket (fd %u)\n", sockfd);
        return -EBADF;
    }

	if (!sock || backlog < 0)
		goto out;

	socket_wr_acquire(sock);
    inc_socket_ref(sock);
    print_debug ("Invoking inet_listen !\n");
	if (sock->ops)
		err = sock->ops->listen(sock, backlog);
    print_debug ("Finished inet_listen !\n");
    dec_socket_ref(sock);
	socket_release(sock);
out:
	return err;
}

//! Associates the socket with a src-ip and source port
int _bind(int sockfd, struct sockaddr *skaddr) {
	int err = -1;
    struct vsocket *sock;

    if ((sock = get_socket(sockfd)) == NULL) {
        print_err("Getsockname: could not find socket (fd %u)\n", sockfd);
        return -EBADF;
    }

	if (!sock || !skaddr)
		goto out;
	
    socket_wr_acquire(sock);
    inc_socket_ref(sock);
	if (sock->ops)
		err = sock->ops->bind(sock, skaddr);
    dec_socket_ref(sock);
	socket_release(sock);
out:
	return err;
}

//! For a socket in TCP_LISTEN state, it blocks until a successfull connection
//  has been established from a remote client. It returns a new vsocket describing
//  the connection. If the socket is closed before this function returns, then
//  a null pointer is returned.
int _accept(int sockfd, struct sockaddr *skaddr) {
	struct vsocket *newsock = NULL;
    struct vsocket *sock;
	int err = 0;
    if ((sock = get_socket(sockfd)) == NULL) {
        print_err("Getsockname: could not find socket (fd %u)\n", sockfd);
        return -1;
    }
	if (!sock)
		return -1;
	/* real accepting process */
    socket_wr_acquire(sock);
    inc_socket_ref(sock);
    print_debug ("Invoking inet_accept !\n");
	if (sock->ops)
		newsock = sock->ops->accept(sock, &err, skaddr);
    dec_socket_ref(sock);
	socket_release(sock);

    if (!newsock)
        return err;
    else
	    return newsock->fd;
}

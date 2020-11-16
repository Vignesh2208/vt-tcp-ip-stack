#include "syshead.h"
#include "sock.h"
#include "socket.h"

//! Allocates a protocol specific vsock and returns it. This would eventually
//  be associated with a vsocket in the function call below.
struct vsock *sk_alloc(struct net_ops *ops, int protocol) {
    struct vsock *sk;
    sk = ops->alloc_sock(protocol);
    sk->ops = ops;
    return sk;
}

//! Initializes vsocket by coupling a protocol specific vsock to it.
//  Initializes receive and write queues of the protocol specific vsock
void sock_init_data(struct vsocket *sock, struct vsock *sk) {
    sock->sk = sk;
    sk->sock = sock;
    wait_init(&sk->send_wait);
    wait_init(&sk->recv_wait);
    wait_init(&sk->accept_wait);
    skb_queue_init(&sk->receive_queue);
    skb_queue_init(&sk->write_queue);
    sk->poll_events = 0;
    if (sk->ops->init)
        sk->ops->init(sk);
}

//! Dequeues and frees every skb in receive and write queues
void sock_free(struct vsock *sk) {
    skb_queue_free(&sk->receive_queue);
    skb_queue_free(&sk->write_queue);
}

//! This function is called when the three-way handshake to establish a connection
//  is successfull at the client. It wakes up any process waiting on the connect
//  systcall and returns success.
void sock_connected(struct vsock *sk) {
    struct vsocket *sock = sk->sock;
    sock->state = SS_CONNECTED;
    sk->err = 0;
    sk->poll_events = (POLLOUT | POLLWRNORM | POLLWRBAND);
    wait_wakeup(&sock->sleep);
}

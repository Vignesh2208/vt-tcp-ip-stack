#include "syshead.h"
#include "inet.h"
#include "tcp.h"
#include "ip.h"
#include "sock.h"
#include "utils.h"
#include "timer.h"
#include "wait.h"

#ifdef DEBUG_TCP
const char *tcp_dbg_states[] = {
    "TCP_LISTEN", "TCP_SYNSENT", "TCP_SYN_RECEIVED", "TCP_ESTABLISHED", "TCP_FIN_WAIT_1",
    "TCP_FIN_WAIT_2", "TCP_CLOSE", "TCP_CLOSE_WAIT", "TCP_CLOSING", "TCP_LAST_ACK", "TCP_TIME_WAIT",
};
#endif

static pthread_rwlock_t tcplock = PTHREAD_RWLOCK_INITIALIZER;


struct net_ops tcp_ops = {
    .alloc_sock = &tcp_alloc_sock,
    .init = NULL,
    .connect =  &tcp_v4_connect,
    .disconnect = &tcp_disconnect,
    .write = &tcp_write,
    .read = &tcp_read,
    .recv_notify = &tcp_recv_notify,
    .close = &tcp_close,
    .set_port = NULL,
    .abort = &tcp_abort,
    .listen = &tcp_listen,
    .accept = &tcp_accept,
};


//! Sets socket state to TCP_LISTEN. This is usually followed by an accept syscall.
int tcp_listen(struct vsock *sk, int backlog) {
	struct tcp_sock *tsk = tcpsk(sk);
	unsigned int oldstate = sk->state;
	if (!sk->sport)	/* no bind */
		return -1;
	if (backlog > TCP_MAX_BACKLOG)
		return -1;
	if (oldstate != TCP_CLOSE && oldstate != TCP_LISTEN)
		return -1;
	tsk->backlog = backlog;
	sk->state = TCP_LISTEN;
	return 0;
}

//! Wait until the accept syscall request has been successfully served.
int tcp_wait_accept(struct tcp_sock *tsk) {
    print_debug ("Entering tcp wait accept !\n");
    pthread_mutex_lock(&tsk->sk.accept_wait.lock);
    socket_release(tsk->sk.sock);
    int rc = wait_sleep(&tsk->sk.accept_wait);
    pthread_mutex_unlock(&tsk->sk.accept_wait.lock);
    socket_wr_acquire(tsk->sk.sock);
    return rc;
}

//! Block until the accept syscall request is successfully served. This
//  syscall may also be interrupted by close syscall i.e when this socket is
//  closed, this must prematurely return NULL.
struct vsock *tcp_accept(struct vsock *sk) {
	struct tcp_sock *tsk = tcpsk(sk);
	struct tcp_sock *newtsk = NULL;
    
	while (list_empty(&tsk->accept_queue)) {
		if (tcp_wait_accept(tsk) < 0)
			goto out;
        if (tsk->accept_err || sk->err < 0)
            return NULL;
	}
	newtsk = tcp_accept_dequeue(tsk);
	newtsk->parent = TCP_DEAD_PARENT;
out:
	return newtsk ? &newtsk->sk : NULL;
}

//! Removes any sockets temporaily present in the listen queue. These sockets
//  have an associated vsocket but they have not completed a three-way handshake
//  Simply schedule all such sockets for delettion shortly. This function is
//  called upon invoking a close syscall on a socket which is currently in listen
//  state.
void tcp_clear_listen_queue(struct tcp_sock *tsk) {
	struct tcp_sock *ltsk;
    
    if (list_empty(&tsk->listen_queue))
        return;

    while (!list_empty(&tsk->listen_queue)) {
		ltsk = list_first_entry(&tsk->listen_queue, struct tcp_sock, list);
        list_del_init(&ltsk->list);
        // schedule this vsock and its associated vsocket to be deleted
        tcp_done(&ltsk->sk, -ECONNRESET);
	}
	
}

//! Initializes a skb from a tcp header.
static void tcp_init_segment(struct tcphdr *th, struct iphdr *ih, struct sk_buff *skb) {
    th->sport = ntohs(th->sport);
    th->dport = ntohs(th->dport);
    th->seq = ntohl(th->seq);
    th->ack_seq = ntohl(th->ack_seq);
    th->win = ntohs(th->win);
    th->csum = ntohs(th->csum);
    th->urp = ntohs(th->urp);

    /*if (th->win == 0) {
        printf ("ERROR: TCP - window is zero !\n");
    }*/


    skb->seq = th->seq;
    skb->dlen = ip_len(ih) - tcp_hlen(th);
    skb->len = skb->dlen + th->syn + th->fin;
    skb->end_seq = skb->seq + skb->dlen;
    skb->payload = th->data;
}

//! Clears the out-of-order tcp queue associated with the socket.
static void tcp_clear_queues(struct tcp_sock *tsk) {
    skb_queue_free(&tsk->ofo_queue);
}

//! Called by ip layer upon receiving a packet. It looks up the tcp socket for
//  which this packet was intended and triggers the tcp state machine for that
//  socket.
void tcp_in(struct sk_buff *skb) {
    struct vsock *sk;
    struct iphdr *iph;
    struct tcphdr *th;

    iph = ip_hdr(skb);
    th = (struct tcphdr*) iph->data;

    if (th->urg) {
        th->urg = 0;
        th->rst = 1;
    }

    tcp_init_segment(th, iph, skb);
    sk = inet_lookup(skb, iph->saddr, iph->daddr, th->sport, th->dport);
    if (sk == NULL) {
        print_err("No TCP socket for sport %d dport %d\n",
                  th->sport, th->dport);
        free_skb(skb);
        return;
    }

    socket_wr_acquire(sk->sock);
    tcp_in_dbg(th, sk, skb);
    tcp_print_hdr(th);
    tcp_input_state(sk, th, skb);
    socket_release(sk->sock);
}

//! Computes tcp packet checksum
int tcp_udp_checksum(uint32_t saddr, uint32_t daddr, uint8_t proto,
                     uint8_t *data, uint16_t len) {
    uint32_t sum = 0;

    sum += saddr;
    sum += daddr;
    sum += htons(proto);
    sum += htons(len);
    
    return checksum(data, len, sum);
}

//! Computes tcp packet checksum
int tcp_v4_checksum(struct sk_buff *skb, uint32_t saddr, uint32_t daddr) {
    return tcp_udp_checksum(saddr, daddr, IP_TCP, skb->data, skb->len);
}

void tcp_init_sock(struct tcp_sock * tsk) {
    tsk->sk.state = TCP_CLOSE;
    tsk->rmss = 1460;
    tsk->smss = 1460;
    tsk->accept_err = 0;
    tsk->sk.proto_sock = tsk;
    tsk->rto = 200;
    tsk->send_queue_size = 0;
    tsk->chk_pt_rcv_queue_size = 0;
    tsk->chk_pt_send_queue_size = 0;
    tsk->chk_pt_send_skb = NULL;
    skb_queue_init(&tsk->ofo_queue);
    list_init(&tsk->listen_queue);
	list_init(&tsk->accept_queue);
	list_init(&tsk->list);
}

//! Allocates a tcp vsock, initializes its listen queue, accept queue, out-of-order
//  queue and sets its receive and send mss (Maximum segment size)
struct vsock *tcp_alloc_sock() {
    struct tcp_sock *tsk = malloc(sizeof(struct tcp_sock));
    memset(tsk, 0, sizeof(struct tcp_sock));
    tcp_init_sock(tsk);
    return (struct vsock *)&tsk->sk;
}

//! Sets the current state of a tcp vsock's state machine
void __tcp_set_state(struct vsock *sk, uint32_t state) {
    sk->state = state;
}

//! Initialize tcp layer
void tcp_init(uint32_t src_ip_addr) {
    tcplayer.src_ip_addr = src_ip_addr;
    tcplayer.initialized = 1;
};


static uint16_t generate_port() {
    /* TODO:: Generate a proper port */
    static int port = 40000;
    pthread_rwlock_wrlock(&tcplock);
    int copy =  ++port + (timer_get_tick() % 10000);
    pthread_rwlock_unlock(&tcplock);

    return copy;
}

int generate_iss() {
    /* TODO:: Generate a proper ISS */
    /*time_t seconds;
    seconds = time(NULL);
    return (int) (seconds * rand())/3600;*/
    //return UINT32_MAX - 1;
    return 0;
}

//! Initiates a connection to a remote socket at the specified address
int tcp_v4_connect(struct vsock *sk, const struct sockaddr *addr, int addrlen, int flags) {
    uint16_t dport = ((struct sockaddr_in *)addr)->sin_port;
    uint32_t daddr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;

    sk->dport = ntohs(dport);
    sk->sport = generate_port();
    sk->daddr = ntohl(daddr);
    sk->saddr = tcplayer.src_ip_addr; 
    // this sets all the tcb values and sends a syn
    return tcp_connect(sk);
}

int tcp_disconnect(struct vsock *sk, int flags) {
    return 0;
}

//! Invoked upon a call to write to the vsock.
int tcp_write(struct vsock *sk, const void *buf, int len) {
    struct tcp_sock *tsk = tcp_sk(sk);
    int ret = sk->err;
    if (ret != 0) goto out;

    switch (sk->state) {
        // Writes are supported only in two states: TCP_ESTABLISHED AND TCP_CLOSE_WAIT
        case TCP_ESTABLISHED:
        case TCP_CLOSE_WAIT:
            break;
        case TCP_LISTEN:
            ret = -EOPNOTSUPP;
            goto out;
        default:
            ret = -EBADF;
            goto out;
    }
    return tcp_send(tsk, buf, len);    
out: 
    return ret;
}

//! Invoked upon a call to read from the vsock into the user specified buffer.
int tcp_read(struct vsock *sk, void *buf, int len) {
    struct tcp_sock *tsk = tcp_sk(sk);
    int ret = -1;

    switch (sk->state) {

    case TCP_CLOSE:
        ret = -EBADF;
        goto out;

    // We don't support read/write on sockets which are listening
    case TCP_LISTEN:
        ret = -EOPNOTSUPP;
        goto out;

    /* Queue for processing after entering ESTABLISHED state.  If there
       is no room to queue this request, respond with "error:
       insufficient resources". */
    case TCP_SYN_SENT:
    case TCP_SYN_RECEIVED:
    case TCP_ESTABLISHED:
    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
        break;
    case TCP_CLOSE_WAIT:
        /* If no text is awaiting delivery, the RECEIVE will get a
           "error:  connection closing" response.  Otherwise, any remaining
           text can be used to satisfy the RECEIVE. */
        if (!skb_queue_empty(&tsk->sk.receive_queue)) break;
        if (tsk->flags & TCP_FIN) {
            tsk->flags &= ~TCP_FIN;
            return 0;
        }
        break;
    case TCP_CLOSING:
    case TCP_LAST_ACK:
    case TCP_TIME_WAIT:
        ret = sk->err;
        goto out;
    default:
        goto out;
    }
    return tcp_receive(tsk, buf, len);    
out: 
    return ret;
}

//! Called to inform a blocked process that there is something to read now.
int tcp_recv_notify(struct vsock *sk) {
    if (&(sk->recv_wait)) {
        return wait_wakeup(&sk->recv_wait);
    }
    // No recv wait lock
    return -1;
}


//! Called to inform a blocked process that there is space to add to  sned buffer now.
int tcp_send_notify(struct vsock *sk) {
    if (&(sk->send_wait)) {
        return wait_wakeup(&sk->send_wait);
    }
    // No recv wait lock
    return -1;
}

//! Called upon invoking a close syscall. It should
//  Wakeup any blocking process waiting on an accept syscall
//  Remember close only indicates no more sends are allowed on this socket.
//  Receives are still possible until the remote socket is also closed.
int tcp_close(struct vsock *sk) {
    switch (sk->state) {
    /* Respond with "error:  connection closing". */
    case TCP_CLOSE:
    case TCP_CLOSING:
    case TCP_LAST_ACK:
    case TCP_TIME_WAIT:
    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
        sk->err = -EBADF;
        return -1;
    case TCP_LISTEN:
        tcp_clear_listen_queue(tcpsk(sk));
    case TCP_SYN_SENT:
    case TCP_SYN_RECEIVED:
        printf ("ABORTING tcp connection! state: %d, fd = %d\n", sk->state, sk->sock->fd);
        return tcp_done(sk, -ECONNABORTED);
    case TCP_ESTABLISHED:
        /* Queue this until all preceding SENDs have been segmentized, then
           form a FIN segment and send it.  In any case, enter FIN-WAIT-1
           state. */
        tcp_set_state(sk, TCP_FIN_WAIT_1);
        tcp_queue_fin(sk);
        break;
    case TCP_CLOSE_WAIT:
        /* Queue this request until all preceding SENDs have been
           segmentized; then send a FIN segment, enter LAST_ACK state. */
        tcp_set_state(sk, TCP_LAST_ACK);
        tcp_queue_fin(sk);
        break;
    default:
        print_err("Unknown TCP state for close\n");
        return -1;
    }

    return 0;
}

//! Sends a reset to any connected peer and marks the socket as closed.
int tcp_abort(struct vsock *sk) {
    printf ("Calling TCP-Abort ! \n");
    struct tcp_sock *tsk = tcp_sk(sk);
    tcp_send_reset(tsk);
    return tcp_done(sk, -ECONNABORTED);
}

// clears timers and out-of-order queue
// wakes up anything sleeping on connect syscall (inet_stream_connect)
// state will be set accordingly before the wake-up and the syscall return
// value will depend on the state set before invoking tcp_done.
static int tcp_free(struct vsock *sk) {
    struct tcp_sock *tsk = tcp_sk(sk);
    tcp_clear_timers(sk);
    tcp_clear_queues(tsk);
    wait_wakeup(&sk->accept_wait);
    wait_wakeup(&sk->recv_wait);
    wait_wakeup(&sk->send_wait);
    wait_wakeup(&sk->sock->sleep);
    return 0;
}

// sets current tcp-socket state to close and triggers wake-up of any process
// blocked on connect syscall with appropriate error value. Also clears all 
// timers and skbs in out-of-order queues.
int tcp_done(struct vsock *sk, int err) {
    tcp_set_state(sk, TCP_CLOSE);
    tcpsk(sk)->accept_err = 1;
    sk->err = err;
    tcp_free(sk);
    printf ("TCP-done for socket: %d, err: %d\n", sk->sock->fd, err);
    return schedule_socket_delete(sk->sock);
}

void tcp_clear_timers(struct vsock *sk) {
    printf ("Clearing all tcp timers !\n");
    struct tcp_sock *tsk = tcp_sk(sk);
    tcp_stop_rto_timer(tsk);
    tcp_stop_delack_timer(tsk);
    timer_cancel(tsk->keepalive);
    timer_cancel(tsk->linger);
    tsk->linger = NULL;
    tsk->keepalive = NULL;
}

void tcp_stop_rto_timer(struct tcp_sock *tsk) {
    if (tsk) {
        timer_cancel(tsk->retransmit);
        tsk->retransmit = NULL;
        tsk->backoff = 0;
        tsk->rto = 200;
    }
}

void tcp_release_rto_timer(struct tcp_sock *tsk) {
    if (tsk) {
        timer_release(tsk->retransmit);
        tsk->retransmit = NULL;
    }
}

void tcp_stop_delack_timer(struct tcp_sock *tsk) {
    timer_cancel(tsk->delack);
    tsk->delack = NULL;
}

void tcp_release_delack_timer(struct tcp_sock *tsk) {
    timer_release(tsk->delack);
    tsk->delack = NULL;
}

void tcp_handle_fin_state(struct vsock *sk) {
    switch (sk->state) {
    case TCP_CLOSE_WAIT:
        tcp_set_state(sk, TCP_LAST_ACK);
        break;
    case TCP_ESTABLISHED:
        tcp_set_state(sk, TCP_FIN_WAIT_1);
        break;
    }
}

static void *tcp_linger(void *arg) {

    printf ("tcp-linger \n");
    struct vsock *sk = (struct vsock *) arg;
    socket_wr_acquire(sk->sock);
    struct tcp_sock *tsk = tcp_sk(sk);
    tcpsock_dbg("TCP time-wait timeout, freeing TCB", sk);
    timer_cancel(tsk->linger);
    tsk->linger = NULL;
    tcp_done(sk, -ETIMEDOUT);
    socket_release(sk->sock);

    return NULL;
}


static void *tcp_user_timeout(void *arg) {

    printf ("tcp-user timeout !\n");
    struct vsock *sk = (struct vsock *) arg;
    socket_wr_acquire(sk->sock);
    struct tcp_sock *tsk = tcp_sk(sk);
    tcpsock_dbg("TCP user timeout, freeing TCB and aborting conn", sk);

    timer_cancel(tsk->linger);
    tsk->linger = NULL;
    tcp_abort(sk);
    socket_release(sk->sock);
    
    return NULL;
}

void tcp_enter_time_wait(struct vsock *sk) {
    struct tcp_sock *tsk = tcp_sk(sk);
    tcp_set_state(sk, TCP_TIME_WAIT);
    tcp_clear_timers(sk);

    printf ("Adding tcp_linger !\n");
    /* RFC793 arbitrarily defines MSL to be 2 minutes */
    tsk->linger = timer_add(TCP_2MSL, &tcp_linger, sk);
}

void tcp_rearm_user_timeout(struct vsock *sk) {
    struct tcp_sock *tsk = tcp_sk(sk);

    if (sk->state == TCP_TIME_WAIT) return;

    timer_cancel(tsk->linger);
    /* RFC793 set user timeout */
    tsk->linger = timer_add(TCP_USER_TIMEOUT, &tcp_user_timeout, sk);
}

void tcp_rtt(struct tcp_sock *tsk) {
    if (tsk->backoff > 0 || !tsk->retransmit) {
        // Karn's Algorithm: Don't measure retransmissions
        tsk->backoff = 0;
        return;
    }

    // tsk->retransmit->expires - tsk->rto represents timer_tick at which the retransmit
    // timer was started i.e time right after a segment is sent.
    int rtt = timer_get_tick() - (tsk->retransmit->expires - tsk->rto);

    if (rtt < 0) return;

    if (!tsk->srtt) {
        // RFC6298 2.2 first measurement is made
        tsk->srtt = rtt;
        tsk->rttvar = rtt / 2;
    } else {
        // RFC6298 2.3 a subsequent measurement is made
        double beta = 0.25;
        double alpha = 0.125;
        tsk->rttvar = (1 - beta) * tsk->rttvar + beta * abs(tsk->srtt - rtt);
        tsk->srtt = (1 - alpha) * tsk->srtt + alpha * rtt;
    }

    int k = 4 * tsk->rttvar;

    // RFC6298 says RTO should be at least 1 second. Linux uses 200ms
    if (k < 200) k = 200;

    tsk->rto = tsk->srtt + k;
}

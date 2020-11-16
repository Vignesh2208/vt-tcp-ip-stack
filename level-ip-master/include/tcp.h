#ifndef TCP_H_
#define TCP_H_
#include "syshead.h"
#include "ip.h"
#include "timer.h"
#include "utils.h"
#include "skbuff.h"

#define TCP_HDR_LEN sizeof(struct tcphdr)
#define TCP_DOFFSET sizeof(struct tcphdr) / 4

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

#define TCP_SYN_BACKOFF 500
#define TCP_CONN_RETRIES 0

#define TCP_OPT_NOOP 1
#define TCP_OPTLEN_MSS 4
#define TCP_OPT_MSS 2


#define TCP_2MSL 600
#define TCP_USER_TIMEOUT 180000

#define tcp_sk(sk) ((struct tcp_sock *)sk)
#define tcp_hlen(tcp) (tcp->hl << 2)

#ifdef DEBUG
#define DEBUG_TCP
#endif

#ifdef DEBUG_TCP
extern const char *tcp_dbg_states[];
#define tcp_in_dbg(hdr, sk, skb)                                        \
    do {                                                                \
        print_debug("TCP (in) %u.%u.%u.%u.%u > %u.%u.%u.%u.%u: " \
                    "Flags [S%uA%uP%uF%uR%u], seq %u (len: %u), ack_seq %u, win %u rto %d boff %d header_len %u", \
                    (uint8_t)(sk->daddr >> 24), (uint8_t)(sk->daddr >> 16), (uint8_t)(sk->daddr >> 8), (uint8_t)(sk->daddr >> 0), sk->dport, \
                    (uint8_t)(sk->saddr >> 24), (uint8_t)(sk->saddr >> 16), (uint8_t)(sk->saddr >> 8), (uint8_t)(sk->saddr >> 0), sk->sport, \
                    hdr->syn, hdr->ack, hdr->psh, hdr->fin, hdr->rst, hdr->seq, skb->dlen,         \
                    hdr->ack_seq, hdr->win, tcp_sk(sk)->rto, tcp_sk(sk)->backoff, (uint8_t)hdr->hl); \
    } while (0) 

#define tcp_out_dbg(hdr, sk, skb)                                       \
    do {                                                                \
        print_debug("TCP (out) %u.%u.%u.%u.%u > %u.%u.%u.%u.%u: " \
                    "Flags [S%uA%uP%uF%uR%u], seq %u (len: %u), ack_seq %u, win %u rto %d boff %d header_len %u", \
                    (uint8_t)(sk->saddr >> 24), (uint8_t)(sk->saddr >> 16), (uint8_t)(sk->saddr >> 8), (uint8_t)(sk->saddr >> 0), sk->sport, \
                    (uint8_t)(sk->daddr >> 24), (uint8_t)(sk->daddr >> 16), (uint8_t)(sk->daddr >> 8), (uint8_t)(sk->daddr >> 0), sk->dport, \
                    hdr->syn, hdr->ack, hdr->psh, hdr->fin, hdr->rst, hdr->seq, skb->dlen,         \
                    hdr->ack_seq, hdr->win, tcp_sk(sk)->rto, tcp_sk(sk)->backoff, (uint8_t)hdr->hl); \
    } while (0)

#define tcp_print_hdr(hdr) \
    do { \
        printf("TCP (header) [S%uA%uP%uF%uR%uU%uE%uC%u], sport: %u, dport: %u seq: %u, ack_seq: %u, rsvd: %u, hl: %u, win: %u, urp: %u\n", \
                hdr->syn, hdr->ack, hdr->psh, hdr->fin, hdr->rst, hdr->urg, hdr->ece, hdr->cwr, \
                (uint16_t)hdr->sport, (uint16_t)hdr->dport, (uint32_t)hdr->seq, (uint32_t)hdr->ack_seq, (uint8_t)hdr->rsvd, (uint8_t)hdr->hl, (uint16_t)hdr->win, \
                (uint16_t)hdr->urp); \
    } while (0)

#define tcpsock_dbg(msg, sk)                                            \
    do {                                                                \
        print_debug("TCP (sock) (fd = %u) x:%u > %u.%u.%u.%u.%u (snd_una %u, snd_nxt %u, snd_wnd %u, " \
                    "snd_wl1 %u, snd_wl2 %u, rcv_nxt %u, rcv_wnd %u iss %u irs %u recv-q %d send-q %d " \
                    "rto %d boff %d) state %s: "msg, \
                    sk->sock->fd, sk->sport, (uint8_t)(sk->daddr >> 24), (uint8_t)(sk->daddr >> 16), (uint8_t)(sk->daddr >> 8), (uint8_t)(sk->daddr >> 0), \
                    sk->dport, tcp_sk(sk)->tcb.snd_una,      \
                    tcp_sk(sk)->tcb.snd_nxt, tcp_sk(sk)->tcb.snd_wnd, \
                    tcp_sk(sk)->tcb.snd_wl1, tcp_sk(sk)->tcb.snd_wl2,   \
                    tcp_sk(sk)->tcb.rcv_nxt - tcp_sk(sk)->tcb.irs, tcp_sk(sk)->tcb.rcv_wnd, \
                    tcp_sk(sk)->tcb.iss, tcp_sk(sk)->tcb.irs, \
                    sk->receive_queue.qlen, sk->write_queue.qlen, tcp_sk(sk)->rto, tcp_sk(sk)->backoff, \
                    tcp_dbg_states[sk->state]);                         \
    } while (0)

#define tcp_set_state(sk, state)                                        \
    do {                                                                \
        tcpsock_dbg("state is now "#state, sk);                         \
        __tcp_set_state(sk, state);                                     \
    } while (0)

#define return_tcp_drop(sk, skb)                          \
    do {                                                  \
        tcpsock_dbg("dropping packet", sk);               \
        return __tcp_drop(sk, skb);                       \
    } while (0)

#define tcp_drop(tsk, skb)                      \
    do {                                        \
        tcpsock_dbg("dropping packet", sk);               \
        __tcp_drop(tsk, skb);                   \
    } while (0)

#else
#define tcp_in_dbg(hdr, sk, skb)
#define tcp_out_dbg(hdr, sk, skb)
#define tcp_print_hdr(hdr)
#define tcpsock_dbg(msg, sk)
#define tcp_set_state(sk, state)  __tcp_set_state(sk, state)
#define return_tcp_drop(tsk, skb) return __tcp_drop(tsk, skb)
#define tcp_drop(tsk, skb) __tcp_drop(tsk, skb)
#endif

struct tcphdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t rsvd : 4;
    uint8_t hl : 4;
    uint8_t fin : 1,
            syn : 1,
            rst : 1,
            psh : 1,
            ack : 1,
            urg : 1,
            ece : 1,
            cwr : 1;
    uint16_t win;
    uint16_t csum;
    uint16_t urp;
    uint8_t data[];
} __attribute__((packed));

struct tcp_options {
    uint16_t options;
    uint16_t mss;
};

struct tcp_opt_mss {
    uint8_t kind;
    uint8_t len;
    uint16_t mss;
} __attribute__((packed));

struct tcpiphdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t proto;
    uint16_t tlen;
} __attribute__((packed));

enum tcp_states {
    TCP_LISTEN, /* represents waiting for a connection request from any remote
                   TCP and port. */
    TCP_SYN_SENT, /* represents waiting for a matching connection request
                     after having sent a connection request. */
    TCP_SYN_RECEIVED, /* represents waiting for a confirming connection
                         request acknowledgment after having both received and sent a
                         connection request. */
    TCP_ESTABLISHED, /* represents an open connection, data received can be
                        delivered to the user.  The normal state for the data transfer phase
                        of the connection. */
    TCP_FIN_WAIT_1, /* represents waiting for a connection termination request
                       from the remote TCP, or an acknowledgment of the connection
                       termination request previously sent. */
    TCP_FIN_WAIT_2, /* represents waiting for a connection termination request
                       from the remote TCP. */
    TCP_CLOSE,      /* represents no connection state at all. */
    TCP_CLOSE_WAIT, /* represents waiting for a connection termination request
                       from the local user. */
    TCP_CLOSING,    /* represents waiting for a connection termination request
                       acknowledgment from the remote TCP. */
    TCP_LAST_ACK, /* represents waiting for an acknowledgment of the
                     connection termination request previously sent to the remote TCP
                     (which includes an acknowledgment of its connection termination
                     request). */
    TCP_TIME_WAIT, /* represents waiting for enough time to pass to be sure
                      the remote TCP received the acknowledgment of its connection
                      termination request. */
};

struct tcb {
    uint32_t snd_una; /* oldest unacknowledged sequence number */
    uint32_t snd_nxt; /* next sequence number to be sent */
    uint32_t snd_wnd;
    uint32_t snd_wl1;
    uint32_t snd_wl2;
    uint32_t iss;
    uint32_t rcv_nxt; /* next sequence number expected on an incoming segments, and
                         is the left or lower edge of the receive window */
    uint32_t rcv_wnd;
    uint32_t irs;
};


struct tcp_sock {
    struct vsock sk;
    int fd;
    uint16_t tcp_header_len;
    struct tcb tcb;
    uint8_t flags;
    uint8_t accept_err;
    uint8_t backoff;
    int32_t srtt;
    int32_t rttvar;
    uint32_t rto;
    uint32_t send_queue_size;
    uint32_t rcv_queue_size;
    uint32_t chk_pt_send_queue_size;
    uint32_t chk_pt_rcv_queue_size;
    struct sk_buff * chk_pt_send_skb;
    struct timer *retransmit;
    struct timer *delack;
    struct timer *keepalive;
    struct timer *linger;
    uint8_t delacks;
    uint16_t rmss;
    uint16_t smss;
    uint16_t cwnd;
    uint32_t inflight;
    
    struct sk_buff_head ofo_queue;  /* Out-of-order queue */
    struct tcp_sock *parent;

	int accept_backlog;		        /* current entries of accept queue */
	int backlog;			        /* size of accept queue */
	struct list_head listen_queue;	/* waiting for second SYN+ACK of three-way handshake */
	struct list_head accept_queue;	/* waiting for third ACK of three-way handshake */
	struct list_head list;

    
};

struct tcplayer {
    uint32_t src_ip_addr;
    int initialized;
};

struct tcplayer tcplayer;

#define tcpsk(sk) ((struct tcp_sock *)sk->proto_sock)

static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb) {
    return (struct tcphdr *)(skb->head + IP_HDR_LEN);
}

#define TCP_MAX_BACKLOG		128
#define TCP_DEAD_PARENT		((struct tcp_sock *)0xffffdaed)

#define TCP_F_PUSH		    0x00000001	/* text pushing to user */
#define TCP_F_ACKNOW		0x00000002	/* ack at right */
#define TCP_F_ACKDELAY		0x00000004	/* ack at right */


void tcp_init(uint32_t src_ip_addr);
void tcp_in(struct sk_buff *skb);
void tcp_init_sock(struct tcp_sock * tsk);
int tcp_checksum(struct tcp_sock *sock, struct tcphdr *thdr);
void tcp_select_initial_window(uint32_t *rcv_wnd);

int tcp_listen(struct vsock *sk, int backlog);
struct vsock *tcp_accept(struct vsock *sk);

int generate_iss();
struct vsock *tcp_alloc_sock();
void __tcp_set_state(struct vsock *sk, uint32_t state);
int tcp_v4_checksum(struct sk_buff *skb, uint32_t saddr, uint32_t daddr);
int tcp_v4_connect(struct vsock *sk, const struct sockaddr *addr, int addrlen, int flags);
int tcp_connect(struct vsock *sk);
int tcp_disconnect(struct vsock *sk, int flags);
int tcp_write(struct vsock *sk, const void *buf, int len);
int tcp_read(struct vsock *sk, void *buf, int len);
int tcp_receive(struct tcp_sock *tsk, void *buf, int len);
int tcp_input_state(struct vsock *sk, struct tcphdr *th, struct sk_buff *skb);

int tcp_send_synack_to(struct vsock *sk, struct sk_buff *src_skb);
int tcp_send_synack(struct vsock *sk);
int tcp_send_next(struct vsock *sk);
int tcp_send_ack(struct vsock *sk);
int tcp_send_reset_to(struct tcp_sock *tsk, struct sk_buff *src_skb);
int tcp_send_reset(struct tcp_sock *tsk);
void *tcp_send_delack(void *arg);

int tcp_queue_fin(struct vsock *sk);
int tcp_send(struct tcp_sock *tsk, const void *buf, int len);
int tcp_recv_notify(struct vsock *sk);
int tcp_send_notify(struct vsock *sk);
int tcp_close(struct vsock *sk);
int tcp_abort(struct vsock *sk);
int tcp_done(struct vsock *sk, int err);
void tcp_rtt(struct tcp_sock *tsk);
void tcp_handle_fin_state(struct vsock *sk);
void tcp_enter_time_wait(struct vsock *sk);
void tcp_clear_timers(struct vsock *sk);
void tcp_rearm_rto_timer(struct tcp_sock *tsk);
void tcp_stop_rto_timer(struct tcp_sock *tsk);
void tcp_release_rto_timer(struct tcp_sock *tsk);
void tcp_stop_delack_timer(struct tcp_sock *tsk);
void tcp_release_delack_timer(struct tcp_sock *tsk);
void tcp_rearm_user_timeout(struct vsock *sk);

static inline int tcp_accept_queue_full(struct tcp_sock *tsk) {
	return (tsk->accept_backlog >= tsk->backlog);
}

static inline void tcp_accept_enqueue(struct tcp_sock *tsk) {
	/* move it from listen queue to accept queue */
	if (!list_empty(&tsk->list))
		list_del(&tsk->list);
	list_add(&tsk->list, &tsk->parent->accept_queue);
	tsk->accept_backlog++;
}

static inline struct tcp_sock *tcp_accept_dequeue(struct tcp_sock *tsk) {
	struct tcp_sock *newtsk;
	newtsk = list_first_entry(&tsk->accept_queue, struct tcp_sock, list);
	list_del_init(&newtsk->list);
	tsk->accept_backlog--;
	return newtsk;
}

#endif

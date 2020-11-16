#include "syshead.h"
#include "utils.h"
#include "tcp.h"
#include "ip.h"
#include "skbuff.h"
#include "timer.h"

//static int num_sleeps = 0;

static void *tcp_retransmission_timeout(void *arg);

static struct sk_buff *tcp_alloc_skb(int optlen, int size) {
    int reserved = IP_HDR_LEN + TCP_HDR_LEN + optlen + size;
    struct sk_buff *skb = alloc_skb(reserved);
    skb_reserve(skb, reserved);
    skb->protocol = IP_TCP;
    skb->dlen = size;
    skb->seq = 0;
    skb->txmitted = 0;
    return skb;
}

static int tcp_write_syn_options(struct tcphdr *th, struct tcp_options *opts, int optlen) {
    struct tcp_opt_mss *opt_mss = (struct tcp_opt_mss *) th->data;

    opt_mss->kind = TCP_OPT_MSS;
    opt_mss->len = TCP_OPTLEN_MSS;
    opt_mss->mss = htons(opts->mss);
    th->hl = TCP_DOFFSET + (optlen / 4);
    return 0;
}

static int tcp_syn_options(struct vsock *sk, struct tcp_options *opts) {
    struct tcp_sock *tsk = tcp_sk(sk);
    int optlen = 0;
    opts->mss = tsk->rmss;
    optlen += TCP_OPTLEN_MSS;
    return optlen;
}

// Reads sport, dport, saddr and daddr from socket book-keeping. In other words
// this function may only be used by socket which is aslready connected and only
// if the skb is intended for the destination to which the socket is connected to.
static int tcp_transmit_skb(struct vsock *sk, struct sk_buff *skb, uint32_t seq) {
    struct tcp_sock *tsk = tcp_sk(sk);
    struct tcb *tcb = &tsk->tcb;
    struct tcphdr *thdr = tcp_hdr(skb);

    /* No options were previously set */
    if (thdr->hl == 0) thdr->hl = TCP_DOFFSET;

    skb_push(skb, thdr->hl * 4);

    thdr->sport = sk->sport;
    thdr->dport = sk->dport;

    if (!skb->seqset) {
        thdr->seq = seq;
    }

    thdr->ack_seq = tcb->rcv_nxt;
    thdr->win = min(tcb->rcv_wnd, sk->sock->rcv_buf_size - tsk->rcv_queue_size);
    thdr->rsvd = 0;
    thdr->csum = 0;
    thdr->urp = 0;


    tcp_out_dbg(thdr, sk, skb);
    tcp_print_hdr(thdr);
    tcpsock_dbg("\nTCP (skb) transmit: ", sk);

    // We are forced to do this ugly hack because iptable rules are somehow
    // blocking any actual rst packet from being sent out
    if (thdr->rst) {
        thdr->urg = 1;
        thdr->rst = 0;
    }

    skb->txmitted = 1;
    thdr->sport = htons(thdr->sport);
    thdr->dport = htons(thdr->dport);
    thdr->seq = htonl(thdr->seq);
    thdr->ack_seq = htonl(thdr->ack_seq);
    thdr->win = htons(thdr->win);
    thdr->csum = htons(thdr->csum);
    thdr->urp = htons(thdr->urp);
    thdr->csum = tcp_v4_checksum(skb, htonl(sk->saddr), htonl(sk->daddr));
    
    return ip_output(sk, skb);
}

static int tcp_queue_transmit_skb(struct vsock *sk, struct sk_buff *skb) {
    struct tcp_sock *tsk = tcp_sk(sk);
    struct tcb *tcb = &tsk->tcb;
    struct tcphdr * th = tcp_hdr(skb);
    int rc = 0;
    
    if (skb_queue_empty(&sk->write_queue)) {
        tcp_rearm_rto_timer(tsk);
    }

    
    if (tsk->inflight == 0) {
        /* Store sequence information into the socket buffer */
        rc = tcp_transmit_skb(sk, skb, tcb->snd_nxt);
        tsk->inflight++;
        skb->seq = tcb->snd_nxt;
        tcb->snd_nxt += skb->dlen;
        skb->end_seq = tcb->snd_nxt;

        if (th->fin) tcb->snd_nxt++;
    }
    tsk->send_queue_size += skb->dlen;
    skb_queue_tail(&sk->write_queue, skb);
    return rc;
}


/* Routine for timer-invoked delayed acknowledgment */
void *tcp_send_delack(void *arg) {

    
    struct vsock *sk = (struct vsock *) arg;
    socket_wr_acquire(sk->sock);
    struct tcp_sock *tsk = tcp_sk(sk);
    tsk->delacks = 0;
    tcp_release_delack_timer(tsk);
    tcp_send_ack(sk);
    printf ("tcp-send delack. ack_seq:  %u\n", tsk->tcb.rcv_nxt);
    socket_release(sk->sock);
    return NULL;
}

int tcp_send_next(struct vsock *sk) {
    struct tcp_sock *tsk = tcp_sk(sk);
    struct tcb *tcb = &tsk->tcb;
    struct tcphdr *th;
    struct sk_buff *next;
    struct list_head *item, *tmp;
    int i = 0;

    list_for_each_safe(item, tmp, &sk->write_queue.head) {
        
        next = list_entry(item, struct sk_buff, list);
        if (next == NULL) return -1;

        if (next->txmitted)
            continue;

        if (tcb->snd_nxt + next->dlen >= tcb->snd_una + tcb->snd_wnd)
            break;

        skb_reset_header(next);
        tcp_transmit_skb(sk, next, tcb->snd_nxt);

        next->seq = tcb->snd_nxt;
        tcb->snd_nxt += next->dlen;
        next->end_seq = tcb->snd_nxt;

        i ++;

        th = tcp_hdr(next);
        if (th->fin) tcb->snd_nxt++;
    }
    
    return i;
}

//! Sends a syn with seq=iss, ack_seq=rcv.nxt (ack_seq will be 0 because rcv.nxt is 0)
//  snd.nxt will be set to iss + 1 after this call.
static int tcp_send_syn(struct vsock *sk) {
    if (sk->state != TCP_SYN_SENT && sk->state != TCP_CLOSE && sk->state != TCP_LISTEN) {
        print_err("Socket was not in correct state (closed or listen)\n");
        return 1;
    }

    struct sk_buff *skb;
    struct tcphdr *th;
    struct tcp_options opts = { 0 };
    int tcp_options_len = 0;

    tcp_options_len = tcp_syn_options(sk, &opts);
    skb = tcp_alloc_skb(tcp_options_len, 0);
    th = tcp_hdr(skb);

    skb->seqset = 0;

    tcp_write_syn_options(th, &opts, tcp_options_len);

    sk->state = TCP_SYN_SENT;
    th->syn = 1;


    return tcp_queue_transmit_skb(sk, skb);
}

// This is intended for transmitting to any destination regardless of whether
// the socket is connected to the destination or not.
static int tcp_transmit_skb_to(struct vsock *sk, struct sk_buff *src_skb,
                               struct sk_buff *dst_skb) {
    struct tcp_sock *tsk = tcp_sk(sk);
    struct tcb *tcb = &tsk->tcb;
    struct tcphdr *thdr = tcp_hdr(dst_skb);
    struct tcphdr *sthdr = tcp_hdr(src_skb);

    /* No options were previously set */
    if (thdr->hl == 0) thdr->hl = TCP_DOFFSET;

    assert(dst_skb->seqset == 1);

    skb_push(dst_skb, thdr->hl * 4);

    thdr->sport = sthdr->dport;
    thdr->dport = sthdr->sport;
    thdr->win = min(tcb->rcv_wnd, sk->sock->rcv_buf_size - tsk->rcv_queue_size);
    thdr->csum = 0;
    thdr->urp = 0;
    thdr->rsvd = 0;

    tcp_out_dbg(thdr, sk, dst_skb);
    tcp_print_hdr(thdr);
    tcpsock_dbg("\nTCP (skb) transmit: ", sk);

    if (thdr->rst) {
        thdr->urg = 1;
        thdr->rst = 0;
    }

    dst_skb->txmitted = 1;

    thdr->sport = htons(thdr->sport);
    thdr->dport = htons(thdr->dport);
    thdr->seq = htonl(thdr->seq);
    thdr->ack_seq = htonl(thdr->ack_seq);
    thdr->win = htons(thdr->win);
    thdr->csum = htons(thdr->csum);
    thdr->urp = htons(thdr->urp);
    thdr->csum = tcp_v4_checksum(dst_skb, htonl(ip_hdr(src_skb)->daddr),
        htonl(ip_hdr(src_skb)->saddr));
    
    return ip_output_daddr(dst_skb, ip_hdr(src_skb)->saddr);
}


int tcp_send_reset_to(struct tcp_sock *tsk, struct sk_buff *src_skb) {
    struct tcphdr *sthdr = tcp_hdr(src_skb);
    struct sk_buff *skb;
    struct tcphdr *th;
    int rc = 0;

    if (sthdr->rst)
        return 0;

    skb = tcp_alloc_skb(0, 0);
    th = tcp_hdr(skb);
    th->rst = 1;
    th->hl = TCP_DOFFSET;

    if (sthdr->ack) {
        th->seq = sthdr->ack_seq;
        th->ack = 0;
    } else {
        th->ack = 1;
        th->ack_seq = src_skb->seq + src_skb->len;
        th->seq = 0;
        
    }

    skb->seqset = 1;

    rc = tcp_transmit_skb_to(&tsk->sk, src_skb, skb);
    free_skb(skb);
    return rc;
}

// Send reset with seq=snd.nxt, ack_seq=rcv.nxt
int tcp_send_reset(struct tcp_sock *tsk) {
    struct sk_buff *skb;
    struct tcphdr *th;
    struct tcb *tcb;
    int rc = 0;

    skb = tcp_alloc_skb(0, 0);
    th = tcp_hdr(skb);
    tcb = &tsk->tcb;

    th->rst = 1;
    tcb->snd_una = tcb->snd_nxt;
    skb->seqset = 0;

    rc = tcp_transmit_skb(&tsk->sk, skb, tcb->snd_nxt);
    free_skb(skb);

    return rc;
}


// Send ack with seq=snd.nxt, ack_seq=rcv.nxt
int tcp_send_ack(struct vsock *sk) {
    if (sk->state == TCP_CLOSE) return 0;
    
    struct sk_buff *skb;
    struct tcphdr *th;
    struct tcb *tcb = &tcp_sk(sk)->tcb;
    int rc = 0;

    skb = tcp_alloc_skb(0, 0);
    th = tcp_hdr(skb);
    th->ack = 1;
    th->hl = TCP_DOFFSET;
    skb->seqset = 0;

    rc = tcp_transmit_skb(sk, skb, tcb->snd_nxt);
    free_skb(skb);
    return rc;
}

//! Send syn-ack with seq=iss, ack_seq=rcv.nxt. Read dport and sport from
//  input src_skbuff
int tcp_send_synack_to(struct vsock *sk, struct sk_buff *src_skb) {
	struct tcphdr *sthdr = tcp_hdr(src_skb);
    struct sk_buff *skb;
    struct tcphdr *th;
    struct tcp_sock * tcpsk = tcp_sk(sk);
    int rc = 0;

	if (sthdr->rst)
		return 0;
    skb = tcp_alloc_skb(0, 0);
    th = tcp_hdr(skb);
    th->syn = 1;
    th->ack = 1;
    th->hl = TCP_DOFFSET;
    th->sport = sthdr->dport;
    th->dport = sthdr->sport;
    th->seq = tcpsk->tcb.iss;
    th->ack_seq = tcpsk->tcb.rcv_nxt;
    th->ack = 1;
    th->win = min(tcpsk->tcb.rcv_wnd, sk->sock->rcv_buf_size - tcpsk->rcv_queue_size);
    

    skb->seqset = 1;

    rc = tcp_transmit_skb_to(sk, src_skb, skb);
    free_skb(skb);
    return rc;
}

//! Send syn-ack with seq=iss, ack_seq=rcv.nxt
int tcp_send_synack(struct vsock *sk) {
    if (sk->state != TCP_SYN_SENT && sk->state != TCP_SYN_RECEIVED) {
        print_err("TCP synack: Socket was not in correct state (SYN_SENT or SYN_RECEIVED)\n");
        return 1;
    }

    struct sk_buff *skb;
    struct tcphdr *th;
    struct tcb * tcb = &tcp_sk(sk)->tcb;
    int rc = 0;

    skb = tcp_alloc_skb(0, 0);
    th = tcp_hdr(skb);

    th->syn = 1;
    th->ack = 1;
    th->seq = tcb->iss;
    th->ack_seq = tcb->rcv_nxt;
    th->win = min(tcb->rcv_wnd, sk->sock->rcv_buf_size - tcp_sk(sk)->rcv_queue_size);

    skb->seqset = 1;

    rc = tcp_transmit_skb(sk, skb, tcb->snd_nxt);
    free_skb(skb);

    return rc;
}


void tcp_select_initial_window(uint32_t *rcv_wnd) {
    // default in linux (= 10 x mss)
    *rcv_wnd = 14600;
}

static void tcp_notify_user(struct vsock *sk) {
    switch (sk->state) {
    case TCP_CLOSE_WAIT:
        wait_wakeup(&sk->sock->sleep);
        break;
    }
}

static void *tcp_connect_rto(void *arg) {
    struct tcp_sock *tsk = (struct tcp_sock *) arg;
    struct tcb *tcb = &tsk->tcb;
    struct vsock *sk = &tsk->sk;

    printf ("tcp-connect rto\n");

    socket_wr_acquire(sk->sock);
    tcp_release_rto_timer(tsk);

    if (sk->state == TCP_SYN_SENT) {
        if (tsk->backoff > TCP_CONN_RETRIES) {
            sk->poll_events |= (POLLOUT | POLLERR | POLLHUP);
            tcp_done(sk, -ETIMEDOUT);
        } else {
            struct sk_buff *skb = write_queue_head(sk);

            if (skb) {
                skb_reset_header(skb);
                tcp_transmit_skb(sk, skb, tcb->snd_una);
            
                tsk->backoff++;
                tcp_rearm_rto_timer(tsk);
            }
         }
    } else {
        print_err("TCP connect RTO triggered even when not in SYNSENT\n");
    }

    socket_release(sk->sock);

    return NULL;
}

static void *tcp_retransmission_timeout(void *arg) {

    

    struct tcp_sock *tsk = (struct tcp_sock *) arg;
    
    struct vsock *sk = &tsk->sk;

    socket_wr_acquire(sk->sock);

    tcp_release_rto_timer(tsk);

    struct sk_buff *skb = write_queue_head(sk);

    if (!skb) {
        tsk->backoff = 0;
        tcpsock_dbg("TCP RTO queue empty, notifying user", sk);
        tcp_notify_user(sk);
        goto unlock;
    }

    struct tcphdr *th = tcp_hdr(skb);
    skb_reset_header(skb);
    
    struct tcb *tcb = &tsk->tcb;
    tcp_transmit_skb(sk, skb, tcb->snd_una);

    
    /* RFC 6298: 2.5 Maximum value MAY be placed on RTO, provided it is at least
       60 seconds */
    if (tsk->rto > 60000) {
        sk->poll_events |= (POLLOUT | POLLERR | POLLHUP);
        tcp_done(sk, -ETIMEDOUT);
        socket_release(sk->sock);
        return NULL;
    } else {
        /* RFC 6298: Section 5.5 double RTO time */
        tsk->rto = tsk->rto * 2;
        tsk->backoff++;

        //printf ("tcp-rto: snd_una: %u, rto: %u, backoff: %u\n", tcb->snd_una, tsk->rto, tsk->backoff);


        tsk->retransmit = timer_add(tsk->rto, &tcp_retransmission_timeout, tsk);

        if (th->fin) {
            tcp_handle_fin_state(sk);
        }
    }

unlock:
    socket_release(sk->sock);

    return NULL;
}

void tcp_rearm_rto_timer(struct tcp_sock *tsk) {
    struct vsock *sk = &tsk->sk;
    tcp_release_rto_timer(tsk);

    if (sk->state == TCP_SYN_SENT) {
        tsk->retransmit = timer_add(TCP_SYN_BACKOFF << tsk->backoff, &tcp_connect_rto, tsk);
    } else {
        tsk->retransmit = timer_add(tsk->rto, &tcp_retransmission_timeout, tsk);
    }
}

int tcp_connect(struct vsock *sk) {
    struct tcp_sock *tsk = tcp_sk(sk);
    struct tcb *tcb = &tsk->tcb;
    int rc = 0;
    
    tsk->tcp_header_len = sizeof(struct tcphdr);
    tcb->iss = generate_iss();
    tcb->snd_una = tcb->iss;
    tcb->snd_nxt = tcb->iss;
    tcb->rcv_nxt = tcb->iss;
    tcb->snd_wnd = 0;
    tcb->snd_wl1 = 0;

    tcp_select_initial_window(&tsk->tcb.rcv_wnd);

    rc = tcp_send_syn(sk);
    tcb->snd_nxt++;
    
    return rc;
}

int tcp_send(struct tcp_sock *tsk, const void *buf, int len) {
    struct sk_buff *skb;
    struct tcphdr *th;    
    int slen;
    int mss = tsk->smss;
    int dlen = 0;
    struct vsock *sk = &tsk->sk;
    struct vsocket *sock = sk->sock;

    int curr_space_left;
    int queued_bytes = 0;

    while (queued_bytes < len) {
        if (tsk->sk.sock->send_buf_size < tsk->send_queue_size)
            curr_space_left = 0;
        else
            curr_space_left = tsk->sk.sock->send_buf_size - tsk->send_queue_size;

        slen = min(len - queued_bytes, curr_space_left);
        while (slen > 0) {
            dlen = slen > mss ? mss : slen;
            slen -= dlen;

            skb = tcp_alloc_skb(0, dlen);
            skb_push(skb, dlen);
            memcpy(skb->data, buf, dlen);
            
            buf += dlen;
            queued_bytes += dlen;
            th = tcp_hdr(skb);
            th->ack = 1;

            

            // we will make only send syscall set this.
            if (skb_queue_empty(&sk->write_queue)) {
                th->psh = 1;
            } else {

                if (tsk->inflight) {
                    tsk->chk_pt_send_queue_size += dlen;
                    if (!tsk->chk_pt_send_skb)
                        tsk->chk_pt_send_skb = skb;
                }
            }

            if (tcp_queue_transmit_skb(&tsk->sk, skb) == -1) {
                perror("Error on TCP skb queueing");
            }

        }


        if (queued_bytes < len && curr_space_left == 0) {
            
            if (sock->flags & O_NONBLOCK) {
                if (queued_bytes == 0) {
                    len = -EAGAIN;
                    break;
                } else {
                    len = queued_bytes;
                    break;
                }
            } else {
                // need to wait
                pthread_mutex_lock(&tsk->sk.send_wait.lock);
                socket_release(sock);
                //num_sleeps ++;
                //printf ("Num sleeps : %d\n", num_sleeps);
                print_debug ("SEND: blocked because snd-buffer is full !\n");
                wait_sleep(&tsk->sk.send_wait);
                pthread_mutex_unlock(&tsk->sk.send_wait.lock);
                socket_wr_acquire(sock);
                print_debug ("SEND: resumed because snd-buffer has some empty space!\n");
            }
        }

        if (tsk->sk.err < 0) {
            tcpsock_dbg("Breaking out of tcp-send due to socket error: ", (&tsk->sk));
        }
    }

    if (tsk->sk.err >= 0) {
        tcp_rearm_user_timeout(&tsk->sk); 
        return len;
    } 
    return tsk->sk.err;
}


//! Enqueues a fin. When fin is transmitted seq=snd.nxt, ack_seq=rcv.nxt
//  snd.nxt is incremented after fin is sent.
int tcp_queue_fin(struct vsock *sk) {
    struct sk_buff *skb;
    struct tcphdr *th;
    int rc = 0;

    skb = tcp_alloc_skb(0, 0);
    th = tcp_hdr(skb);

    th->fin = 1;
    th->ack = 1;

    tcpsock_dbg("Queueing fin", sk);
    
    rc = tcp_queue_transmit_skb(sk, skb);

    return rc;
}

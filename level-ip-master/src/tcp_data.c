
#include "syshead.h"
#include "tcp.h"
#include "list.h"


/* Routine for inserting skbs ordered by seq into queue */
static void tcp_data_insert_ordered(
    struct sk_buff_head *queue, struct sk_buff *skb, uint32_t seq_lb, uint32_t seq_ub) {
    struct sk_buff *next;
    struct list_head *item, *tmp;
    int wrap_around = 0;

    
    list_for_each_safe(item, tmp, &queue->head) {
        next = list_entry(item, struct sk_buff, list);

        if (skb->seq > seq_lb || wrap_around) {
            if (skb->seq < next->seq) {
                if (skb->end_seq > next->seq) {
                    /* TODO: We need to join skbs */
                    print_err("Could not join skbs\n");
                } else {
                    skb->refcnt++;
                    skb_queue_add(queue, skb, next);
                    return;
                }
            } else if (skb->seq == next->seq) {
                /* We already have this segment! */
                return;
            }
        } 
        if (next->seq > next->end_seq || next->seq == UINT32_MAX || next->end_seq == UINT32_MAX)
            wrap_around = 1;
    }

    skb->refcnt++;
    skb_queue_tail(queue, skb);
}

/* Routine for transforming out-of-order segments into order */
static void tcp_consume_ofo_queue(struct tcp_sock *tsk) {
    struct vsock *sk = &tsk->sk;
    struct tcb *tcb = &tsk->tcb;
    struct sk_buff *skb = NULL;

    while ((skb = skb_peek(&tsk->ofo_queue)) != NULL
           && tcb->rcv_nxt == skb->seq) {
       /* skb is in-order, put it in receive queue */
       tcb->rcv_nxt += skb->dlen;
       skb_dequeue(&tsk->ofo_queue);
       skb_queue_tail(&sk->receive_queue, skb);
    }
}

int tcp_data_dequeue(struct tcp_sock *tsk, void *user_buf, int userlen) {
    struct vsock *sk = &tsk->sk;
    struct tcphdr *th;
    int rlen = 0;

    while (!skb_queue_empty(&sk->receive_queue) && rlen < userlen) {
        struct sk_buff *skb = skb_peek(&sk->receive_queue);
        if (skb == NULL) break;
        
        th = tcp_hdr(skb);

        /* Guard datalen to not overflow userbuf */
        int dlen = (rlen + skb->dlen) > userlen ? (userlen - rlen) : skb->dlen;
        memcpy(user_buf, skb->payload, dlen);

        /* Accommodate next round of data dequeue */
        skb->dlen -= dlen;
        skb->payload += dlen;
        rlen += dlen;
        user_buf += dlen;
        tsk->rcv_queue_size -= dlen;

        /* skb is fully eaten, process flags and drop it */
        if (skb->dlen == 0) {
            if (th->psh) tsk->flags |= TCP_PSH;
            skb_dequeue(&sk->receive_queue);
            skb->refcnt--;
            free_skb(skb);
        }
    }

    if (skb_queue_empty(&sk->receive_queue) && !(tsk->flags & TCP_FIN)) {
        sk->poll_events &= ~POLLIN;
    }
    
    return rlen;
}

int tcp_data_queue(struct tcp_sock *tsk, struct tcphdr *th, struct sk_buff *skb) {
    struct vsock *sk = &tsk->sk;
    struct vsocket * sock = sk->sock;
    struct tcb *tcb = &tsk->tcb;
    int rc = 0;

    if (!tcb->rcv_wnd) {
        return -1;
    }

    if (skb->dlen && tsk->rcv_queue_size + skb->dlen > sock->rcv_buf_size) {
        // no space left in rcv buffer. we simply drop the packet.
        return -1;
    }


    int expected = skb->seq == tcb->rcv_nxt;
    if (expected) {
        // rcv_nxt is only incremented upon receiving segments with data.
        // it is not incremented for receiving standalone ACKs
        
        tcb->rcv_nxt += skb->dlen;
        skb->refcnt++;
        skb_queue_tail(&sk->receive_queue, skb);
        tcp_consume_ofo_queue(tsk);

        tsk->rcv_queue_size += skb->dlen;
        tsk->chk_pt_rcv_queue_size += skb->dlen;

        // There is new data for user to read
        sk->poll_events |= (POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND);
        tsk->sk.ops->recv_notify(&tsk->sk);

        // the ack for this is sent in the last stage of tcp_input_state function
        // under congestion control and delacks section
    } else {
        /* Segment passed validation, hence it is in-window
           but not the left-most sequence. Put into out-of-order queue
           for later processing */

        tsk->rcv_queue_size += skb->dlen;
        tsk->chk_pt_rcv_queue_size += skb->dlen;

        tcp_data_insert_ordered(&tsk->ofo_queue, skb, tcb->rcv_nxt, tcb->rcv_nxt + tcb->rcv_wnd);

        /* RFC5581: A TCP receiver SHOULD send an immediate duplicate ACK when an out-
         * of-order segment arrives.  The purpose of this ACK is to inform the
         * sender that a segment was received out-of-order and which sequence
         * number is expected. */
        tcp_send_ack(sk);
    }
    
    return rc;
}

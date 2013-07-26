/*
 *	MPTCP implementation
 *
 *	Initial Design & Implementation:
 *	Sébastien Barré <sebastien.barre@uclouvain.be>
 *
 *	Current Maintainer & Author:
 *	Christoph Paasch <christoph.paasch@uclouvain.be>
 *
 *	Additional authors:
 *	Jaakko Korkeaniemi <jaakko.korkeaniemi@aalto.fi>
 *	Gregory Detal <gregory.detal@uclouvain.be>
 *	Fabien Duchêne <fabien.duchene@uclouvain.be>
 *	Andreas Seelinger <Andreas.Seelinger@rwth-aachen.de>
 *	Lavkesh Lahngir <lavkesh51@gmail.com>
 *	Andreas Ripke <ripke@neclab.eu>
 *	Vlad Dogaru <vlad.dogaru@intel.com>
 *	Octavian Purdila <octavian.purdila@intel.com>
 *	John Ronan <jronan@tssg.org>
 *	Catalin Nicutar <catalin.nicutar@gmail.com>
 *	Brandon Heller <brandonh@stanford.edu>
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _MPTCP_H
#define _MPTCP_H

#include <linux/inetdevice.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/kernel.h>

#include <asm/byteorder.h>
#include <asm/unaligned.h>
#include <crypto/hash.h>
#include <net/mptcp_pm.h>
#include <net/tcp.h>

#if defined(__LITTLE_ENDIAN_BITFIELD)
	#define ntohll(x)  be64_to_cpu(x)
	#define htonll(x)  cpu_to_be64(x)
#elif defined(__BIG_ENDIAN_BITFIELD)
	#define ntohll(x) (x)
	#define htonll(x) (x)
#endif

struct mptcp_request_sock {
	struct tcp_request_sock		req;
	struct hlist_nulls_node		collide_tk;
	u32                             mptcp_loc_token;
	u64				mptcp_loc_key;
	u64				mptcp_rem_key;
	u8				dss_csum:1;
};

struct mptcp_options_received {
	u16	saw_mpc:1,
		dss_csum:1,
		drop_me:1,

		mp_fail:1,
		mp_fclose:1;
	u8	prio_addr_id;	/* Address-id in the MP_PRIO */

	const unsigned char *add_addr_ptr; /* Pointer to add-address option */

	u32	data_ack;
	u32	data_seq;
	u16	data_len;

	/* Key inside the option (from mp_capable or fast_close) */
	u64	mptcp_key;

	u32	mptcp_recv_nonce;
	u64	mptcp_recv_tmac;
};

struct mptcp_tcp_sock {
	struct tcp_sock	*next;		/* Next subflow socket */
	struct mptcp_options_received rx_opt;

	 /* Those three fields record the current mapping */
	u64	map_data_seq;
	u32	map_subseq;
	u16	map_data_len;
	u16	slave_sk:1,
		nonce_set:1, /* Is the nonce set? (in order to support 0-nonce) */
		fully_established:1,
		establish_increased:1,
		second_packet:1,
		attached:1,
		send_mp_fail:1,
		include_mpc:1,
		mapping_present:1,
		map_data_fin:1,
		pre_established:1; /* State between sending 3rd ACK and
				    * receiving the fourth ack of new subflows.
				    */

	/* isn: needed to translate abs to relative subflow seqnums */
	u32	snt_isn;
	u32	rcv_isn;
	u32	last_data_seq;
	u8	path_index;
	u8	rem_id;

	u32	last_rbuf_opti;	/* Timestamp of last rbuf optimization */
	unsigned int sent_pkts;

	struct sk_buff  *shortcut_ofoqueue; /* Shortcut to the current modified
					     * skb in the ofo-queue.
					     */

	int	init_rcv_wnd;
	u32	infinite_cutoff_seq;
	struct delayed_work work;
	u32	mptcp_loc_nonce;
	struct tcp_sock *tp; /* Where is my daddy? */
	u32	last_end_data_seq;

	/* MP_JOIN subflow: timer for retransmitting the 3rd ack */
	struct timer_list mptcp_ack_timer;

	/* HMAC of the third ack */
	char sender_mac[20];
};

struct mptcp_tw {
	struct list_head list;
	u64 loc_key;
	u64 rcv_nxt;
	struct mptcp_cb __rcu *mpcb;
	u8 meta_tw:1,
	   in_list:1;
};

struct mptcp_cb {
	struct sock *meta_sk;

	/* list of sockets in this multipath connection */
	struct tcp_sock *connection_list;

	spinlock_t	 tw_lock;
	struct list_head tw_list;
	unsigned char	 mptw_state;

	atomic_t	refcnt;

	/* High-order bits of 64-bit sequence numbers */
	u32 snd_high_order[2];
	u32 rcv_high_order[2];

	u16	send_infinite_mapping:1,
		in_time_wait:1,
		dss_csum:1,
		server_side:1,
		infinite_mapping_rcv:1,
		infinite_mapping_snd:1,
		dfin_combined:1,   /* Was the DFIN combined with subflow-fin? */
		passive_close:1,
		snd_hiseq_index:1, /* Index in snd_high_order of snd_nxt */
		rcv_hiseq_index:1; /* Index in rcv_high_order of rcv_nxt */

	/* socket count in this connection */
	u8 cnt_subflows;
	u8 cnt_established;

	u32 noneligible;	/* Path mask of temporarily non
				 * eligible subflows by the scheduler
				 */

	struct sk_buff_head reinject_queue;

	u8 dfin_path_index;
	/* Mutex needed, because otherwise mptcp_close will complain that the
	 * socket is owned by the user.
	 * E.g., mptcp_sub_close_wq is taking the meta-lock.
	 */
	struct mutex mutex;

	/* Master socket, also part of the connection_list, this
	 * socket is the one that the application sees.
	 */
	struct sock *master_sk;

	u64	csum_cutoff_seq;

	__u64	mptcp_loc_key;
	__u32	mptcp_loc_token;
	__u64	mptcp_rem_key;
	__u32	mptcp_rem_token;

	/* Create a new subflow - necessary because the meta-sk may be IPv4, but
	 * the new subflow can be IPv6
	 */
	struct sock *(*syn_recv_sock)(struct sock *sk, struct sk_buff *skb,
				      struct request_sock *req,
				      struct dst_entry *dst);

	/* Local addresses */
	struct mptcp_loc4 locaddr4;

	/* Original snd/rcvbuf of the initial subflow.
	 * Used for the new subflows on the server-side to allow correct
	 * autotuning
	 */
	int orig_sk_rcvbuf;
	int orig_sk_sndbuf;
	u32 orig_window_clamp;
};

#define MPTCP_SUB_CAPABLE			0
#define MPTCP_SUB_LEN_CAPABLE_SYN		12
#define MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN		12
#define MPTCP_SUB_LEN_CAPABLE_ACK		20
#define MPTCP_SUB_LEN_CAPABLE_ACK_ALIGN		20

#define MPTCP_SUB_JOIN			1
#define MPTCP_SUB_LEN_JOIN_SYN		12
#define MPTCP_SUB_LEN_JOIN_SYN_ALIGN	12
#define MPTCP_SUB_LEN_JOIN_SYNACK	16
#define MPTCP_SUB_LEN_JOIN_SYNACK_ALIGN	16
#define MPTCP_SUB_LEN_JOIN_ACK		24
#define MPTCP_SUB_LEN_JOIN_ACK_ALIGN	24

#define MPTCP_SUB_DSS		2
#define MPTCP_SUB_LEN_DSS	4
#define MPTCP_SUB_LEN_DSS_ALIGN	4

/* Lengths for seq and ack are the ones without the generic MPTCP-option header,
 * as they are part of the DSS-option.
 * To get the total length, just add the different options together.
 */
#define MPTCP_SUB_LEN_SEQ	10
#define MPTCP_SUB_LEN_SEQ_CSUM	12
#define MPTCP_SUB_LEN_SEQ_ALIGN	12

#define MPTCP_SUB_LEN_SEQ_64		14
#define MPTCP_SUB_LEN_SEQ_CSUM_64	16
#define MPTCP_SUB_LEN_SEQ_64_ALIGN	16

#define MPTCP_SUB_LEN_ACK	4
#define MPTCP_SUB_LEN_ACK_ALIGN	4

#define MPTCP_SUB_LEN_ACK_64		8
#define MPTCP_SUB_LEN_ACK_64_ALIGN	8

/* This is the "default" option-length we will send out most often.
 * MPTCP DSS-header
 * 32-bit data sequence number
 * 32-bit data ack
 *
 * It is necessary to calculate the effective MSS we will be using when
 * sending data.
 */
#define MPTCP_SUB_LEN_DSM_ALIGN  (MPTCP_SUB_LEN_DSS_ALIGN +		\
				  MPTCP_SUB_LEN_SEQ_ALIGN +		\
				  MPTCP_SUB_LEN_ACK_ALIGN)

#define MPTCP_SUB_FAIL		6
#define MPTCP_SUB_LEN_FAIL	12
#define MPTCP_SUB_LEN_FAIL_ALIGN	12

#define MPTCP_SUB_FCLOSE	7
#define MPTCP_SUB_LEN_FCLOSE	12
#define MPTCP_SUB_LEN_FCLOSE_ALIGN	12


#define OPTION_MPTCP		(1 << 5)

/* Without MPTCP, we just do one iteration
 * over the only socket available. This assumes that
 * the sk/tp arg is the socket in that case.
 */
#define mptcp_for_each_sk(mpcb, sk)
#define mptcp_for_each_sk_safe(__mpcb, __sk, __temp)

static inline int mptcp_is_data_fin(const struct sk_buff *skb)
{
	return 0;
}
static inline int mptcp_is_data_seq(const struct sk_buff *skb)
{
	return 0;
}
static inline struct sock *mptcp_meta_sk(const struct sock *sk)
{
	return NULL;
}
static inline struct tcp_sock *mptcp_meta_tp(const struct tcp_sock *tp)
{
	return NULL;
}
static inline int is_meta_sk(const struct sock *sk)
{
	return 0;
}
static inline int is_master_tp(const struct tcp_sock *tp)
{
	return 0;
}
static inline void mptcp_purge_ofo_queue(struct tcp_sock *meta_tp) {}
static inline void mptcp_cleanup_rbuf(const struct sock *meta_sk, int copied) {}
static inline void mptcp_del_sock(const struct sock *sk) {}
static inline void mptcp_reinject_data(struct sock *orig_sk, int clone_it) {}
static inline void mptcp_init_buffer_space(const struct sock *sk) {}
static inline void mptcp_update_sndbuf(const struct mptcp_cb *mpcb) {}
static inline void mptcp_skb_entail_init(const struct tcp_sock *tp,
					 const struct sk_buff *skb) {}
static inline void mptcp_clean_rtx_infinite(const struct sk_buff *skb,
					    const struct sock *sk) {}
static inline void mptcp_retransmit_timer(const struct sock *meta_sk) {}
static inline int mptcp_write_wakeup(struct sock *meta_sk)
{
	return 0;
}
static inline void mptcp_sub_close(struct sock *sk, unsigned long delay) {}
static inline void mptcp_set_rto(const struct sock *sk) {}
static inline void mptcp_send_fin(const struct sock *meta_sk) {}
static inline void mptcp_parse_options(const uint8_t *ptr, const int opsize,
				       const struct tcp_options_received *opt_rx,
				       const struct mptcp_options_received *mopt,
				       const struct sk_buff *skb) {}
static inline void mptcp_syn_options(struct sock *sk,
				     struct tcp_out_options *opts,
				     unsigned *remaining) {}
static inline void mptcp_synack_options(struct request_sock *req,
					struct tcp_out_options *opts,
					unsigned *remaining) {}

static inline void mptcp_established_options(struct sock *sk,
					     struct sk_buff *skb,
					     struct tcp_out_options *opts,
					     unsigned *size) {}
static inline void mptcp_options_write(__be32 *ptr, struct tcp_sock *tp,
				       struct tcp_out_options *opts,
				       struct sk_buff *skb) {}
static inline void mptcp_close(struct sock *meta_sk, long timeout) {}
static inline int mptcp_doit(struct sock *sk)
{
	return 0;
}
static inline int mptcp_check_req_master(const struct sock *sk,
					 const struct sock *child,
					 struct request_sock *req,
					 struct request_sock **prev,
					 const struct mptcp_options_received *mopt)
{
	return 1;
}
static inline u32 __mptcp_select_window(const struct sock *sk)
{
	return 0;
}
static inline void mptcp_select_initial_window(int *__space,
					       __u32 *window_clamp,
					       const struct sock *sk) {}
static inline unsigned int mptcp_current_mss(struct sock *meta_sk)
{
	return 0;
}
static inline int mptcp_select_size(const struct sock *meta_sk, bool sg)
{
	return 0;
}
static inline void mptcp_sub_close_passive(struct sock *sk) {}
static inline bool mptcp_fallback_infinite(const struct sock *sk, int flag)
{
	return false;
}
static inline void mptcp_init_mp_opt(const struct mptcp_options_received *mopt) {}
static inline int mptcp_check_rtt(const struct tcp_sock *tp, int time)
{
	return 0;
}
static inline int mptcp_check_snd_buf(const struct tcp_sock *tp)
{
	return 0;
}
static inline int mptcp_sysctl_syn_retries(void)
{
	return 0;
}
static inline void mptcp_send_reset(const struct sock *sk) {}
static inline void mptcp_send_active_reset(struct sock *meta_sk,
					   gfp_t priority) {}
static inline int mptcp_write_xmit(struct sock *sk, unsigned int mss_now,
				   int nonagle, int push_one, gfp_t gfp)
{
	return 0;
}
static inline struct sock *mptcp_sk_clone(const struct sock *sk,
					  int family, int priority)
{
	return NULL;
}
static inline void mptcp_set_keepalive(struct sock *sk, int val) {}
static inline int mptcp_handle_options(struct sock *sk,
				       const struct tcphdr *th,
				       struct sk_buff *skb)
{
	return 0;
}
static inline void mptcp_reset_mopt(struct tcp_sock *tp) {}
static inline void  __init mptcp_init(void) {}
static inline int mptcp_trim_head(struct sock *sk, struct sk_buff *skb, u32 len)
{
	return 0;
}
static inline int mptcp_fragment(struct sock *sk, struct sk_buff *skb, u32 len,
				 unsigned int mss_now, int reinject)
{
	return 0;
}
static inline int mptso_fragment(struct sock *sk, struct sk_buff *skb,
				 unsigned int len, unsigned int mss_now,
				 gfp_t gfp, int reinject)
{
	return 0;
}
static inline bool mptcp_sk_can_gso(const struct sock *sk)
{
	return false;
}
static inline bool mptcp_can_sg(const struct sock *meta_sk)
{
	return false;
}
static inline unsigned int mptcp_xmit_size_goal(struct sock *meta_sk,
						u32 mss_now, int large_allowed)
{
	return 0;
}
static inline void mptcp_destroy_sock(struct sock *sk) {}
static inline int mptcp_rcv_synsent_state_process(struct sock *sk,
						  struct sock **skptr,
						  struct sk_buff *skb,
						  struct mptcp_options_received *mopt)
{
	return 0;
}
static inline bool mptcp_can_sendpage(struct sock *sk)
{
	return false;
}
static inline int mptcp_time_wait(struct sock *sk, struct tcp_timewait_sock *tw)
{
	return 0;
}
static inline void mptcp_twsk_destructor(struct tcp_timewait_sock *tw) {}
static inline void mptcp_update_tw_socks(const struct tcp_sock *tp, int state) {}

#endif /* _MPTCP_H */

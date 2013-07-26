/*
 *	MPTCP implementation - IPv4-specific functions
 *
 *	Initial Design & Implementation:
 *	Sébastien Barré <sebastien.barre@uclouvain.be>
 *
 *	Current Maintainer:
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

#include <linux/export.h>
#include <linux/ip.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/tcp.h>

#include <net/inet_common.h>
#include <net/inet_connection_sock.h>
#include <net/mptcp.h>
#include <net/mptcp_pm.h>
#include <net/mptcp_v4.h>
#include <net/request_sock.h>
#include <net/tcp.h>

u32 mptcp_v4_get_nonce(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport,
		       u32 seq)
{
	u32 hash[MD5_DIGEST_WORDS];

	hash[0] = (__force u32)saddr;
	hash[1] = (__force u32)daddr;
	hash[2] = ((__force u16)sport << 16) + (__force u16)dport;
	hash[3] = seq;

	md5_transform(hash, mptcp_secret);

	return hash[0];
}

u64 mptcp_v4_get_key(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	u32 hash[MD5_DIGEST_WORDS];

	hash[0] = (__force u32)saddr;
	hash[1] = (__force u32)daddr;
	hash[2] = ((__force u16)sport << 16) + (__force u16)dport;
	hash[3] = mptcp_key_seed++;

	md5_transform(hash, mptcp_secret);

	return *((u64 *)hash);
}


static void mptcp_v4_reqsk_destructor(struct request_sock *req)
{
	mptcp_reqsk_destructor(req);

	tcp_v4_reqsk_destructor(req);
}

/* Similar to tcp_request_sock_ops */
struct request_sock_ops mptcp_request_sock_ops __read_mostly = {
	.family		=	PF_INET,
	.obj_size	=	sizeof(struct mptcp_request_sock),
	.rtx_syn_ack	=	tcp_v4_rtx_synack,
	.send_ack	=	tcp_v4_reqsk_send_ack,
	.destructor	=	mptcp_v4_reqsk_destructor,
	.send_reset	=	tcp_v4_send_reset,
	.syn_ack_timeout =	tcp_syn_ack_timeout,
};

/* Based on function tcp_v4_conn_request (tcp_ipv4.c)
 * Returns -1 if there is no space anymore to store an additional
 * address
 */
int mptcp_v4_add_raddress(struct mptcp_cb *mpcb, const struct in_addr *addr,
			  __be16 port, u8 id)
{
	int i;
	struct mptcp_rem4 *rem4;

	mptcp_for_each_bit_set(mpcb->rem4_bits, i) {
		rem4 = &mpcb->remaddr4[i];

		/* Address is already in the list --- continue */
		if (rem4->id == id &&
		    rem4->addr.s_addr == addr->s_addr && rem4->port == port)
			return 0;

		/* This may be the case, when the peer is behind a NAT. He is
		 * trying to JOIN, thus sending the JOIN with a certain ID.
		 * However the src_addr of the IP-packet has been changed. We
		 * update the addr in the list, because this is the address as
		 * OUR BOX sees it.
		 */
		if (rem4->id == id && rem4->addr.s_addr != addr->s_addr) {
			/* update the address */
			rem4->addr.s_addr = addr->s_addr;
			rem4->port = port;
			mpcb->list_rcvd = 1;
			return 0;
		}
	}

	i = mptcp_find_free_index(mpcb->rem4_bits);
	/* Do we have already the maximum number of local/remote addresses? */
	if (i < 0)
		return -1;

	rem4 = &mpcb->remaddr4[i];

	/* Address is not known yet, store it */
	rem4->addr.s_addr = addr->s_addr;
	rem4->port = port;
	rem4->bitfield = 0;
	rem4->retry_bitfield = 0;
	rem4->id = id;
	mpcb->list_rcvd = 1;
	mpcb->rem4_bits |= (1 << i);

	return 0;
}

/* Sets the bitfield of the remote-address field
 * local address is not set as it will disappear with the global address-list
 */
void mptcp_v4_set_init_addr_bit(struct mptcp_cb *mpcb, __be32 daddr)
{
	int i;

	mptcp_for_each_bit_set(mpcb->rem4_bits, i) {
		if (mpcb->remaddr4[i].addr.s_addr == daddr) {
			/* It's the initial flow - thus local index == 0 */
			mpcb->remaddr4[i].bitfield |= 1;
			return;
		}
	}
}

/* We only process join requests here. (either the SYN or the final ACK) */
int mptcp_v4_do_rcv(struct sock *meta_sk, struct sk_buff *skb)
{
	int ret;
	struct tcphdr *th = tcp_hdr(skb);
	const struct iphdr *iph = ip_hdr(skb);
	struct sock *sk;

	sk = inet_lookup_established(sock_net(meta_sk), &tcp_hashinfo,
				     iph->saddr, th->source, iph->daddr,
				     th->dest, inet_iif(skb));

	if (!sk) {
		kfree_skb(skb);
		return 0;
	}
	if (is_meta_sk(sk)) {
		WARN("%s Did not find a sub-sk - did found the meta!\n", __func__);
		kfree_skb(skb);
		sock_put(sk);
		return 0;
	}

	if (sk->sk_state == TCP_TIME_WAIT) {
		inet_twsk_put(inet_twsk(sk));
		kfree_skb(skb);
		return 0;
	}

	ret = tcp_v4_do_rcv(sk, skb);
	sock_put(sk);

	return ret;
}

/* Create a new IPv4 subflow.
 *
 * We are in user-context and meta-sock-lock is hold.
 */
int mptcp_init4_subsockets(struct sock *meta_sk, const struct mptcp_loc4 *loc,
			   struct mptcp_rem4 *rem)
{
	struct tcp_sock *tp;
	struct sock *sk;
	struct sockaddr_in loc_in, rem_in;
	struct socket sock;
	int ulid_size = 0, ret;

	/* Don't try again - even if it fails */
	rem->bitfield |= (1 << loc->id);

	/** First, create and prepare the new socket */

	sock.type = meta_sk->sk_socket->type;
	sock.state = SS_UNCONNECTED;
	sock.wq = meta_sk->sk_socket->wq;
	sock.file = meta_sk->sk_socket->file;
	sock.ops = NULL;

	ret = inet_create(sock_net(meta_sk), &sock, IPPROTO_TCP, 1);
	if (unlikely(ret < 0))
		return ret;

	sk = sock.sk;
	tp = tcp_sk(sk);

	/* All subsockets need the MPTCP-lock-class */
	lockdep_set_class_and_name(&(sk)->sk_lock.slock, &meta_slock_key, "slock-AF_INET-MPTCP");
	lockdep_init_map(&(sk)->sk_lock.dep_map, "sk_lock-AF_INET-MPTCP", &meta_key, 0);

	if (mptcp_add_sock(meta_sk, sk, rem->id, GFP_KERNEL))
		goto error;

	tp->mptcp->slave_sk = 1;

	/* Initializing the timer for an MPTCP subflow */
	setup_timer(&tp->mptcp->mptcp_ack_timer, mptcp_ack_handler, (unsigned long)sk);

	/** Then, connect the socket to the peer */

	ulid_size = sizeof(struct sockaddr_in);
	loc_in.sin_family = AF_INET;
	rem_in.sin_family = AF_INET;
	loc_in.sin_port = 0;
	if (rem->port)
		rem_in.sin_port = rem->port;
	else
		rem_in.sin_port = inet_sk(meta_sk)->inet_dport;
	loc_in.sin_addr = loc->addr;
	rem_in.sin_addr = rem->addr;

	ret = sock.ops->bind(&sock, (struct sockaddr *)&loc_in, ulid_size);
	if (ret < 0)
		goto error;

	ret = sock.ops->connect(&sock, (struct sockaddr *)&rem_in,
				ulid_size, O_NONBLOCK);
	if (ret < 0 && ret != -EINPROGRESS)
		goto error;

	sk_set_socket(sk, meta_sk->sk_socket);
	sk->sk_wq = meta_sk->sk_wq;

	return 0;

error:
	/* May happen if mptcp_add_sock fails first */
	if (!tp->mpc) {
		tcp_close(sk, 0);
	} else {
		local_bh_disable();
		mptcp_sub_force_close(sk);
		local_bh_enable();
	}
	return ret;
}

/****** IPv4-Address event handler ******/

/* React on IP-addr add/rem-events */
static int mptcp_pm_inetaddr_event(struct notifier_block *this,
				   unsigned long event, void *ptr)
{
	return mptcp_pm_addr_event_handler(event, ptr, AF_INET);
}

/* React on ifup/down-events */
static int mptcp_pm_netdev_event(struct notifier_block *this,
				 unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct in_device *in_dev;

	if (!(event == NETDEV_UP || event == NETDEV_CHANGE))
		return NOTIFY_DONE;

	/* Iterate over the addresses of the interface, then we go over the
	 * mpcb's to modify them - that way we take tk_hash_lock for a shorter
	 * time at each iteration. - otherwise we would need to take it from the
	 * beginning till the end.
	 */
	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);

	if (in_dev) {
		for_primary_ifa(in_dev) {
			mptcp_pm_inetaddr_event(NULL, event, ifa);
		} endfor_ifa(in_dev);
	}

	rcu_read_unlock();
	return NOTIFY_DONE;
}

void mptcp_pm_addr4_event_handler(struct in_ifaddr *ifa, unsigned long event,
				  struct mptcp_cb *mpcb)
{
	int i;

	if (ifa->ifa_scope > RT_SCOPE_LINK)
		return;

	/* Look for the address among the local addresses */
	mptcp_for_each_bit_set(mpcb->loc4_bits, i) {
		if (mpcb->locaddr4[i].addr.s_addr == ifa->ifa_local)
			return;
	}

	/* Not yet in address-list */
	if (event == NETDEV_UP && netif_running(ifa->ifa_dev->dev)) {
		i = __mptcp_find_free_index(mpcb->loc4_bits, 0, mpcb->next_v4_index);
		if (i < 0)
			return;

		/* update this mpcb */
		mpcb->locaddr4[i].addr.s_addr = ifa->ifa_local;
		mpcb->locaddr4[i].id = i;
		mpcb->loc4_bits |= (1 << i);
		mpcb->next_v4_index = i + 1;
		/* re-send addresses */
		mptcp_v4_send_add_addr(i, mpcb);
		/* re-evaluate paths */
		mptcp_create_subflows(mpcb->meta_sk);
	}
	return;
}

/* Send ADD_ADDR for loc_id on all available subflows */
void mptcp_v4_send_add_addr(int loc_id, struct mptcp_cb *mpcb)
{
	struct tcp_sock *tp;

	mptcp_for_each_tp(mpcb, tp)
		tp->mptcp->add_addr4 |= (1 << loc_id);
}

static struct notifier_block mptcp_pm_inetaddr_notifier = {
		.notifier_call = mptcp_pm_inetaddr_event,
};

static struct notifier_block mptcp_pm_netdev_notifier = {
		.notifier_call = mptcp_pm_netdev_event,
};

/****** End of IPv4-Address event handler ******/

/* General initialization of IPv4 for MPTCP */
int mptcp_pm_v4_init(void)
{
	int ret;
	struct request_sock_ops *ops = &mptcp_request_sock_ops;

	ops->slab_name = kasprintf(GFP_KERNEL, "request_sock_%s", "MPTCP");
	if (ops->slab_name == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	ops->slab = kmem_cache_create(ops->slab_name, ops->obj_size, 0,
				      SLAB_HWCACHE_ALIGN, NULL);

	if (ops->slab == NULL) {
		ret =  -ENOMEM;
		goto err_reqsk_create;
	}

	ret = register_inetaddr_notifier(&mptcp_pm_inetaddr_notifier);
	if (ret)
		goto err_reg_inetaddr;
	ret = register_netdevice_notifier(&mptcp_pm_netdev_notifier);
	if (ret)
		goto err_reg_netdev;

out:
	return ret;

err_reg_netdev:
	unregister_inetaddr_notifier(&mptcp_pm_inetaddr_notifier);
err_reg_inetaddr:
	kmem_cache_destroy(ops->slab);
err_reqsk_create:
	kfree(ops->slab_name);
	ops->slab_name = NULL;
	goto out;
}

void mptcp_pm_v4_undo(void)
{
	unregister_inetaddr_notifier(&mptcp_pm_inetaddr_notifier);
	unregister_netdevice_notifier(&mptcp_pm_netdev_notifier);
	kmem_cache_destroy(mptcp_request_sock_ops.slab);
	kfree(mptcp_request_sock_ops.slab_name);
}



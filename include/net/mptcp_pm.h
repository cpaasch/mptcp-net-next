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

#ifndef _MPTCP_PM_H
#define _MPTCP_PM_H

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/spinlock_types.h>
#include <linux/types.h>

#include <net/request_sock.h>
#include <net/sock.h>
#include <net/tcp.h>

/* Max number of local or remote addresses we can store.
 * When changing, see the bitfield below in mptcp_loc4/6. */
#define MPTCP_MAX_ADDR	8

#define MPTCP_SUBFLOW_RETRY_DELAY	1000

struct mptcp_loc4 {
	u8		id;
	__be16		port;
	struct in_addr	addr;
};

struct mptcp_cb;

static inline void mptcp_reqsk_new_mptcp(struct request_sock *req,
					 const struct tcp_options_received *rx_opt,
					 const struct mptcp_options_received *mopt,
					 const struct sk_buff *skb)
{}
static inline void mptcp_hash_remove(struct tcp_sock *meta_tp) {}

#endif /*_MPTCP_PM_H*/

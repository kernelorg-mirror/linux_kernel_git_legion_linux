// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NET4:	Sysctl interface to net af_unix subsystem.
 *
 * Authors:	Mike Shaver.
 */

#include <linux/string.h>
#include <linux/sysctl.h>
#include <net/af_unix.h>
#include <net/net_namespace.h>

#include "af_unix.h"

static void *unix_max_dgram_qlen_data(const struct ctl_context *ctx)
{
	return &ctx->ns.net_ns->unx.sysctl_max_dgram_qlen;
}

static const struct ctl_field unix_table[] = {
	{
		.table = {
			.procname	= "max_dgram_qlen",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = unix_max_dgram_qlen_data,
	},
};

int __net_init unix_sysctl_register(struct net *net)
{
	net->unx.ctl = register_net_sysctl_fields(net, "net/unix",
						  unix_table,
						  ARRAY_SIZE(unix_table));
	if (net->unx.ctl == NULL)
		return -ENOMEM;

	return 0;
}

void unix_sysctl_unregister(struct net *net)
{
	unregister_net_sysctl_table(net->unx.ctl);
}

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NET4:	Sysctl interface to net af_unix subsystem.
 *
 * Authors:	Mike Shaver.
 */

#include <linux/sysctl.h>
#include <net/af_unix.h>
#include <net/net_namespace.h>

#include "af_unix.h"

static int *unix_max_dgram_qlen_data(const struct sysctl_context *ctx)
{
	return &ctx->ns.net_ns->unx.sysctl_max_dgram_qlen;
}

static const struct sysctl_field unix_table[] = {
	SYSCTL_FIELD_INT("max_dgram_qlen", 0644, unix_max_dgram_qlen_data),
};

int __net_init unix_sysctl_register(struct net *net)
{
	struct sysctl_context ctx = {
		.ns.net_ns = net,
	};

	net->unx.ctl = register_sysctl_fields(&net->sysctls, "net/unix",
					      unix_table, &ctx);
	if (net->unx.ctl == NULL)
		return -ENOMEM;

	return 0;
}

void unix_sysctl_unregister(struct net *net)
{
	unregister_net_sysctl_table(net->unx.ctl);
}

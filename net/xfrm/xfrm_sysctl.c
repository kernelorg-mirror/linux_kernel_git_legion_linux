// SPDX-License-Identifier: GPL-2.0
#include <linux/sysctl.h>
#include <net/net_namespace.h>
#include <net/xfrm.h>

static void __net_init __xfrm_sysctl_init(struct net *net)
{
	net->xfrm.sysctl_aevent_etime = XFRM_AE_ETIME;
	net->xfrm.sysctl_aevent_rseqth = XFRM_AE_SEQT_SIZE;
	net->xfrm.sysctl_larval_drop = 1;
	net->xfrm.sysctl_acq_expires = 30;
}

#ifdef CONFIG_SYSCTL
#define XFRM_DATA(name, field)						\
static void * xfrm_ ## name ## _data(const struct ctl_context *ctx)	\
{									\
	return &ctx->ns.net_ns->xfrm.field;				\
}

XFRM_DATA(aevent_etime, sysctl_aevent_etime);
XFRM_DATA(aevent_rseqth, sysctl_aevent_rseqth);
XFRM_DATA(larval_drop, sysctl_larval_drop);
XFRM_DATA(acq_expires, sysctl_acq_expires);

static const struct ctl_field xfrm_table[] = {
	{
		.table = {
			.procname	= "xfrm_aevent_etime",
			.maxlen		= sizeof(u32),
			.mode		= 0644,
			.proc_handler	= proc_douintvec,
		},
		.data = xfrm_aevent_etime_data,
	},
	{
		.table = {
			.procname	= "xfrm_aevent_rseqth",
			.maxlen		= sizeof(u32),
			.mode		= 0644,
			.proc_handler	= proc_douintvec,
		},
		.data = xfrm_aevent_rseqth_data,
	},
	{
		.table = {
			.procname	= "xfrm_larval_drop",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = xfrm_larval_drop_data,
	},
	{
		.table = {
			.procname	= "xfrm_acq_expires",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = xfrm_acq_expires_data,
	},
};

int __net_init xfrm_sysctl_init(struct net *net)
{
	size_t table_size = ARRAY_SIZE(xfrm_table);

	__xfrm_sysctl_init(net);

	/* Don't export sysctls to unprivileged users */
	if (net->user_ns != &init_user_ns)
		table_size = 0;

	net->xfrm.sysctl_hdr = register_net_sysctl_fields(net, "net/core",
							  xfrm_table,
							  table_size);
	if (!net->xfrm.sysctl_hdr)
		return -ENOMEM;
	return 0;
}

void __net_exit xfrm_sysctl_fini(struct net *net)
{
	unregister_net_sysctl_table(net->xfrm.sysctl_hdr);
}
#else
int __net_init xfrm_sysctl_init(struct net *net)
{
	__xfrm_sysctl_init(net);
	return 0;
}
#endif

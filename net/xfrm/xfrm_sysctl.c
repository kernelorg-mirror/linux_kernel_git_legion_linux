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
#define XFRM_UINT_DATA(name)						\
static unsigned int *xfrm_ ## name ## _data(const struct sysctl_context *ctx) \
{									\
	return &ctx->ns.net_ns->xfrm.name;				\
}

#define XFRM_INT_DATA(name)						\
static int *xfrm_ ## name ## _data(const struct sysctl_context *ctx)	\
{									\
	return &ctx->ns.net_ns->xfrm.name;				\
}

XFRM_UINT_DATA(sysctl_aevent_etime)
XFRM_UINT_DATA(sysctl_aevent_rseqth)
XFRM_INT_DATA(sysctl_larval_drop)
XFRM_INT_DATA(sysctl_acq_expires)

static const struct sysctl_field xfrm_table[] = {
	SYSCTL_FIELD_UINT("xfrm_aevent_etime", 0644, xfrm_sysctl_aevent_etime_data),
	SYSCTL_FIELD_UINT("xfrm_aevent_rseqth", 0644, xfrm_sysctl_aevent_rseqth_data),
	SYSCTL_FIELD_INT("xfrm_larval_drop", 0644, xfrm_sysctl_larval_drop_data),
	SYSCTL_FIELD_INT("xfrm_acq_expires", 0644, xfrm_sysctl_acq_expires_data),
};

int __net_init xfrm_sysctl_init(struct net *net)
{
	struct sysctl_context ctx = {
		.ns.net_ns = net,
	};
	size_t table_size = ARRAY_SIZE(xfrm_table);

	__xfrm_sysctl_init(net);

	/* Don't export sysctls to unprivileged users */
	if (net->user_ns != &init_user_ns)
		table_size = 0;

	net->xfrm.sysctl_hdr = __register_sysctl_fields(&net->sysctls, "net/core",
							xfrm_table, table_size,
							&ctx, sizeof(ctx));
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

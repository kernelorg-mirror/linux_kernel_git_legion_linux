// SPDX-License-Identifier: GPL-2.0

#include <linux/sysctl.h>
#include <net/lwtunnel.h>
#include <net/netfilter/nf_hooks_lwtunnel.h>

static inline int nf_hooks_lwtunnel_get(void)
{
	if (static_branch_unlikely(&nf_hooks_lwtunnel_enabled))
		return 1;
	else
		return 0;
}

static inline int nf_hooks_lwtunnel_set(int enable)
{
	if (static_branch_unlikely(&nf_hooks_lwtunnel_enabled)) {
		if (!enable)
			return -EBUSY;
	} else if (enable) {
		static_branch_enable(&nf_hooks_lwtunnel_enabled);
	}

	return 0;
}

#ifdef CONFIG_SYSCTL
int nf_hooks_lwtunnel_sysctl_handler(struct ctl_context *ctx,
				     void *buffer, size_t *lenp, loff_t *ppos)
{
	int proc_nf_hooks_lwtunnel_enabled = 0;
	struct ctl_table tmp = {
		.procname = ctx->ctl_table->procname,
		.data = &proc_nf_hooks_lwtunnel_enabled,
		.maxlen = sizeof(int),
		.mode = ctx->ctl_table->mode,
		.extra1 = SYSCTL_ZERO,
		.extra2 = SYSCTL_ONE,
	};
	int ret;

	ctx->ctl_table = &tmp;

	if (!ctx->write)
		proc_nf_hooks_lwtunnel_enabled = nf_hooks_lwtunnel_get();

	ret = proc_dointvec_minmax(ctx, buffer, lenp, ppos);

	if (ctx->write && ret == 0)
		ret = nf_hooks_lwtunnel_set(proc_nf_hooks_lwtunnel_enabled);

	return ret;
}
EXPORT_SYMBOL_GPL(nf_hooks_lwtunnel_sysctl_handler);
#endif /* CONFIG_SYSCTL */

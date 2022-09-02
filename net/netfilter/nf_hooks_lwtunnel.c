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
static ssize_t nf_hooks_lwtunnel_sysctl_write(struct ctl_context *ctx, struct file *file,
		char *buffer, size_t *lenp, loff_t *ppos)
{
	int proc_nf_hooks_lwtunnel_enabled = 0;
	ssize_t ret;

	ret = do_proc_dointvec_w(&proc_nf_hooks_lwtunnel_enabled, ctx->ctl_table,
			buffer, lenp, ppos,
			do_proc_dointvec_minmax_conv, SYSCTL_ZERO, SYSCTL_ONE);

	if (ret == 0)
		ret = nf_hooks_lwtunnel_set(proc_nf_hooks_lwtunnel_enabled);

	return ret;
}

static ssize_t nf_hooks_lwtunnel_sysctl_read(struct ctl_context *ctx, struct file *file,
		char *buffer, size_t *lenp, loff_t *ppos)
{
	int proc_nf_hooks_lwtunnel_enabled = nf_hooks_lwtunnel_get();

	return do_proc_dointvec_r(&proc_nf_hooks_lwtunnel_enabled, ctx->ctl_table,
			buffer, lenp, ppos,
			do_proc_dointvec_minmax_conv, NULL, NULL);
}

struct ctl_fops nf_hooks_lwtunnel_sysctl_fops = {
	.read  = nf_hooks_lwtunnel_sysctl_read,
	.write = nf_hooks_lwtunnel_sysctl_write,
};

EXPORT_SYMBOL_GPL(nf_hooks_lwtunnel_sysctl_fops);
#endif /* CONFIG_SYSCTL */

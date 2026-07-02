// SPDX-License-Identifier: GPL-2.0

#include <linux/sysctl.h>
#include <net/lwtunnel.h>
#include <net/netfilter/nf_hooks_lwtunnel.h>
#include <linux/netfilter.h>

#include "nf_internals.h"

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
int nf_hooks_lwtunnel_sysctl_handler(const struct ctl_table *table, int write,
				     void *buffer, size_t *lenp, loff_t *ppos)
{
	int proc_nf_hooks_lwtunnel_enabled = 0;
	struct ctl_table tmp = {
		.procname = table->procname,
		.data = &proc_nf_hooks_lwtunnel_enabled,
		.maxlen = sizeof(int),
		.mode = table->mode,
		.extra1 = SYSCTL_ZERO,
		.extra2 = SYSCTL_ONE,
	};
	int ret;

	if (!write)
		proc_nf_hooks_lwtunnel_enabled = nf_hooks_lwtunnel_get();

	ret = proc_dointvec_minmax(&tmp, write, buffer, lenp, ppos);

	if (write && ret == 0)
		ret = nf_hooks_lwtunnel_set(proc_nf_hooks_lwtunnel_enabled);

	return ret;
}
EXPORT_SYMBOL_GPL(nf_hooks_lwtunnel_sysctl_handler);

static const struct sysctl_field nf_lwtunnel_sysctl_table[] = {
	SYSCTL_FIELD_CUSTOM("nf_hooks_lwtunnel", 0644, sizeof(int), NULL,
			 nf_hooks_lwtunnel_sysctl_handler),
};

static int __net_init nf_lwtunnel_net_init(struct net *net)
{
	struct sysctl_context ctx = {
		.ns.net_ns = net,
	};
	struct ctl_table_header *hdr;

	hdr = register_sysctl_fields(&net->sysctls, "net/netfilter",
				     nf_lwtunnel_sysctl_table, &ctx);
	if (!hdr)
		return -ENOMEM;

	net->nf.nf_lwtnl_dir_header = hdr;

	return 0;
}

static void __net_exit nf_lwtunnel_net_exit(struct net *net)
{
	unregister_net_sysctl_table(net->nf.nf_lwtnl_dir_header);
}

static struct pernet_operations nf_lwtunnel_net_ops = {
	.init = nf_lwtunnel_net_init,
	.exit = nf_lwtunnel_net_exit,
};

int __init netfilter_lwtunnel_init(void)
{
	return register_pernet_subsys(&nf_lwtunnel_net_ops);
}

void netfilter_lwtunnel_fini(void)
{
	unregister_pernet_subsys(&nf_lwtunnel_net_ops);
}
#else
int __init netfilter_lwtunnel_init(void) { return 0; }
void netfilter_lwtunnel_fini(void) {}
#endif /* CONFIG_SYSCTL */

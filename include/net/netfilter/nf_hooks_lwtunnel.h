#include <linux/sysctl.h>
#include <linux/types.h>

#ifdef CONFIG_SYSCTL
int nf_hooks_lwtunnel_sysctl_handler(struct ctl_context *ctx,
				     void *buffer, size_t *lenp, loff_t *ppos);
#endif

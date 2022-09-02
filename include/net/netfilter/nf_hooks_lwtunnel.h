#include <linux/sysctl.h>
#include <linux/types.h>

#ifdef CONFIG_SYSCTL
extern struct ctl_fops nf_hooks_lwtunnel_sysctl_fops;
#endif

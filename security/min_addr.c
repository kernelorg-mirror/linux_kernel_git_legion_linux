// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/security.h>
#include <linux/sysctl.h>

/* amount of vm to protect from userspace access by both DAC and the LSM*/
unsigned long mmap_min_addr;
/* amount of vm to protect from userspace using CAP_SYS_RAWIO (DAC) */
unsigned long dac_mmap_min_addr = CONFIG_DEFAULT_MMAP_MIN_ADDR;
/* amount of vm to protect from userspace using the LSM = CONFIG_LSM_MMAP_MIN_ADDR */

/*
 * Update mmap_min_addr = max(dac_mmap_min_addr, CONFIG_LSM_MMAP_MIN_ADDR)
 */
static void update_mmap_min_addr(void)
{
#ifdef CONFIG_LSM_MMAP_MIN_ADDR
	if (dac_mmap_min_addr > CONFIG_LSM_MMAP_MIN_ADDR)
		mmap_min_addr = dac_mmap_min_addr;
	else
		mmap_min_addr = CONFIG_LSM_MMAP_MIN_ADDR;
#else
	mmap_min_addr = dac_mmap_min_addr;
#endif
}

/*
 * sysctl operations which just sets dac_mmap_min_addr = the new value and then
 * calls update_mmap_min_addr() so non MAP_FIXED hints get rounded properly
 */
static ssize_t sysctl_write_dac_mmap_min_addr(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos)
{
	ssize_t ret;

	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;

	ret = sysctl_write_ulongvec(ctx, file, buffer, lenp, ppos);

	update_mmap_min_addr();

	return ret;
}

static ssize_t sysctl_read_dac_mmap_min_addr(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos)
{
	ssize_t ret;

	ret = sysctl_read_ulongvec(ctx, file, buffer, lenp, ppos);

	update_mmap_min_addr();

	return ret;
}

struct ctl_fops sysctl_dac_mmap_min_addr_fops = {
	.read  = sysctl_read_dac_mmap_min_addr,
	.write = sysctl_write_dac_mmap_min_addr,
};

static int __init init_mmap_min_addr(void)
{
	update_mmap_min_addr();

	return 0;
}
pure_initcall(init_mmap_min_addr);

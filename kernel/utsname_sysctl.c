// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 2007
 *
 *  Author: Eric Biederman <ebiederm@xmision.com>
 */

#include <linux/export.h>
#include <linux/uts.h>
#include <linux/utsname.h>
#include <linux/sysctl.h>
#include <linux/wait.h>
#include <linux/rwsem.h>

#ifdef CONFIG_PROC_SYSCTL

static void *get_uts(struct ctl_table *table)
{
	char *which = table->data;
	struct uts_namespace *uts_ns;

	uts_ns = current->nsproxy->uts_ns;
	which = (which - (char *)&init_uts_ns) + (char *)uts_ns;

	return which;
}

/*
 *	Special case of dostring for the UTS structure. This has locks
 *	to observe. Should this be in kernel/sys.c ????
 */
static ssize_t sysctl_write_uts_value(struct ctl_context *ctx, struct file *file,
				      char *buffer, size_t *lenp, loff_t *ppos)
{
	ssize_t r;
	char tmp_data[__NEW_UTS_LEN + 1];

	/*
	 * Buffer the value in tmp_data so that proc_dostring() can be called
	 * without holding any locks.
	 * We also need to read the original value in the write==1 case to
	 * support partial writes.
	 */
	down_read(&uts_sem);
	memcpy(tmp_data, get_uts(ctx->ctl_table), sizeof(tmp_data));
	up_read(&uts_sem);

	r = sysctl_write_string_data(tmp_data, sizeof(tmp_data), ctx->ctl_table,
			buffer, lenp, ppos);

	/*
	 * Write back the new value.
	 * Note that, since we dropped uts_sem, the result can
	 * theoretically be incorrect if there are two parallel writes
	 * at non-zero offsets to the same sysctl.
	 */
	down_write(&uts_sem);
	memcpy(get_uts(ctx->ctl_table), tmp_data, sizeof(tmp_data));
	up_write(&uts_sem);

	proc_sys_poll_notify(ctx->ctl_table->poll);

	return r;
}

static ssize_t sysctl_read_uts_value(struct ctl_context *ctx, struct file *file,
				     char *buffer, size_t *lenp, loff_t *ppos)
{
	char tmp_data[__NEW_UTS_LEN + 1];

	down_read(&uts_sem);
	memcpy(tmp_data, get_uts(ctx->ctl_table), sizeof(tmp_data));
	up_read(&uts_sem);

	return sysctl_read_string_data(tmp_data, sizeof(tmp_data), ctx->ctl_table,
			buffer, lenp, ppos);
}
#else
#define sysctl_read_uts_value NULL
#define sysctl_write_uts_value NULL
#endif

static struct ctl_fops sysctl_uts_value_fops = {
	.read  = sysctl_read_uts_value,
	.write = sysctl_write_uts_value,
};

static DEFINE_CTL_TABLE_POLL(hostname_poll);
static DEFINE_CTL_TABLE_POLL(domainname_poll);

static struct ctl_table uts_kern_table[] = {
	{
		.procname	= "ostype",
		.data		= init_uts_ns.name.sysname,
		.maxlen		= sizeof(init_uts_ns.name.sysname),
		.mode		= 0444,
		.ctl_fops	= &sysctl_uts_value_fops,
	},
	{
		.procname	= "osrelease",
		.data		= init_uts_ns.name.release,
		.maxlen		= sizeof(init_uts_ns.name.release),
		.mode		= 0444,
		.ctl_fops	= &sysctl_uts_value_fops,
	},
	{
		.procname	= "version",
		.data		= init_uts_ns.name.version,
		.maxlen		= sizeof(init_uts_ns.name.version),
		.mode		= 0444,
		.ctl_fops	= &sysctl_uts_value_fops,
	},
	{
		.procname	= "hostname",
		.data		= init_uts_ns.name.nodename,
		.maxlen		= sizeof(init_uts_ns.name.nodename),
		.mode		= 0644,
		.ctl_fops	= &sysctl_uts_value_fops,
		.poll		= &hostname_poll,
	},
	{
		.procname	= "domainname",
		.data		= init_uts_ns.name.domainname,
		.maxlen		= sizeof(init_uts_ns.name.domainname),
		.mode		= 0644,
		.ctl_fops	= &sysctl_uts_value_fops,
		.poll		= &domainname_poll,
	},
	{}
};

static struct ctl_table uts_root_table[] = {
	{
		.procname	= "kernel",
		.mode		= 0555,
		.child		= uts_kern_table,
	},
	{}
};

#ifdef CONFIG_PROC_SYSCTL
/*
 * Notify userspace about a change in a certain entry of uts_kern_table,
 * identified by the parameter proc.
 */
void uts_proc_notify(enum uts_proc proc)
{
	struct ctl_table *table = &uts_kern_table[proc];

	proc_sys_poll_notify(table->poll);
}
#endif

static int __init utsname_sysctl_init(void)
{
	register_sysctl_table(uts_root_table);
	return 0;
}

device_initcall(utsname_sysctl_init);

// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 2007 IBM Corporation
 *
 *  Author: Cedric Le Goater <clg@fr.ibm.com>
 */

#include <linux/nsproxy.h>
#include <linux/ipc_namespace.h>
#include <linux/sysctl.h>

#include <linux/stat.h>
#include <linux/capability.h>
#include <linux/slab.h>

static void *mq_sys_get_value(struct ctl_context *ctx, struct file *file);
static int mq_sys_open(struct ctl_context *ctx, struct inode *inode, struct file *file);

static struct ctl_fops mq_sys_fops = {
	.open		= mq_sys_open,
	.get_value	= mq_sys_get_value,
	.read		= proc_sys_read_handler,
	.write		= proc_sys_write_handler,
};

enum {
	MQ_SYSCTL_QUEUES_MAX,
	MQ_SYSCTL_MSG_MAX,
	MQ_SYSCTL_MSGSIZE_MAX,
	MQ_SYSCTL_MSG_DEFAULT,
	MQ_SYSCTL_MSGSIZE_DEFAULT,
	MQ_SYSCTL_COUNTS
};

static int msg_max_limit_min = MIN_MSGMAX;
static int msg_max_limit_max = HARD_MSGMAX;

static int msg_maxsize_limit_min = MIN_MSGSIZEMAX;
static int msg_maxsize_limit_max = HARD_MSGSIZEMAX;

static struct ctl_table mq_sysctls[] = {
	[MQ_SYSCTL_QUEUES_MAX] = {
		.procname	= "queues_max",
		.data		= &init_ipc_ns.mq_queues_max,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.ctl_fops	= &mq_sys_fops,
	},
	[MQ_SYSCTL_MSG_MAX] = {
		.procname	= "msg_max",
		.data		= &init_ipc_ns.mq_msg_max,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &msg_max_limit_min,
		.extra2		= &msg_max_limit_max,
		.ctl_fops	= &mq_sys_fops,
	},
	[MQ_SYSCTL_MSGSIZE_MAX] = {
		.procname	= "msgsize_max",
		.data		= &init_ipc_ns.mq_msgsize_max,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &msg_maxsize_limit_min,
		.extra2		= &msg_maxsize_limit_max,
		.ctl_fops	= &mq_sys_fops,
	},
	[MQ_SYSCTL_MSG_DEFAULT] = {
		.procname	= "msg_default",
		.data		= &init_ipc_ns.mq_msg_default,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &msg_max_limit_min,
		.extra2		= &msg_max_limit_max,
		.ctl_fops	= &mq_sys_fops,
	},
	[MQ_SYSCTL_MSGSIZE_DEFAULT] = {
		.procname	= "msgsize_default",
		.data		= &init_ipc_ns.mq_msgsize_default,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &msg_maxsize_limit_min,
		.extra2		= &msg_maxsize_limit_max,
		.ctl_fops	= &mq_sys_fops,
	},
	{}
};

static int mq_sys_open(struct ctl_context *ctx, struct inode *inode, struct file *file)
{
	ctx->ipc_ns = current->nsproxy->ipc_ns;
	return 0;
}

static void *mq_sys_get_value(struct ctl_context *ctx, struct file *file)
{
	switch (ctx->ctl_table - mq_sysctls) {
		case MQ_SYSCTL_QUEUES_MAX:      return &ctx->ipc_ns->mq_queues_max;
		case MQ_SYSCTL_MSG_MAX:         return &ctx->ipc_ns->mq_msg_max;
		case MQ_SYSCTL_MSGSIZE_MAX:     return &ctx->ipc_ns->mq_msgsize_max;
		case MQ_SYSCTL_MSG_DEFAULT:     return &ctx->ipc_ns->mq_msg_default;
		case MQ_SYSCTL_MSGSIZE_DEFAULT: return &ctx->ipc_ns->mq_msgsize_default;
	}
	return NULL;
}

static struct ctl_table mq_sysctl_dir[] = {
	{
		.procname       = "mqueue",
		.mode           = 0555,
		.child          = mq_sysctls,
	},
	{}
};

static struct ctl_table mq_sysctl_root[] = {
	{
		.procname       = "fs",
		.mode           = 0555,
		.child          = mq_sysctl_dir,
	},
	{}
};

static int __init mq_sysctl_init(void)
{
	register_sysctl_table(mq_sysctl_root);
	return 0;
}

device_initcall(mq_sysctl_init);

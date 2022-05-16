// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 2007
 *
 *  Author: Eric Biederman <ebiederm@xmision.com>
 */

#include <linux/module.h>
#include <linux/ipc.h>
#include <linux/nsproxy.h>
#include <linux/sysctl.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/ipc_namespace.h>
#include <linux/msg.h>
#include <linux/slab.h>
#include "util.h"

static int proc_ipc_dointvec_minmax_orphans(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ipc_namespace *ns =
		container_of(table->data, struct ipc_namespace, shm_rmid_forced);
	int err;

	err = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (err < 0)
		return err;
	if (ns->shm_rmid_forced)
		shm_destroy_orphaned(ns);
	return err;
}

static int proc_ipc_auto_msgmni(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table ipc_table;
	int dummy = 0;

	memcpy(&ipc_table, table, sizeof(ipc_table));
	ipc_table.data = &dummy;

	if (write)
		pr_info_once("writing to auto_msgmni has no effect");

	return proc_dointvec_minmax(&ipc_table, write, buffer, lenp, ppos);
}

static int proc_ipc_sem_dointvec(struct ctl_table *table, int write,
	void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ipc_namespace *ns =
		container_of(table->data, struct ipc_namespace, sem_ctls);
	int ret, semmni;

	semmni = ns->sem_ctls[3];
	ret = proc_dointvec(table, write, buffer, lenp, ppos);

	if (!ret)
		ret = sem_check_semmni(ns);

	/*
	 * Reset the semmni value if an error happens.
	 */
	if (ret)
		ns->sem_ctls[3] = semmni;
	return ret;
}

static inline void *data_from_ns(struct ctl_context *ctx, struct ctl_table *table);

static int ipc_sys_open(struct ctl_context *ctx, struct inode *inode, struct file *file)
{
	struct ipc_namespace *ns = current->nsproxy->ipc_ns;

	// For now, we only allow changes in init_user_ns.
	if (ns->user_ns != &init_user_ns)
		return -EPERM;

#ifdef CONFIG_CHECKPOINT_RESTORE
	int index = (ctx->table - ipc_sysctls);

	switch (index) {
		case IPC_SYSCTL_SEM_NEXT_ID:
		case IPC_SYSCTL_MSG_NEXT_ID:
		case IPC_SYSCTL_SHM_NEXT_ID:
			if (!checkpoint_restore_ns_capable(ns->user_ns))
				return -EPERM;
			break;
	}
#endif
	ctx->ctl_data = ns;
	return 0;
}

static ssize_t ipc_sys_read(struct ctl_context *ctx, struct file *file,
		     char *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table table = *ctx->table;
	table.data = data_from_ns(ctx, ctx->table);
	return table.proc_handler(&table, 0, buffer, lenp, ppos);
}

static ssize_t ipc_sys_write(struct ctl_context *ctx, struct file *file,
		      char *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table table = *ctx->table;
	table.data = data_from_ns(ctx, ctx->table);
	return table.proc_handler(&table, 1, buffer, lenp, ppos);
}

static struct ctl_fops ipc_sys_fops = {
	.open	= ipc_sys_open,
	.read	= ipc_sys_read,
	.write	= ipc_sys_write,
};

int ipc_mni = IPCMNI;
int ipc_mni_shift = IPCMNI_SHIFT;
int ipc_min_cycle = RADIX_TREE_MAP_SIZE;

enum {
	IPC_SYSCTL_SHMMAX,
	IPC_SYSCTL_SHMALL,
	IPC_SYSCTL_SHMMNI,
	IPC_SYSCTL_SHM_RMID_FORCED,
	IPC_SYSCTL_MSGMAX,
	IPC_SYSCTL_MSGMNI,
	IPC_SYSCTL_AUTO_MSGMNI,
	IPC_SYSCTL_MSGMNB,
	IPC_SYSCTL_SEM,
#ifdef CONFIG_CHECKPOINT_RESTORE
	IPC_SYSCTL_SEM_NEXT_ID,
	IPC_SYSCTL_MSG_NEXT_ID,
	IPC_SYSCTL_SHM_NEXT_ID,
#endif
	IPC_SYSCTL_COUNTS
};

static struct ctl_table ipc_sysctls[] = {
	[IPC_SYSCTL_SHMMAX] = {
		.procname	= "shmmax",
		.data		= &init_ipc_ns.shm_ctlmax,
		.maxlen		= sizeof(init_ipc_ns.shm_ctlmax),
		.mode		= 0644,
		.proc_handler   = proc_doulongvec_minmax,
		.ctl_fops	= &ipc_sys_fops,
	},
	[IPC_SYSCTL_SHMALL] = {
		.procname	= "shmall",
		.data		= &init_ipc_ns.shm_ctlall,
		.maxlen		= sizeof(init_ipc_ns.shm_ctlall),
		.mode		= 0644,
		.proc_handler   = proc_doulongvec_minmax,
		.ctl_fops	= &ipc_sys_fops,
	},
	[IPC_SYSCTL_SHMMNI] = {
		.procname	= "shmmni",
		.data		= &init_ipc_ns.shm_ctlmni,
		.maxlen		= sizeof(init_ipc_ns.shm_ctlmni),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &ipc_mni,
		.ctl_fops	= &ipc_sys_fops,
	},
	[IPC_SYSCTL_SHM_RMID_FORCED] = {
		.procname	= "shm_rmid_forced",
		.data		= &init_ipc_ns.shm_rmid_forced,
		.maxlen		= sizeof(init_ipc_ns.shm_rmid_forced),
		.mode		= 0644,
		.proc_handler	= proc_ipc_dointvec_minmax_orphans,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
		.ctl_fops	= &ipc_sys_fops,
	},
	[IPC_SYSCTL_MSGMAX] = {
		.procname	= "msgmax",
		.data		= &init_ipc_ns.msg_ctlmax,
		.maxlen		= sizeof(init_ipc_ns.msg_ctlmax),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_INT_MAX,
		.ctl_fops	= &ipc_sys_fops,
	},
	[IPC_SYSCTL_MSGMNI] = {
		.procname	= "msgmni",
		.data		= &init_ipc_ns.msg_ctlmni,
		.maxlen		= sizeof(init_ipc_ns.msg_ctlmni),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &ipc_mni,
		.ctl_fops	= &ipc_sys_fops,
	},
	[IPC_SYSCTL_AUTO_MSGMNI] = {
		.procname	= "auto_msgmni",
		.data		= NULL,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_ipc_auto_msgmni,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
		.ctl_fops	= &ipc_sys_fops,
	},
	[IPC_SYSCTL_MSGMNB] = {
		.procname	=  "msgmnb",
		.data		= &init_ipc_ns.msg_ctlmnb,
		.maxlen		= sizeof(init_ipc_ns.msg_ctlmnb),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_INT_MAX,
		.ctl_fops	= &ipc_sys_fops,
	},
	[IPC_SYSCTL_SEM] = {
		.procname	= "sem",
		.data		= &init_ipc_ns.sem_ctls,
		.maxlen		= 4*sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_ipc_sem_dointvec,
		.ctl_fops	= &ipc_sys_fops,
	},
#ifdef CONFIG_CHECKPOINT_RESTORE
	[IPC_SYSCTL_SEM_NEXT_ID] = {
		.procname	= "sem_next_id",
		.data		= &init_ipc_ns.ids[IPC_SEM_IDS].next_id,
		.maxlen		= sizeof(init_ipc_ns.ids[IPC_SEM_IDS].next_id),
		.mode		= 0666,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_INT_MAX,
		.ctl_fops	= &ipc_sys_fops,
	},
	[IPC_SYSCTL_MSG_NEXT_ID] = {
		.procname	= "msg_next_id",
		.data		= &init_ipc_ns.ids[IPC_MSG_IDS].next_id,
		.maxlen		= sizeof(init_ipc_ns.ids[IPC_MSG_IDS].next_id),
		.mode		= 0666,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_INT_MAX,
		.ctl_fops	= &ipc_sys_fops,
	},
	[IPC_SYSCTL_SHM_NEXT_ID] = {
		.procname	= "shm_next_id",
		.data		= &init_ipc_ns.ids[IPC_SHM_IDS].next_id,
		.maxlen		= sizeof(init_ipc_ns.ids[IPC_SHM_IDS].next_id),
		.mode		= 0666,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_INT_MAX,
		.ctl_fops	= &ipc_sys_fops,
	},
#endif
	[IPC_SYSCTL_COUNTS] = {}
};

static inline void *data_from_ns(struct ctl_context *ctx, struct ctl_table *table)
{
	struct ipc_namespace *ns = ctx->ctl_data;

	switch (ctx->table - ipc_sysctls) {
		case IPC_SYSCTL_SHMMAX:			return &ns->shm_ctlmax;
		case IPC_SYSCTL_SHMALL:			return &ns->shm_ctlall;
		case IPC_SYSCTL_SHMMNI:			return &ns->shm_ctlmni;
		case IPC_SYSCTL_SHM_RMID_FORCED:	return &ns->shm_rmid_forced;
		case IPC_SYSCTL_MSGMAX:			return &ns->msg_ctlmax;
		case IPC_SYSCTL_MSGMNI:			return &ns->msg_ctlmni;
		case IPC_SYSCTL_MSGMNB:			return &ns->msg_ctlmnb;
		case IPC_SYSCTL_SEM:			return &ns->sem_ctls;
#ifdef CONFIG_CHECKPOINT_RESTORE
		case IPC_SYSCTL_SEM_NEXT_ID:		return &ns->ids[IPC_SEM_IDS].next_id;
		case IPC_SYSCTL_MSG_NEXT_ID:		return &ns->ids[IPC_MSG_IDS].next_id;
		case IPC_SYSCTL_SHM_NEXT_ID:		return &ns->ids[IPC_SHM_IDS].next_id;
#endif
	}
	return NULL;
}

static struct ctl_table ipc_root_table[] = {
	{
		.procname       = "kernel",
		.mode           = 0555,
		.child          = ipc_sysctls,
	},
	{}
};

static int __init ipc_sysctl_init(void)
{
	register_sysctl_table(ipc_root_table);
	return 0;
}

device_initcall(ipc_sysctl_init);

static int __init ipc_mni_extend(char *str)
{
	ipc_mni = IPCMNI_EXTEND;
	ipc_mni_shift = IPCMNI_EXTEND_SHIFT;
	ipc_min_cycle = IPCMNI_EXTEND_MIN_CYCLE;
	pr_info("IPCMNI extended to %d.\n", ipc_mni);
	return 0;
}
early_param("ipcmni_extend", ipc_mni_extend);

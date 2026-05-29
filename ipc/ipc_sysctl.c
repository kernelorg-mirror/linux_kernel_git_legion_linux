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
#include <linux/cred.h>
#include "util.h"

static int proc_ipc_dointvec_minmax_orphans(const struct ctl_table *table, int write,
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

static int proc_ipc_auto_msgmni(const struct ctl_table *table, int write,
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

static int proc_ipc_sem_dointvec(const struct ctl_table *table, int write,
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

int ipc_mni = IPCMNI;
int ipc_mni_shift = IPCMNI_SHIFT;
int ipc_min_cycle = RADIX_TREE_MAP_SIZE;

#define IPC_SYSCTL_DATA(name, member)				\
static void *name ## _data(const struct ctl_context *ctx)	\
{								\
	return &ctx->ns.ipc_ns->member;				\
}

IPC_SYSCTL_DATA(shm_ctlmax, shm_ctlmax);
IPC_SYSCTL_DATA(shm_ctlall, shm_ctlall);
IPC_SYSCTL_DATA(shm_ctlmni, shm_ctlmni);
IPC_SYSCTL_DATA(shm_rmid_forced, shm_rmid_forced);
IPC_SYSCTL_DATA(msg_ctlmax, msg_ctlmax);
IPC_SYSCTL_DATA(msg_ctlmni, msg_ctlmni);
IPC_SYSCTL_DATA(msg_ctlmnb, msg_ctlmnb);
IPC_SYSCTL_DATA(sem_ctls, sem_ctls);

#ifdef CONFIG_CHECKPOINT_RESTORE
IPC_SYSCTL_DATA(sem_next_id, ids[IPC_SEM_IDS].next_id);
IPC_SYSCTL_DATA(msg_next_id, ids[IPC_MSG_IDS].next_id);
IPC_SYSCTL_DATA(shm_next_id, ids[IPC_SHM_IDS].next_id);
#endif

static const struct ctl_field ipc_sysctls[] = {
	{
		.table = {
			.procname	= "shmmax",
			.maxlen		= sizeof(init_ipc_ns.shm_ctlmax),
			.mode		= 0644,
			.proc_handler	= proc_doulongvec_minmax,
		},
		.data = shm_ctlmax_data,
	},
	{
		.table = {
			.procname	= "shmall",
			.maxlen		= sizeof(init_ipc_ns.shm_ctlall),
			.mode		= 0644,
			.proc_handler	= proc_doulongvec_minmax,
		},
		.data = shm_ctlall_data,
	},
	{
		.table = {
			.procname	= "shmmni",
			.maxlen		= sizeof(init_ipc_ns.shm_ctlmni),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ZERO,
			.extra2		= &ipc_mni,
		},
		.data = shm_ctlmni_data,
	},
	{
		.table = {
			.procname	= "shm_rmid_forced",
			.maxlen		= sizeof(init_ipc_ns.shm_rmid_forced),
			.mode		= 0644,
			.proc_handler	= proc_ipc_dointvec_minmax_orphans,
			.extra1		= SYSCTL_ZERO,
			.extra2		= SYSCTL_ONE,
		},
		.data = shm_rmid_forced_data,
	},
	{
		.table = {
			.procname	= "msgmax",
			.maxlen		= sizeof(init_ipc_ns.msg_ctlmax),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ZERO,
			.extra2		= SYSCTL_INT_MAX,
		},
		.data = msg_ctlmax_data,
	},
	{
		.table = {
			.procname	= "msgmni",
			.maxlen		= sizeof(init_ipc_ns.msg_ctlmni),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ZERO,
			.extra2		= &ipc_mni,
		},
		.data = msg_ctlmni_data,
	},
	{
		.table = {
			.procname	= "auto_msgmni",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_ipc_auto_msgmni,
			.extra1		= SYSCTL_ZERO,
			.extra2		= SYSCTL_ONE,
		},
	},
	{
		.table = {
			.procname	=  "msgmnb",
			.maxlen		= sizeof(init_ipc_ns.msg_ctlmnb),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ZERO,
			.extra2		= SYSCTL_INT_MAX,
		},
		.data = msg_ctlmnb_data,
	},
	{
		.table = {
			.procname	= "sem",
			.maxlen		= sizeof(init_ipc_ns.sem_ctls),
			.mode		= 0644,
			.proc_handler	= proc_ipc_sem_dointvec,
		},
		.data = sem_ctls_data,
	},
#ifdef CONFIG_CHECKPOINT_RESTORE
	{
		.table = {
			.procname	= "sem_next_id",
			.maxlen		= sizeof(init_ipc_ns.ids[IPC_SEM_IDS].next_id),
			.mode		= 0444,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ZERO,
			.extra2		= SYSCTL_INT_MAX,
		},
		.data = sem_next_id_data,
	},
	{
		.table = {
			.procname	= "msg_next_id",
			.maxlen		= sizeof(init_ipc_ns.ids[IPC_MSG_IDS].next_id),
			.mode		= 0444,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ZERO,
			.extra2		= SYSCTL_INT_MAX,
		},
		.data = msg_next_id_data,
	},
	{
		.table = {
			.procname	= "shm_next_id",
			.maxlen		= sizeof(init_ipc_ns.ids[IPC_SHM_IDS].next_id),
			.mode		= 0444,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ZERO,
			.extra2		= SYSCTL_INT_MAX,
		},
		.data = shm_next_id_data,
	},
#endif
};

static struct ctl_table_set *set_lookup(struct ctl_table_root *root)
{
	return &current->nsproxy->ipc_ns->ipc_set;
}

static int set_is_seen(struct ctl_table_set *set)
{
	return &current->nsproxy->ipc_ns->ipc_set == set;
}

static void ipc_set_ownership(struct ctl_table_header *head,
			      kuid_t *uid, kgid_t *gid)
{
	struct ipc_namespace *ns =
		container_of(head->set, struct ipc_namespace, ipc_set);

	kuid_t ns_root_uid = make_kuid(ns->user_ns, 0);
	kgid_t ns_root_gid = make_kgid(ns->user_ns, 0);

	*uid = uid_valid(ns_root_uid) ? ns_root_uid : GLOBAL_ROOT_UID;
	*gid = gid_valid(ns_root_gid) ? ns_root_gid : GLOBAL_ROOT_GID;
}

static int ipc_permissions(struct ctl_table_header *head, const struct ctl_table *table)
{
	int mode = table->mode;

#ifdef CONFIG_CHECKPOINT_RESTORE
	struct ipc_namespace *ns =
		container_of(head->set, struct ipc_namespace, ipc_set);

	if (((table->data == &ns->ids[IPC_SEM_IDS].next_id) ||
	     (table->data == &ns->ids[IPC_MSG_IDS].next_id) ||
	     (table->data == &ns->ids[IPC_SHM_IDS].next_id)) &&
	    checkpoint_restore_ns_capable_noaudit(ns->user_ns))
		mode = 0666;
	else
#endif
	{
		kuid_t ns_root_uid;
		kgid_t ns_root_gid;

		ipc_set_ownership(head, &ns_root_uid, &ns_root_gid);

		if (uid_eq(current_euid(), ns_root_uid))
			mode >>= 6;

		else if (in_egroup_p(ns_root_gid))
			mode >>= 3;
	}

	mode &= 7;

	return (mode << 6) | (mode << 3) | mode;
}

static struct ctl_table_root set_root = {
	.lookup = set_lookup,
	.permissions = ipc_permissions,
	.set_ownership = ipc_set_ownership,
};

bool setup_ipc_sysctls(struct ipc_namespace *ns)
{
	struct ctl_context ctx = {
		.ns.ipc_ns = ns,
	};

	setup_sysctl_set(&ns->ipc_set, &set_root, set_is_seen);

	ns->ipc_sysctls = __register_sysctl_fields(&ns->ipc_set, "kernel",
						   ipc_sysctls,
						   ARRAY_SIZE(ipc_sysctls),
						   &ctx);
	if (!ns->ipc_sysctls) {
		retire_sysctl_set(&ns->ipc_set);
		return false;
	}

	return true;
}

void retire_ipc_sysctls(struct ipc_namespace *ns)
{
	unregister_sysctl_table(ns->ipc_sysctls);
	retire_sysctl_set(&ns->ipc_set);
}

static int __init ipc_sysctl_init(void)
{
	if (!setup_ipc_sysctls(&init_ipc_ns)) {
		pr_warn("ipc sysctl registration failed\n");
		return -ENOMEM;
	}
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

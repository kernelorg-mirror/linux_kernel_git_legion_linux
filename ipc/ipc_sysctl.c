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

int ipc_mni = IPCMNI;
int ipc_mni_shift = IPCMNI_SHIFT;
int ipc_min_cycle = RADIX_TREE_MAP_SIZE;

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

#define IPC_DATA(type, field)						\
static type *ipc_ ## field ## _data(const struct sysctl_context *ctx)	\
{									\
	return &ctx->ns.ipc_ns->field;					\
}

IPC_DATA(void, shm_ctlmax)
IPC_DATA(void, shm_ctlall)
IPC_DATA(int, shm_ctlmni)
IPC_DATA(void, shm_rmid_forced)
IPC_DATA(void, msg_ctlmax)
IPC_DATA(void, msg_ctlmni)
IPC_DATA(void, msg_ctlmnb)
IPC_DATA(void, sem_ctls)

#define IPC_LIMIT(name, value)						\
static void *ipc_ ## name ## _limit(const struct sysctl_context *ctx)	\
{									\
	return value;							\
}

IPC_LIMIT(zero, SYSCTL_ZERO)
IPC_LIMIT(one, SYSCTL_ONE)
IPC_LIMIT(int_max, SYSCTL_INT_MAX)
IPC_LIMIT(mni, &ipc_mni)

#define IPC_FIELD_CUSTOM_MINMAX(_procname, _len, _data, _handler, _min, _max) \
	{								\
		.procname = (_procname),				\
		.mode = 0644,						\
		.type = SYSCTL_FIELD_CUSTOM,				\
		.ctl_custom = {						\
			.proc_handler = (_handler),			\
			.maxlen = (_len),				\
			.data = (_data),				\
			.extra1 = (_min),				\
			.extra2 = (_max),				\
		},							\
	}

#ifdef CONFIG_CHECKPOINT_RESTORE
#define IPC_ID_NEXT_DATA(name, id)					\
static int *ipc_ ## name ## _data(const struct sysctl_context *ctx)	\
{									\
	return &ctx->ns.ipc_ns->ids[id].next_id;			\
}

IPC_ID_NEXT_DATA(sem_next_id, IPC_SEM_IDS)
IPC_ID_NEXT_DATA(msg_next_id, IPC_MSG_IDS)
IPC_ID_NEXT_DATA(shm_next_id, IPC_SHM_IDS)
#endif

static const struct sysctl_field ipc_sysctls[] = {
	SYSCTL_FIELD_CUSTOM("shmmax", 0644, sizeof(init_ipc_ns.shm_ctlmax),
			 ipc_shm_ctlmax_data, proc_doulongvec_minmax),
	SYSCTL_FIELD_CUSTOM("shmall", 0644, sizeof(init_ipc_ns.shm_ctlall),
			 ipc_shm_ctlall_data, proc_doulongvec_minmax),
	SYSCTL_FIELD_STATIC_INT_MINMAX("shmmni", 0644, ipc_shm_ctlmni_data,
				    SYSCTL_ZERO, &ipc_mni),
	IPC_FIELD_CUSTOM_MINMAX("shm_rmid_forced",
				sizeof(init_ipc_ns.shm_rmid_forced),
				ipc_shm_rmid_forced_data,
				proc_ipc_dointvec_minmax_orphans,
				ipc_zero_limit, ipc_one_limit),
	IPC_FIELD_CUSTOM_MINMAX("msgmax", sizeof(init_ipc_ns.msg_ctlmax),
				ipc_msg_ctlmax_data, proc_dointvec_minmax,
				ipc_zero_limit, ipc_int_max_limit),
	IPC_FIELD_CUSTOM_MINMAX("msgmni", sizeof(init_ipc_ns.msg_ctlmni),
				ipc_msg_ctlmni_data, proc_dointvec_minmax,
				ipc_zero_limit, ipc_mni_limit),
	IPC_FIELD_CUSTOM_MINMAX("auto_msgmni", sizeof(int), NULL,
				proc_ipc_auto_msgmni,
				ipc_zero_limit, ipc_one_limit),
	IPC_FIELD_CUSTOM_MINMAX("msgmnb", sizeof(init_ipc_ns.msg_ctlmnb),
				ipc_msg_ctlmnb_data, proc_dointvec_minmax,
				ipc_zero_limit, ipc_int_max_limit),
	SYSCTL_FIELD_CUSTOM("sem", 0644, 4 * sizeof(int), ipc_sem_ctls_data,
			 proc_ipc_sem_dointvec),
#ifdef CONFIG_CHECKPOINT_RESTORE
	SYSCTL_FIELD_STATIC_INT_MINMAX("sem_next_id", 0444,
				    ipc_sem_next_id_data, SYSCTL_ZERO,
				    SYSCTL_INT_MAX),
	SYSCTL_FIELD_STATIC_INT_MINMAX("msg_next_id", 0444,
				    ipc_msg_next_id_data, SYSCTL_ZERO,
				    SYSCTL_INT_MAX),
	SYSCTL_FIELD_STATIC_INT_MINMAX("shm_next_id", 0444,
				    ipc_shm_next_id_data, SYSCTL_ZERO,
				    SYSCTL_INT_MAX),
#endif
};

#undef IPC_FIELD_CUSTOM_MINMAX
#undef IPC_LIMIT

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
	struct sysctl_context ctx = {
		.ns.ipc_ns = ns,
	};

	setup_sysctl_set(&ns->ipc_set, &set_root, set_is_seen);

	ns->ipc_sysctls = register_sysctl_fields(&ns->ipc_set, "kernel",
						 ipc_sysctls, &ctx);
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

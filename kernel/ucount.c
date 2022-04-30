// SPDX-License-Identifier: GPL-2.0-only

#include <linux/stat.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/hash.h>
#include <linux/kmemleak.h>
#include <linux/user_namespace.h>

struct ucounts init_ucounts = {
	.ns    = &init_user_ns,
	.uid   = GLOBAL_ROOT_UID,
	.count = ATOMIC_INIT(1),
};

#define UCOUNTS_HASHTABLE_BITS 10
static struct hlist_head ucounts_hashtable[(1 << UCOUNTS_HASHTABLE_BITS)];
static DEFINE_SPINLOCK(ucounts_lock);

#define ucounts_hashfn(ns, uid)						\
	hash_long((unsigned long)__kuid_val(uid) + (unsigned long)(ns), \
		  UCOUNTS_HASHTABLE_BITS)
#define ucounts_hashentry(ns, uid)	\
	(ucounts_hashtable + ucounts_hashfn(ns, uid))


static int proc_ucounts_doulongvec_minmax(struct ctl_context *ctx,
					  struct ctl_table *table, int write,
					  void *buf, size_t *lenp, loff_t *ppos)
{
	struct user_namespace *user_ns = container_of(ctx->ctl_ns, struct user_namespace, ns);
	struct ctl_table tbl;

	if (write && !ns_capable(user_ns, CAP_SYS_RESOURCE))
		return -EPERM;

	tbl = *table;
	tbl.data = &user_ns->ucount_max[ctx->ctl_table->index];

	return proc_doulongvec_minmax(ctx, &tbl, write, buf, lenp, ppos);
}

static long ue_zero = 0;
static long ue_int_max = INT_MAX;

#define UCOUNT_ENTRY(name, idx)					\
	{							\
		.procname	= name,				\
		.maxlen		= sizeof(long),			\
		.mode		= 0644,				\
		.proc_handler	= proc_ucounts_doulongvec_minmax,	\
		.extra1		= &ue_zero,			\
		.extra2		= &ue_int_max,			\
		.ns_type	= CTL_USER_NS,			\
		.index		= idx,				\
	}
static struct ctl_table user_table[] = {
	UCOUNT_ENTRY("max_user_namespaces",   UCOUNT_USER_NAMESPACES),
	UCOUNT_ENTRY("max_pid_namespaces",    UCOUNT_PID_NAMESPACES),
	UCOUNT_ENTRY("max_uts_namespaces",    UCOUNT_UTS_NAMESPACES),
	UCOUNT_ENTRY("max_ipc_namespaces",    UCOUNT_IPC_NAMESPACES),
	UCOUNT_ENTRY("max_net_namespaces",    UCOUNT_NET_NAMESPACES),
	UCOUNT_ENTRY("max_mnt_namespaces",    UCOUNT_MNT_NAMESPACES),
	UCOUNT_ENTRY("max_cgroup_namespaces", UCOUNT_CGROUP_NAMESPACES),
	UCOUNT_ENTRY("max_time_namespaces",   UCOUNT_TIME_NAMESPACES),
#ifdef CONFIG_INOTIFY_USER
	UCOUNT_ENTRY("max_inotify_instances", UCOUNT_INOTIFY_INSTANCES),
	UCOUNT_ENTRY("max_inotify_watches",   UCOUNT_INOTIFY_WATCHES),
#endif
#ifdef CONFIG_FANOTIFY
	UCOUNT_ENTRY("max_fanotify_groups",   UCOUNT_FANOTIFY_GROUPS),
	UCOUNT_ENTRY("max_fanotify_marks",    UCOUNT_FANOTIFY_MARKS),
#endif
	{ },
	{ },
	{ },
	{ },
	{ }
};

static struct ctl_table user_sysctl_root[] = {
	{
		.procname	= "user",
		.mode		= 0555,
		.child		= user_table,
	},
	{}
};

struct ctl_table_header *user_register_sysctl_table(void)
{
	return register_sysctl_table(user_sysctl_root);
}

static struct ucounts *find_ucounts(struct user_namespace *ns, kuid_t uid, struct hlist_head *hashent)
{
	struct ucounts *ucounts;

	hlist_for_each_entry(ucounts, hashent, node) {
		if (uid_eq(ucounts->uid, uid) && (ucounts->ns == ns))
			return ucounts;
	}
	return NULL;
}

static void hlist_add_ucounts(struct ucounts *ucounts)
{
	struct hlist_head *hashent = ucounts_hashentry(ucounts->ns, ucounts->uid);
	spin_lock_irq(&ucounts_lock);
	hlist_add_head(&ucounts->node, hashent);
	spin_unlock_irq(&ucounts_lock);
}

static inline bool get_ucounts_or_wrap(struct ucounts *ucounts)
{
	/* Returns true on a successful get, false if the count wraps. */
	return !atomic_add_negative(1, &ucounts->count);
}

struct ucounts *get_ucounts(struct ucounts *ucounts)
{
	if (!get_ucounts_or_wrap(ucounts)) {
		put_ucounts(ucounts);
		ucounts = NULL;
	}
	return ucounts;
}

struct ucounts *alloc_ucounts(struct user_namespace *ns, kuid_t uid)
{
	struct hlist_head *hashent = ucounts_hashentry(ns, uid);
	struct ucounts *ucounts, *new;
	bool wrapped;

	spin_lock_irq(&ucounts_lock);
	ucounts = find_ucounts(ns, uid, hashent);
	if (!ucounts) {
		spin_unlock_irq(&ucounts_lock);

		new = kzalloc(sizeof(*new), GFP_KERNEL);
		if (!new)
			return NULL;

		new->ns = ns;
		new->uid = uid;
		atomic_set(&new->count, 1);

		spin_lock_irq(&ucounts_lock);
		ucounts = find_ucounts(ns, uid, hashent);
		if (ucounts) {
			kfree(new);
		} else {
			hlist_add_head(&new->node, hashent);
			get_user_ns(new->ns);
			spin_unlock_irq(&ucounts_lock);
			return new;
		}
	}
	wrapped = !get_ucounts_or_wrap(ucounts);
	spin_unlock_irq(&ucounts_lock);
	if (wrapped) {
		put_ucounts(ucounts);
		return NULL;
	}
	return ucounts;
}

void put_ucounts(struct ucounts *ucounts)
{
	unsigned long flags;

	if (atomic_dec_and_lock_irqsave(&ucounts->count, &ucounts_lock, flags)) {
		hlist_del_init(&ucounts->node);
		spin_unlock_irqrestore(&ucounts_lock, flags);
		put_user_ns(ucounts->ns);
		kfree(ucounts);
	}
}

static inline bool atomic_long_inc_below(atomic_long_t *v, int u)
{
	long c, old;
	c = atomic_long_read(v);
	for (;;) {
		if (unlikely(c >= u))
			return false;
		old = atomic_long_cmpxchg(v, c, c+1);
		if (likely(old == c))
			return true;
		c = old;
	}
}

struct ucounts *inc_ucount(struct user_namespace *ns, kuid_t uid,
			   enum ucount_type type)
{
	struct ucounts *ucounts, *iter, *bad;
	struct user_namespace *tns;
	ucounts = alloc_ucounts(ns, uid);
	for (iter = ucounts; iter; iter = tns->ucounts) {
		long max;
		tns = iter->ns;
		max = READ_ONCE(tns->ucount_max[type]);
		if (!atomic_long_inc_below(&iter->ucount[type], max))
			goto fail;
	}
	return ucounts;
fail:
	bad = iter;
	for (iter = ucounts; iter != bad; iter = iter->ns->ucounts)
		atomic_long_dec(&iter->ucount[type]);

	put_ucounts(ucounts);
	return NULL;
}

void dec_ucount(struct ucounts *ucounts, enum ucount_type type)
{
	struct ucounts *iter;
	for (iter = ucounts; iter; iter = iter->ns->ucounts) {
		long dec = atomic_long_dec_if_positive(&iter->ucount[type]);
		WARN_ON_ONCE(dec < 0);
	}
	put_ucounts(ucounts);
}

long inc_rlimit_ucounts(struct ucounts *ucounts, enum ucount_type type, long v)
{
	struct ucounts *iter;
	long max = LONG_MAX;
	long ret = 0;

	for (iter = ucounts; iter; iter = iter->ns->ucounts) {
		long new = atomic_long_add_return(v, &iter->ucount[type]);
		if (new < 0 || new > max)
			ret = LONG_MAX;
		else if (iter == ucounts)
			ret = new;
		max = READ_ONCE(iter->ns->ucount_max[type]);
	}
	return ret;
}

bool dec_rlimit_ucounts(struct ucounts *ucounts, enum ucount_type type, long v)
{
	struct ucounts *iter;
	long new = -1; /* Silence compiler warning */
	for (iter = ucounts; iter; iter = iter->ns->ucounts) {
		long dec = atomic_long_sub_return(v, &iter->ucount[type]);
		WARN_ON_ONCE(dec < 0);
		if (iter == ucounts)
			new = dec;
	}
	return (new == 0);
}

static void do_dec_rlimit_put_ucounts(struct ucounts *ucounts,
				struct ucounts *last, enum ucount_type type)
{
	struct ucounts *iter, *next;
	for (iter = ucounts; iter != last; iter = next) {
		long dec = atomic_long_sub_return(1, &iter->ucount[type]);
		WARN_ON_ONCE(dec < 0);
		next = iter->ns->ucounts;
		if (dec == 0)
			put_ucounts(iter);
	}
}

void dec_rlimit_put_ucounts(struct ucounts *ucounts, enum ucount_type type)
{
	do_dec_rlimit_put_ucounts(ucounts, NULL, type);
}

long inc_rlimit_get_ucounts(struct ucounts *ucounts, enum ucount_type type)
{
	/* Caller must hold a reference to ucounts */
	struct ucounts *iter;
	long max = LONG_MAX;
	long dec, ret = 0;

	for (iter = ucounts; iter; iter = iter->ns->ucounts) {
		long new = atomic_long_add_return(1, &iter->ucount[type]);
		if (new < 0 || new > max)
			goto unwind;
		if (iter == ucounts)
			ret = new;
		max = READ_ONCE(iter->ns->ucount_max[type]);
		/*
		 * Grab an extra ucount reference for the caller when
		 * the rlimit count was previously 0.
		 */
		if (new != 1)
			continue;
		if (!get_ucounts(iter))
			goto dec_unwind;
	}
	return ret;
dec_unwind:
	dec = atomic_long_sub_return(1, &iter->ucount[type]);
	WARN_ON_ONCE(dec < 0);
unwind:
	do_dec_rlimit_put_ucounts(ucounts, iter, type);
	return 0;
}

bool is_ucounts_overlimit(struct ucounts *ucounts, enum ucount_type type, unsigned long rlimit)
{
	struct ucounts *iter;
	long max = rlimit;
	if (rlimit > LONG_MAX)
		max = LONG_MAX;
	for (iter = ucounts; iter; iter = iter->ns->ucounts) {
		long val = get_ucounts_value(iter, type);
		if (val < 0 || val > max)
			return true;
		max = READ_ONCE(iter->ns->ucount_max[type]);
	}
	return false;
}

static __init int user_namespace_sysctl_init(void)
{
	BUG_ON(!user_register_sysctl_table());
	hlist_add_ucounts(&init_ucounts);
	inc_rlimit_ucounts(&init_ucounts, UCOUNT_RLIMIT_NPROC, 1);
	return 0;
}
subsys_initcall(user_namespace_sysctl_init);

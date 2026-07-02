// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/percpu.h>
#include <linux/netdevice.h>
#include <linux/security.h>
#include <net/net_namespace.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#include <net/netfilter/nf_log.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_timestamp.h>
#include <linux/rculist_nulls.h>

static bool enable_hooks __read_mostly;
MODULE_PARM_DESC(enable_hooks, "Always enable conntrack hooks");
module_param(enable_hooks, bool, 0000);

unsigned int nf_conntrack_net_id __read_mostly;

#ifdef CONFIG_NF_CONNTRACK_PROCFS
void
print_tuple(struct seq_file *s, const struct nf_conntrack_tuple *tuple,
            const struct nf_conntrack_l4proto *l4proto)
{
	switch (tuple->src.l3num) {
	case NFPROTO_IPV4:
		seq_printf(s, "src=%pI4 dst=%pI4 ",
			   &tuple->src.u3.ip, &tuple->dst.u3.ip);
		break;
	case NFPROTO_IPV6:
		seq_printf(s, "src=%pI6 dst=%pI6 ",
			   tuple->src.u3.ip6, tuple->dst.u3.ip6);
		break;
	default:
		break;
	}

	switch (l4proto->l4proto) {
	case IPPROTO_ICMP:
		seq_printf(s, "type=%u code=%u id=%u ",
			   tuple->dst.u.icmp.type,
			   tuple->dst.u.icmp.code,
			   ntohs(tuple->src.u.icmp.id));
		break;
	case IPPROTO_TCP:
		seq_printf(s, "sport=%hu dport=%hu ",
			   ntohs(tuple->src.u.tcp.port),
			   ntohs(tuple->dst.u.tcp.port));
		break;
	case IPPROTO_UDP:
		seq_printf(s, "sport=%hu dport=%hu ",
			   ntohs(tuple->src.u.udp.port),
			   ntohs(tuple->dst.u.udp.port));

		break;
	case IPPROTO_SCTP:
		seq_printf(s, "sport=%hu dport=%hu ",
			   ntohs(tuple->src.u.sctp.port),
			   ntohs(tuple->dst.u.sctp.port));
		break;
	case IPPROTO_ICMPV6:
		seq_printf(s, "type=%u code=%u id=%u ",
			   tuple->dst.u.icmp.type,
			   tuple->dst.u.icmp.code,
			   ntohs(tuple->src.u.icmp.id));
		break;
	case IPPROTO_GRE:
		seq_printf(s, "srckey=0x%x dstkey=0x%x ",
			   ntohs(tuple->src.u.gre.key),
			   ntohs(tuple->dst.u.gre.key));
		break;
	default:
		break;
	}
}
EXPORT_SYMBOL_GPL(print_tuple);

struct ct_iter_state {
	struct seq_net_private p;
	struct hlist_nulls_head *hash;
	unsigned int htable_size;
	unsigned int skip_elems;
	unsigned int bucket;
	u_int64_t time_now;
};

static struct nf_conntrack_tuple_hash *ct_get_next(const struct net *net,
						   struct ct_iter_state *st)
{
	struct nf_conntrack_tuple_hash *h;
	struct hlist_nulls_node *n;
	unsigned int i;

	for (i = st->bucket; i < st->htable_size; i++) {
		unsigned int skip = 0;

restart:
		hlist_nulls_for_each_entry_rcu(h, n, &st->hash[i], hnnode) {
			struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);
			struct hlist_nulls_node *tmp = n;

			if (!net_eq(net, nf_ct_net(ct)))
				continue;

			if (++skip <= st->skip_elems)
				continue;

			/* h should be returned, skip to nulls marker. */
			while (!is_a_nulls(tmp))
				tmp = rcu_dereference(hlist_nulls_next_rcu(tmp));

			/* check if h is still linked to hash[i] */
			if (get_nulls_value(tmp) != i) {
				skip = 0;
				goto restart;
			}

			st->skip_elems = skip;
			st->bucket = i;
			return h;
		}

		skip = 0;
		if (get_nulls_value(n) != i)
			goto restart;

		st->skip_elems = 0;
	}

	st->bucket = i;
	return NULL;
}

static void *ct_seq_start(struct seq_file *seq, loff_t *pos)
	__acquires(RCU)
{
	struct ct_iter_state *st = seq->private;
	struct net *net = seq_file_net(seq);

	st->time_now = ktime_get_real_ns();
	rcu_read_lock();

	nf_conntrack_get_ht(&st->hash, &st->htable_size);

	if (*pos == 0) {
		st->skip_elems = 0;
		st->bucket = 0;
	} else if (st->skip_elems) {
		/* resume from last dumped entry */
		st->skip_elems--;
	}

	return ct_get_next(net, st);
}

static void *ct_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct ct_iter_state *st = s->private;
	struct net *net = seq_file_net(s);

	(*pos)++;
	return ct_get_next(net, st);
}

static void ct_seq_stop(struct seq_file *s, void *v)
	__releases(RCU)
{
	rcu_read_unlock();
}

#ifdef CONFIG_NF_CONNTRACK_SECMARK
static void ct_show_secctx(struct seq_file *s, const struct nf_conn *ct)
{
	struct lsm_context ctx;
	int ret;

	ret = security_secid_to_secctx(ct->secmark, &ctx);
	if (ret < 0)
		return;

	seq_printf(s, "secctx=%s ", ctx.context);

	security_release_secctx(&ctx);
}
#else
static inline void ct_show_secctx(struct seq_file *s, const struct nf_conn *ct)
{
}
#endif

#ifdef CONFIG_NF_CONNTRACK_ZONES
static void ct_show_zone(struct seq_file *s, const struct nf_conn *ct,
			 int dir)
{
	const struct nf_conntrack_zone *zone = nf_ct_zone(ct);

	if (zone->dir != dir)
		return;
	switch (zone->dir) {
	case NF_CT_DEFAULT_ZONE_DIR:
		seq_printf(s, "zone=%u ", zone->id);
		break;
	case NF_CT_ZONE_DIR_ORIG:
		seq_printf(s, "zone-orig=%u ", zone->id);
		break;
	case NF_CT_ZONE_DIR_REPL:
		seq_printf(s, "zone-reply=%u ", zone->id);
		break;
	default:
		break;
	}
}
#else
static inline void ct_show_zone(struct seq_file *s, const struct nf_conn *ct,
				int dir)
{
}
#endif

#ifdef CONFIG_NF_CONNTRACK_TIMESTAMP
static void ct_show_delta_time(struct seq_file *s, const struct nf_conn *ct)
{
	struct ct_iter_state *st = s->private;
	struct nf_conn_tstamp *tstamp;
	s64 delta_time;

	tstamp = nf_conn_tstamp_find(ct);
	if (tstamp) {
		delta_time = st->time_now - tstamp->start;
		if (delta_time > 0)
			delta_time = div_s64(delta_time, NSEC_PER_SEC);
		else
			delta_time = 0;

		seq_printf(s, "delta-time=%llu ",
			   (unsigned long long)delta_time);
	}
	return;
}
#else
static inline void
ct_show_delta_time(struct seq_file *s, const struct nf_conn *ct)
{
}
#endif

static const char* l3proto_name(u16 proto)
{
	switch (proto) {
	case AF_INET: return "ipv4";
	case AF_INET6: return "ipv6";
	}

	return "unknown";
}

static const char* l4proto_name(u16 proto)
{
	switch (proto) {
	case IPPROTO_ICMP: return "icmp";
	case IPPROTO_TCP: return "tcp";
	case IPPROTO_UDP: return "udp";
	case IPPROTO_GRE: return "gre";
	case IPPROTO_SCTP: return "sctp";
	case IPPROTO_ICMPV6: return "icmpv6";
	}

	return "unknown";
}

static void
seq_print_acct(struct seq_file *s, const struct nf_conn *ct, int dir)
{
	struct nf_conn_acct *acct;
	struct nf_conn_counter *counter;

	acct = nf_conn_acct_find(ct);
	if (!acct)
		return;

	counter = acct->counter;
	seq_printf(s, "packets=%llu bytes=%llu ",
		   (unsigned long long)atomic64_read(&counter[dir].packets),
		   (unsigned long long)atomic64_read(&counter[dir].bytes));
}

/* return 0 on success, 1 in case of error */
static int ct_seq_show(struct seq_file *s, void *v)
{
	struct nf_conntrack_tuple_hash *hash = v;
	struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(hash);
	const struct nf_conntrack_l4proto *l4proto;
	struct net *net = seq_file_net(s);
	int ret = 0;

	WARN_ON(!ct);
	if (unlikely(!refcount_inc_not_zero(&ct->ct_general.use)))
		return 0;

	/* load ->status after refcount increase */
	smp_acquire__after_ctrl_dep();

	if (nf_ct_should_gc(ct)) {
		struct ct_iter_state *st = s->private;

		st->skip_elems--;
		nf_ct_kill(ct);
		goto release;
	}

	/* we only want to print DIR_ORIGINAL */
	if (NF_CT_DIRECTION(hash))
		goto release;

	if (!net_eq(nf_ct_net(ct), net))
		goto release;

	l4proto = nf_ct_l4proto_find(nf_ct_protonum(ct));

	ret = -ENOSPC;
	seq_printf(s, "%-8s %u %-8s %u ",
		   l3proto_name(nf_ct_l3num(ct)), nf_ct_l3num(ct),
		   l4proto_name(l4proto->l4proto), nf_ct_protonum(ct));

	if (!test_bit(IPS_OFFLOAD_BIT, &ct->status))
		seq_printf(s, "%ld ", nf_ct_expires(ct)  / HZ);

	if (l4proto->print_conntrack)
		l4proto->print_conntrack(s, ct);

	print_tuple(s, &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple,
		    l4proto);

	ct_show_zone(s, ct, NF_CT_ZONE_DIR_ORIG);

	if (seq_has_overflowed(s))
		goto release;

	seq_print_acct(s, ct, IP_CT_DIR_ORIGINAL);

	if (!(test_bit(IPS_SEEN_REPLY_BIT, &ct->status)))
		seq_puts(s, "[UNREPLIED] ");

	print_tuple(s, &ct->tuplehash[IP_CT_DIR_REPLY].tuple, l4proto);

	ct_show_zone(s, ct, NF_CT_ZONE_DIR_REPL);

	seq_print_acct(s, ct, IP_CT_DIR_REPLY);

	if (test_bit(IPS_HW_OFFLOAD_BIT, &ct->status))
		seq_puts(s, "[HW_OFFLOAD] ");
	else if (test_bit(IPS_OFFLOAD_BIT, &ct->status))
		seq_puts(s, "[OFFLOAD] ");
	else if (test_bit(IPS_ASSURED_BIT, &ct->status))
		seq_puts(s, "[ASSURED] ");

	if (seq_has_overflowed(s))
		goto release;

#if defined(CONFIG_NF_CONNTRACK_MARK)
	seq_printf(s, "mark=%u ", READ_ONCE(ct->mark));
#endif

	ct_show_secctx(s, ct);
	ct_show_zone(s, ct, NF_CT_DEFAULT_ZONE_DIR);
	ct_show_delta_time(s, ct);

	seq_printf(s, "use=%u\n", refcount_read(&ct->ct_general.use));

	if (seq_has_overflowed(s))
		goto release;

	ret = 0;
release:
	nf_ct_put(ct);
	return ret;
}

static const struct seq_operations ct_seq_ops = {
	.start = ct_seq_start,
	.next  = ct_seq_next,
	.stop  = ct_seq_stop,
	.show  = ct_seq_show
};

static void *ct_cpu_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct net *net = seq_file_net(seq);
	int cpu;

	if (*pos == 0)
		return SEQ_START_TOKEN;

	for (cpu = *pos-1; cpu < nr_cpu_ids; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu + 1;
		return per_cpu_ptr(net->ct.stat, cpu);
	}

	return NULL;
}

static void *ct_cpu_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct net *net = seq_file_net(seq);
	int cpu;

	for (cpu = *pos; cpu < nr_cpu_ids; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu + 1;
		return per_cpu_ptr(net->ct.stat, cpu);
	}
	(*pos)++;
	return NULL;
}

static void ct_cpu_seq_stop(struct seq_file *seq, void *v)
{
}

static int ct_cpu_seq_show(struct seq_file *seq, void *v)
{
	struct net *net = seq_file_net(seq);
	const struct ip_conntrack_stat *st = v;
	unsigned int nr_conntracks;

	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "entries  clashres found new invalid ignore delete chainlength insert insert_failed drop early_drop icmp_error  expect_new expect_create expect_delete search_restart\n");
		return 0;
	}

	nr_conntracks = nf_conntrack_count(net);

	seq_printf(seq, "%08x  %08x %08x %08x %08x %08x %08x %08x "
			"%08x %08x %08x %08x %08x  %08x %08x %08x %08x\n",
		   nr_conntracks,
		   st->clash_resolve,
		   st->found,
		   0,
		   st->invalid,
		   0,
		   0,
		   st->chaintoolong,
		   st->insert,
		   st->insert_failed,
		   st->drop,
		   st->early_drop,
		   st->error,

		   st->expect_new,
		   st->expect_create,
		   st->expect_delete,
		   st->search_restart
		);
	return 0;
}

static const struct seq_operations ct_cpu_seq_ops = {
	.start	= ct_cpu_seq_start,
	.next	= ct_cpu_seq_next,
	.stop	= ct_cpu_seq_stop,
	.show	= ct_cpu_seq_show,
};

static int nf_conntrack_standalone_init_proc(struct net *net)
{
	struct proc_dir_entry *pde;
	kuid_t root_uid;
	kgid_t root_gid;

	pde = proc_create_net("nf_conntrack", 0440, net->proc_net, &ct_seq_ops,
			sizeof(struct ct_iter_state));
	if (!pde)
		goto out_nf_conntrack;

	root_uid = make_kuid(net->user_ns, 0);
	root_gid = make_kgid(net->user_ns, 0);
	if (uid_valid(root_uid) && gid_valid(root_gid))
		proc_set_user(pde, root_uid, root_gid);

	pde = proc_create_net("nf_conntrack", 0444, net->proc_net_stat,
			&ct_cpu_seq_ops, sizeof(struct seq_net_private));
	if (!pde)
		goto out_stat_nf_conntrack;
	return 0;

out_stat_nf_conntrack:
	remove_proc_entry("nf_conntrack", net->proc_net);
out_nf_conntrack:
	return -ENOMEM;
}

static void nf_conntrack_standalone_fini_proc(struct net *net)
{
	remove_proc_entry("nf_conntrack", net->proc_net_stat);
	remove_proc_entry("nf_conntrack", net->proc_net);
}
#else
static int nf_conntrack_standalone_init_proc(struct net *net)
{
	return 0;
}

static void nf_conntrack_standalone_fini_proc(struct net *net)
{
}
#endif /* CONFIG_NF_CONNTRACK_PROCFS */

u32 nf_conntrack_count(const struct net *net)
{
	const struct nf_conntrack_net *cnet = nf_ct_pernet(net);

	return atomic_read(&cnet->count);
}
EXPORT_SYMBOL_GPL(nf_conntrack_count);

/* Sysctl support */

#ifdef CONFIG_SYSCTL
/* size the user *wants to set */
static unsigned int nf_conntrack_htable_size_user __read_mostly;

static int
nf_conntrack_hash_sysctl(const struct ctl_table *table, int write,
			 void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	/* module_param hashsize could have changed value */
	nf_conntrack_htable_size_user = nf_conntrack_htable_size;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (ret < 0 || !write)
		return ret;

	/* update ret, we might not be able to satisfy request */
	ret = nf_conntrack_hash_resize(nf_conntrack_htable_size_user);

	/* update it to the actual value used by conntrack */
	nf_conntrack_htable_size_user = nf_conntrack_htable_size;
	return ret;
}

static int
nf_conntrack_log_invalid_sysctl(const struct ctl_table *table, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret, i;

	ret = proc_dou8vec_minmax(table, write, buffer, lenp, ppos);
	if (ret < 0 || !write)
		return ret;

	if (*(u8 *)table->data == 0)
		return 0;

	/* Load nf_log_syslog only if no logger is currently registered */
	for (i = 0; i < NFPROTO_NUMPROTO; i++) {
		if (nf_log_is_registered(i))
			return 0;
	}
	request_module("%s", "nf_log_syslog");

	return 0;
}

static struct ctl_table_header *nf_ct_netfilter_header;
static unsigned int nf_ct_max_limit = INT_MAX;

static umode_t nf_ct_global_sysctl_mode(const struct sysctl_context *ctx)
{
	return net_eq(ctx->ns.net_ns, &init_net) ? 0644 : 0444;
}

static unsigned int *nf_ct_max_data(const struct sysctl_context *ctx)
{
	return &nf_conntrack_max;
}

static void *nf_ct_count_data(const struct sysctl_context *ctx)
{
	struct nf_conntrack_net *cnet = nf_ct_pernet(ctx->ns.net_ns);

	return &cnet->count;
}

static void *nf_ct_buckets_data(const struct sysctl_context *ctx)
{
	return &nf_conntrack_htable_size_user;
}

static u8 *nf_ct_checksum_data(const struct sysctl_context *ctx)
{
	return &ctx->ns.net_ns->ct.sysctl_checksum;
}

static void *nf_ct_log_invalid_data(const struct sysctl_context *ctx)
{
	return &ctx->ns.net_ns->ct.sysctl_log_invalid;
}

static unsigned int *nf_ct_expect_max_data(const struct sysctl_context *ctx)
{
	return &nf_ct_expect_max;
}

static u8 *nf_ct_acct_data(const struct sysctl_context *ctx)
{
	return &ctx->ns.net_ns->ct.sysctl_acct;
}

#ifdef CONFIG_NF_CONNTRACK_EVENTS
static u8 *nf_ct_events_data(const struct sysctl_context *ctx)
{
	return &ctx->ns.net_ns->ct.sysctl_events;
}
#endif

#ifdef CONFIG_NF_CONNTRACK_TIMESTAMP
static u8 *nf_ct_timestamp_data(const struct sysctl_context *ctx)
{
	return &ctx->ns.net_ns->ct.sysctl_tstamp;
}
#endif

static void *nf_ct_generic_timeout_data(const struct sysctl_context *ctx)
{
	return &nf_generic_pernet(ctx->ns.net_ns)->timeout;
}

#define NF_CT_TCP_TIMEOUT_DATA(name, state)				\
static void *nf_ct_tcp_timeout_ ## name ## _data(const struct sysctl_context *ctx)	\
{									\
	struct nf_tcp_net *tn = nf_tcp_pernet(ctx->ns.net_ns);		\
	return &tn->timeouts[TCP_CONNTRACK_ ## state];			\
}

NF_CT_TCP_TIMEOUT_DATA(syn_sent, SYN_SENT)
NF_CT_TCP_TIMEOUT_DATA(syn_recv, SYN_RECV)
NF_CT_TCP_TIMEOUT_DATA(established, ESTABLISHED)
NF_CT_TCP_TIMEOUT_DATA(fin_wait, FIN_WAIT)
NF_CT_TCP_TIMEOUT_DATA(close_wait, CLOSE_WAIT)
NF_CT_TCP_TIMEOUT_DATA(last_ack, LAST_ACK)
NF_CT_TCP_TIMEOUT_DATA(time_wait, TIME_WAIT)
NF_CT_TCP_TIMEOUT_DATA(close, CLOSE)
NF_CT_TCP_TIMEOUT_DATA(retrans, RETRANS)
NF_CT_TCP_TIMEOUT_DATA(unack, UNACK)
#undef NF_CT_TCP_TIMEOUT_DATA

#if IS_ENABLED(CONFIG_NF_FLOW_TABLE)
static void *nf_ct_tcp_offload_timeout_data(const struct sysctl_context *ctx)
{
	return &nf_tcp_pernet(ctx->ns.net_ns)->offload_timeout;
}
#endif

#define NF_CT_TCP_U8_DATA(name, field)					\
static u8 *nf_ct_tcp_ ## name ## _data(const struct sysctl_context *ctx)	\
{									\
	return &nf_tcp_pernet(ctx->ns.net_ns)->field;			\
}

NF_CT_TCP_U8_DATA(loose, tcp_loose)
NF_CT_TCP_U8_DATA(liberal, tcp_be_liberal)
NF_CT_TCP_U8_DATA(ignore_invalid_rst, tcp_ignore_invalid_rst)
NF_CT_TCP_U8_DATA(max_retrans, tcp_max_retrans)
#undef NF_CT_TCP_U8_DATA

static void *nf_ct_udp_timeout_data(const struct sysctl_context *ctx)
{
	return &nf_udp_pernet(ctx->ns.net_ns)->timeouts[UDP_CT_UNREPLIED];
}

static void *nf_ct_udp_stream_timeout_data(const struct sysctl_context *ctx)
{
	return &nf_udp_pernet(ctx->ns.net_ns)->timeouts[UDP_CT_REPLIED];
}

#if IS_ENABLED(CONFIG_NF_FLOW_TABLE)
static void *nf_ct_udp_offload_timeout_data(const struct sysctl_context *ctx)
{
	return &nf_udp_pernet(ctx->ns.net_ns)->offload_timeout;
}
#endif

static void *nf_ct_icmp_timeout_data(const struct sysctl_context *ctx)
{
	return &nf_icmp_pernet(ctx->ns.net_ns)->timeout;
}

static void *nf_ct_icmpv6_timeout_data(const struct sysctl_context *ctx)
{
	return &nf_icmpv6_pernet(ctx->ns.net_ns)->timeout;
}

#ifdef CONFIG_NF_CT_PROTO_SCTP
#define NF_CT_SCTP_TIMEOUT_DATA(name, state)				\
static void *nf_ct_sctp_timeout_ ## name ## _data(const struct sysctl_context *ctx) \
{									\
	struct nf_sctp_net *sn = nf_sctp_pernet(ctx->ns.net_ns);	\
	return &sn->timeouts[SCTP_CONNTRACK_ ## state];			\
}

NF_CT_SCTP_TIMEOUT_DATA(closed, CLOSED)
NF_CT_SCTP_TIMEOUT_DATA(cookie_wait, COOKIE_WAIT)
NF_CT_SCTP_TIMEOUT_DATA(cookie_echoed, COOKIE_ECHOED)
NF_CT_SCTP_TIMEOUT_DATA(established, ESTABLISHED)
NF_CT_SCTP_TIMEOUT_DATA(shutdown_sent, SHUTDOWN_SENT)
NF_CT_SCTP_TIMEOUT_DATA(shutdown_recd, SHUTDOWN_RECD)
NF_CT_SCTP_TIMEOUT_DATA(shutdown_ack_sent, SHUTDOWN_ACK_SENT)
NF_CT_SCTP_TIMEOUT_DATA(heartbeat_sent, HEARTBEAT_SENT)
#undef NF_CT_SCTP_TIMEOUT_DATA
#endif

#ifdef CONFIG_NF_CT_PROTO_GRE
static void *nf_ct_gre_timeout_data(const struct sysctl_context *ctx)
{
	return &nf_gre_pernet(ctx->ns.net_ns)->timeouts[GRE_CT_UNREPLIED];
}

static void *nf_ct_gre_stream_timeout_data(const struct sysctl_context *ctx)
{
	return &nf_gre_pernet(ctx->ns.net_ns)->timeouts[GRE_CT_REPLIED];
}
#endif

#define NF_CT_GLOBAL_UINT_MINMAX(_procname, _data)			\
	{								\
		.procname	= (_procname),				\
		.mode		= 0644,					\
		.mode_fn	= nf_ct_global_sysctl_mode,		\
		.type		= SYSCTL_FIELD_STATIC_UINT_MINMAX,		\
		.ctl_static_uint = {					\
			.data		= (_data),			\
			.min_value	= SYSCTL_UINT_ONE,		\
			.max_value	= &nf_ct_max_limit,		\
		},							\
	}

static const struct sysctl_field nf_ct_sysctl_table[] = {
	NF_CT_GLOBAL_UINT_MINMAX("nf_conntrack_max", nf_ct_max_data),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_count", 0444, sizeof(int),
			 nf_ct_count_data, proc_dointvec),
	SYSCTL_FIELD_CUSTOM_MODE("nf_conntrack_buckets", 0644,
			      nf_ct_global_sysctl_mode,
			      sizeof(unsigned int),
			      nf_ct_buckets_data,
			      nf_conntrack_hash_sysctl),
	SYSCTL_FIELD_STATIC_U8_MINMAX("nf_conntrack_checksum", 0644,
				   nf_ct_checksum_data, SYSCTL_UINT_ZERO,
				   SYSCTL_UINT_ONE),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_log_invalid", 0644, sizeof(u8),
			 nf_ct_log_invalid_data,
			 nf_conntrack_log_invalid_sysctl),
	NF_CT_GLOBAL_UINT_MINMAX("nf_conntrack_expect_max",
				 nf_ct_expect_max_data),
	SYSCTL_FIELD_STATIC_U8_MINMAX("nf_conntrack_acct", 0644,
				   nf_ct_acct_data, SYSCTL_UINT_ZERO,
				   SYSCTL_UINT_ONE),
#ifdef CONFIG_NF_CONNTRACK_EVENTS
	SYSCTL_FIELD_STATIC_U8_MINMAX("nf_conntrack_events", 0644,
				   nf_ct_events_data, SYSCTL_UINT_ZERO,
				   SYSCTL_UINT_TWO),
#endif
#ifdef CONFIG_NF_CONNTRACK_TIMESTAMP
	SYSCTL_FIELD_STATIC_U8_MINMAX("nf_conntrack_timestamp", 0644,
				   nf_ct_timestamp_data,
				   SYSCTL_UINT_ZERO,
				   SYSCTL_UINT_ONE),
#endif
	SYSCTL_FIELD_CUSTOM("nf_conntrack_generic_timeout", 0644,
			 sizeof(unsigned int),
			 nf_ct_generic_timeout_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_tcp_timeout_syn_sent", 0644,
			 sizeof(unsigned int),
			 nf_ct_tcp_timeout_syn_sent_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_tcp_timeout_syn_recv", 0644,
			 sizeof(unsigned int),
			 nf_ct_tcp_timeout_syn_recv_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_tcp_timeout_established", 0644,
			 sizeof(unsigned int),
			 nf_ct_tcp_timeout_established_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_tcp_timeout_fin_wait", 0644,
			 sizeof(unsigned int),
			 nf_ct_tcp_timeout_fin_wait_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_tcp_timeout_close_wait", 0644,
			 sizeof(unsigned int),
			 nf_ct_tcp_timeout_close_wait_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_tcp_timeout_last_ack", 0644,
			 sizeof(unsigned int),
			 nf_ct_tcp_timeout_last_ack_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_tcp_timeout_time_wait", 0644,
			 sizeof(unsigned int),
			 nf_ct_tcp_timeout_time_wait_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_tcp_timeout_close", 0644,
			 sizeof(unsigned int),
			 nf_ct_tcp_timeout_close_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_tcp_timeout_max_retrans", 0644,
			 sizeof(unsigned int),
			 nf_ct_tcp_timeout_retrans_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_tcp_timeout_unacknowledged", 0644,
			 sizeof(unsigned int),
			 nf_ct_tcp_timeout_unack_data,
			 proc_dointvec_jiffies),
#if IS_ENABLED(CONFIG_NF_FLOW_TABLE)
	SYSCTL_FIELD_CUSTOM("nf_flowtable_tcp_timeout", 0644,
			 sizeof(unsigned int),
			 nf_ct_tcp_offload_timeout_data,
			 proc_dointvec_jiffies),
#endif
	SYSCTL_FIELD_STATIC_U8_MINMAX("nf_conntrack_tcp_loose", 0644,
				   nf_ct_tcp_loose_data,
				   SYSCTL_UINT_ZERO,
				   SYSCTL_UINT_ONE),
	SYSCTL_FIELD_STATIC_U8_MINMAX("nf_conntrack_tcp_be_liberal",
				   0644, nf_ct_tcp_liberal_data,
				   SYSCTL_UINT_ZERO,
				   SYSCTL_UINT_ONE),
	SYSCTL_FIELD_STATIC_U8_MINMAX("nf_conntrack_tcp_ignore_invalid_rst",
				   0644,
				   nf_ct_tcp_ignore_invalid_rst_data,
				   SYSCTL_UINT_ZERO,
				   SYSCTL_UINT_ONE),
	SYSCTL_FIELD_U8("nf_conntrack_tcp_max_retrans", 0644,
			     nf_ct_tcp_max_retrans_data),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_udp_timeout", 0644,
			 sizeof(unsigned int),
			 nf_ct_udp_timeout_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_udp_timeout_stream", 0644,
			 sizeof(unsigned int),
			 nf_ct_udp_stream_timeout_data,
			 proc_dointvec_jiffies),
#if IS_ENABLED(CONFIG_NF_FLOW_TABLE)
	SYSCTL_FIELD_CUSTOM("nf_flowtable_udp_timeout", 0644,
			 sizeof(unsigned int),
			 nf_ct_udp_offload_timeout_data,
			 proc_dointvec_jiffies),
#endif
	SYSCTL_FIELD_CUSTOM("nf_conntrack_icmp_timeout", 0644,
			 sizeof(unsigned int),
			 nf_ct_icmp_timeout_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_icmpv6_timeout", 0644,
			 sizeof(unsigned int),
			 nf_ct_icmpv6_timeout_data,
			 proc_dointvec_jiffies),
#ifdef CONFIG_NF_CT_PROTO_SCTP
	SYSCTL_FIELD_CUSTOM("nf_conntrack_sctp_timeout_closed", 0644,
			 sizeof(unsigned int),
			 nf_ct_sctp_timeout_closed_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_sctp_timeout_cookie_wait", 0644,
			 sizeof(unsigned int),
			 nf_ct_sctp_timeout_cookie_wait_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_sctp_timeout_cookie_echoed",
			 0644, sizeof(unsigned int),
			 nf_ct_sctp_timeout_cookie_echoed_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_sctp_timeout_established",
			 0644, sizeof(unsigned int),
			 nf_ct_sctp_timeout_established_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_sctp_timeout_shutdown_sent",
			 0644, sizeof(unsigned int),
			 nf_ct_sctp_timeout_shutdown_sent_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_sctp_timeout_shutdown_recd",
			 0644, sizeof(unsigned int),
			 nf_ct_sctp_timeout_shutdown_recd_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_sctp_timeout_shutdown_ack_sent",
			 0644, sizeof(unsigned int),
			 nf_ct_sctp_timeout_shutdown_ack_sent_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_sctp_timeout_heartbeat_sent",
			 0644, sizeof(unsigned int),
			 nf_ct_sctp_timeout_heartbeat_sent_data,
			 proc_dointvec_jiffies),
#endif
#ifdef CONFIG_NF_CT_PROTO_GRE
	SYSCTL_FIELD_CUSTOM("nf_conntrack_gre_timeout", 0644,
			 sizeof(unsigned int),
			 nf_ct_gre_timeout_data,
			 proc_dointvec_jiffies),
	SYSCTL_FIELD_CUSTOM("nf_conntrack_gre_timeout_stream", 0644,
			 sizeof(unsigned int),
			 nf_ct_gre_stream_timeout_data,
			 proc_dointvec_jiffies),
#endif
};

#undef NF_CT_GLOBAL_UINT_MINMAX

static struct ctl_table nf_ct_netfilter_table[] = {
	{
		.procname	= "nf_conntrack_max",
		.data		= &nf_conntrack_max,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE,
		.extra2		= SYSCTL_INT_MAX,
	},
};

static int nf_conntrack_standalone_init_sysctl(struct net *net)
{
	struct sysctl_context ctx = {
		.ns.net_ns = net,
	};
	struct nf_conntrack_net *cnet = nf_ct_pernet(net);

	cnet->sysctl_header = register_sysctl_fields(&net->sysctls, "net/netfilter",
						     nf_ct_sysctl_table, &ctx);
	if (!cnet->sysctl_header)
		return -ENOMEM;

	return 0;
}

static void nf_conntrack_standalone_fini_sysctl(struct net *net)
{
	struct nf_conntrack_net *cnet = nf_ct_pernet(net);

	unregister_net_sysctl_table(cnet->sysctl_header);
}
#else
static int nf_conntrack_standalone_init_sysctl(struct net *net)
{
	return 0;
}

static void nf_conntrack_standalone_fini_sysctl(struct net *net)
{
}
#endif /* CONFIG_SYSCTL */

static void nf_conntrack_fini_net(struct net *net)
{
	if (enable_hooks)
		nf_ct_netns_put(net, NFPROTO_INET);

	nf_conntrack_standalone_fini_proc(net);
	nf_conntrack_standalone_fini_sysctl(net);
}

static int nf_conntrack_pernet_init(struct net *net)
{
	int ret;

	net->ct.sysctl_checksum = 1;

	ret = nf_conntrack_standalone_init_sysctl(net);
	if (ret < 0)
		return ret;

	ret = nf_conntrack_standalone_init_proc(net);
	if (ret < 0)
		goto out_proc;

	ret = nf_conntrack_init_net(net);
	if (ret < 0)
		goto out_init_net;

	if (enable_hooks) {
		ret = nf_ct_netns_get(net, NFPROTO_INET);
		if (ret < 0)
			goto out_hooks;
	}

	return 0;

out_hooks:
	nf_conntrack_cleanup_net(net);
out_init_net:
	nf_conntrack_standalone_fini_proc(net);
out_proc:
	nf_conntrack_standalone_fini_sysctl(net);
	return ret;
}

static void nf_conntrack_pernet_exit(struct list_head *net_exit_list)
{
	struct net *net;

	list_for_each_entry(net, net_exit_list, exit_list)
		nf_conntrack_fini_net(net);

	nf_conntrack_cleanup_net_list(net_exit_list);
}

static struct pernet_operations nf_conntrack_net_ops = {
	.init		= nf_conntrack_pernet_init,
	.exit_batch	= nf_conntrack_pernet_exit,
	.id		= &nf_conntrack_net_id,
	.size = sizeof(struct nf_conntrack_net),
};

static int __init nf_conntrack_standalone_init(void)
{
	int ret = nf_conntrack_init_start();
	if (ret < 0)
		goto out_start;

	BUILD_BUG_ON(NFCT_INFOMASK <= IP_CT_NUMBER);

#ifdef CONFIG_SYSCTL
	nf_ct_netfilter_header =
		register_net_sysctl(&init_net, "net", nf_ct_netfilter_table);
	if (!nf_ct_netfilter_header) {
		pr_err("nf_conntrack: can't register to sysctl.\n");
		ret = -ENOMEM;
		goto out_sysctl;
	}

	nf_conntrack_htable_size_user = nf_conntrack_htable_size;
#endif

	nf_conntrack_init_end();

	ret = register_pernet_subsys(&nf_conntrack_net_ops);
	if (ret < 0)
		goto out_pernet;

	return 0;

out_pernet:
#ifdef CONFIG_SYSCTL
	unregister_net_sysctl_table(nf_ct_netfilter_header);
out_sysctl:
#endif
	nf_conntrack_cleanup_end();
out_start:
	return ret;
}

static void __exit nf_conntrack_standalone_fini(void)
{
	nf_conntrack_cleanup_start();
	unregister_pernet_subsys(&nf_conntrack_net_ops);
#ifdef CONFIG_SYSCTL
	unregister_net_sysctl_table(nf_ct_netfilter_header);
#endif
	nf_conntrack_cleanup_end();
}

module_init(nf_conntrack_standalone_init);
module_exit(nf_conntrack_standalone_fini);

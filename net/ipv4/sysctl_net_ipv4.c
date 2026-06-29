// SPDX-License-Identifier: GPL-2.0
/*
 * sysctl_net_ipv4.c: sysctl interface to net IPV4 subsystem.
 *
 * Begun April 1, 1996, Mike Shaver.
 * Added /proc/sys/net/ipv4 directory entry (empty =) ). [MS]
 */

#include <linux/sysctl.h>
#include <linux/seqlock.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/ip_fib.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/cipso_ipv4.h>
#include <net/ping.h>
#include <net/protocol.h>
#include <net/netevent.h>

static unsigned int tcp_retr1_max = 255;
static int ip_local_port_range_min[] = { 1, 1 };
static int ip_local_port_range_max[] = { 65535, 65535 };
static int tcp_adv_win_scale_min = -31;
static int tcp_adv_win_scale_max = 31;
static unsigned int tcp_app_win_max = 31;
static int tcp_min_snd_mss_min = TCP_MIN_SND_MSS;
static int tcp_min_snd_mss_max = 65535;
static int tcp_rto_max_max = TCP_RTO_MAX_SEC * MSEC_PER_SEC;
static int ip_privileged_port_min;
static int ip_privileged_port_max = 65535;
static unsigned int ip_ttl_min = 1;
static unsigned int ip_ttl_max = 255;
static unsigned int tcp_syn_retries_min = 1;
static unsigned int tcp_syn_retries_max = MAX_TCP_SYNCNT;
static unsigned int tcp_syn_linear_timeouts_max = MAX_TCP_SYNCNT;
static unsigned long ip_ping_group_range_min[] = { 0, 0 };
static unsigned long ip_ping_group_range_max[] = { GID_T_MAX, GID_T_MAX };
static u32 u32_max_div_HZ = UINT_MAX / HZ;
static int one_day_secs = 24 * 3600;
static u32 fib_multipath_hash_fields_all_mask __maybe_unused =
	FIB_MULTIPATH_HASH_FIELD_ALL_MASK;
static unsigned int tcp_child_ehash_entries_max = 16 * 1024 * 1024;
static unsigned int udp_child_hash_entries_max = UDP_HTABLE_SIZE_MAX;
static unsigned int tcp_plb_max_rounds = 31;
static int tcp_plb_max_cong_thresh = 256;
static unsigned int tcp_tw_reuse_delay_max = TCP_PAWS_MSL * MSEC_PER_SEC;
static unsigned int tcp_ecn_mode_max = 5;
static unsigned int icmp_errors_extension_mask_all =
	GENMASK_U8(ICMP_ERR_EXT_COUNT - 1, 0);

/* obsolete */
static int sysctl_tcp_low_latency __read_mostly;

/* Update system visible IP port range */
static void set_local_port_range(struct net *net, unsigned int low, unsigned int high)
{
	bool same_parity = !((low ^ high) & 1);

	if (same_parity && !net->ipv4.ip_local_ports.warned) {
		net->ipv4.ip_local_ports.warned = true;
		pr_err_ratelimited("ip_local_port_range: prefer different parity for start/end values.\n");
	}
	WRITE_ONCE(net->ipv4.ip_local_ports.range, high << 16 | low);
}

/* Validate changes from /proc interface. */
static int ipv4_local_port_range(const struct ctl_table *table, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = table->data;
	int ret;
	int range[2];
	struct ctl_table tmp = {
		.data = &range,
		.maxlen = sizeof(range),
		.mode = table->mode,
		.extra1 = &ip_local_port_range_min,
		.extra2 = &ip_local_port_range_max,
	};

	inet_get_local_port_range(net, &range[0], &range[1]);

	ret = proc_dointvec_minmax(&tmp, write, buffer, lenp, ppos);

	if (write && ret == 0) {
		/* Ensure that the upper limit is not smaller than the lower,
		 * and that the lower does not encroach upon the privileged
		 * port limit.
		 */
		if ((range[1] < range[0]) ||
		    (range[0] < READ_ONCE(net->ipv4.sysctl_ip_prot_sock)))
			ret = -EINVAL;
		else
			set_local_port_range(net, range[0], range[1]);
	}

	return ret;
}

/* Validate changes from /proc interface. */
static int ipv4_privileged_ports(const struct ctl_table *table, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = container_of(table->data, struct net,
	    ipv4.sysctl_ip_prot_sock);
	int ret;
	int pports;
	int range[2];
	struct ctl_table tmp = {
		.data = &pports,
		.maxlen = sizeof(pports),
		.mode = table->mode,
		.extra1 = &ip_privileged_port_min,
		.extra2 = &ip_privileged_port_max,
	};

	pports = READ_ONCE(net->ipv4.sysctl_ip_prot_sock);

	ret = proc_dointvec_minmax(&tmp, write, buffer, lenp, ppos);

	if (write && ret == 0) {
		inet_get_local_port_range(net, &range[0], &range[1]);
		/* Ensure that the local port range doesn't overlap with the
		 * privileged port range.
		 */
		if (range[0] < pports)
			ret = -EINVAL;
		else
			WRITE_ONCE(net->ipv4.sysctl_ip_prot_sock, pports);
	}

	return ret;
}

static void inet_get_ping_group_range_table(const struct ctl_table *table,
					    kgid_t *low, kgid_t *high)
{
	kgid_t *data = table->data;
	struct net *net =
		container_of(table->data, struct net, ipv4.ping_group_range.range);
	unsigned int seq;
	do {
		seq = read_seqbegin(&net->ipv4.ping_group_range.lock);

		*low = data[0];
		*high = data[1];
	} while (read_seqretry(&net->ipv4.ping_group_range.lock, seq));
}

/* Update system visible IP port range */
static void set_ping_group_range(const struct ctl_table *table,
				 kgid_t low, kgid_t high)
{
	kgid_t *data = table->data;
	struct net *net =
		container_of(table->data, struct net, ipv4.ping_group_range.range);
	write_seqlock(&net->ipv4.ping_group_range.lock);
	data[0] = low;
	data[1] = high;
	write_sequnlock(&net->ipv4.ping_group_range.lock);
}

/* Validate changes from /proc interface. */
static int ipv4_ping_group_range(const struct ctl_table *table, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	struct user_namespace *user_ns = current_user_ns();
	int ret;
	unsigned long urange[2];
	kgid_t low, high;
	struct ctl_table tmp = {
		.data = &urange,
		.maxlen = sizeof(urange),
		.mode = table->mode,
		.extra1 = &ip_ping_group_range_min,
		.extra2 = &ip_ping_group_range_max,
	};

	inet_get_ping_group_range_table(table, &low, &high);
	urange[0] = from_kgid_munged(user_ns, low);
	urange[1] = from_kgid_munged(user_ns, high);
	ret = proc_doulongvec_minmax(&tmp, write, buffer, lenp, ppos);

	if (write && ret == 0) {
		low = make_kgid(user_ns, urange[0]);
		high = make_kgid(user_ns, urange[1]);
		if (!gid_valid(low) || !gid_valid(high))
			return -EINVAL;
		if (urange[1] < urange[0] || gid_lt(high, low)) {
			low = make_kgid(&init_user_ns, 1);
			high = make_kgid(&init_user_ns, 0);
		}
		set_ping_group_range(table, low, high);
	}

	return ret;
}

static int ipv4_fwd_update_priority(const struct ctl_table *table, int write,
				    void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net;
	struct ctl_table tmp;
	int ret;

	net = container_of(table->data, struct net,
			   ipv4.sysctl_ip_fwd_update_priority);
	tmp = *table;
	tmp.extra1 = SYSCTL_UINT_ZERO;
	tmp.extra2 = SYSCTL_UINT_ONE;

	ret = proc_dou8vec_minmax(&tmp, write, buffer, lenp, ppos);
	if (write && ret == 0)
		call_netevent_notifiers(NETEVENT_IPV4_FWD_UPDATE_PRIORITY_UPDATE,
					net);

	return ret;
}

static int proc_tcp_congestion_control(const struct ctl_table *ctl, int write,
				       void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = container_of(ctl->data, struct net,
				       ipv4.tcp_congestion_control);
	char val[TCP_CA_NAME_MAX];
	struct ctl_table tbl = {
		.data = val,
		.maxlen = TCP_CA_NAME_MAX,
	};
	int ret;

	tcp_get_default_congestion_control(net, val);

	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0)
		ret = tcp_set_default_congestion_control(net, val);
	return ret;
}

static int proc_tcp_available_congestion_control(const struct ctl_table *ctl,
						 int write, void *buffer,
						 size_t *lenp, loff_t *ppos)
{
	struct ctl_table tbl = { .maxlen = TCP_CA_BUF_MAX, };
	int ret;

	tbl.data = kmalloc(tbl.maxlen, GFP_USER);
	if (!tbl.data)
		return -ENOMEM;
	tcp_get_available_congestion_control(tbl.data, TCP_CA_BUF_MAX);
	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	kfree(tbl.data);
	return ret;
}

static int proc_allowed_congestion_control(const struct ctl_table *ctl,
					   int write, void *buffer,
					   size_t *lenp, loff_t *ppos)
{
	struct ctl_table tbl = { .maxlen = TCP_CA_BUF_MAX };
	int ret;

	tbl.data = kmalloc(tbl.maxlen, GFP_USER);
	if (!tbl.data)
		return -ENOMEM;

	tcp_get_allowed_congestion_control(tbl.data, tbl.maxlen);
	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0)
		ret = tcp_set_allowed_congestion_control(tbl.data);
	kfree(tbl.data);
	return ret;
}

static int sscanf_key(char *buf, __le32 *key)
{
	u32 user_key[4];
	int i, ret = 0;

	if (sscanf(buf, "%x-%x-%x-%x", user_key, user_key + 1,
		   user_key + 2, user_key + 3) != 4) {
		ret = -EINVAL;
	} else {
		for (i = 0; i < ARRAY_SIZE(user_key); i++)
			key[i] = cpu_to_le32(user_key[i]);
	}
	pr_debug("proc TFO key set 0x%x-%x-%x-%x <- 0x%s: %u\n",
		 user_key[0], user_key[1], user_key[2], user_key[3], buf, ret);

	return ret;
}

static int proc_tcp_fastopen_key(const struct ctl_table *table, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = container_of(table->data, struct net,
	    ipv4.sysctl_tcp_fastopen);
	/* maxlen to print the list of keys in hex (*2), with dashes
	 * separating doublewords and a comma in between keys.
	 */
	struct ctl_table tbl = { .maxlen = ((TCP_FASTOPEN_KEY_LENGTH *
					    2 * TCP_FASTOPEN_KEY_MAX) +
					    (TCP_FASTOPEN_KEY_MAX * 5)) };
	u32 user_key[TCP_FASTOPEN_KEY_BUF_LENGTH / sizeof(u32)];
	__le32 key[TCP_FASTOPEN_KEY_BUF_LENGTH / sizeof(__le32)];
	char *backup_data;
	int ret, i = 0, off = 0, n_keys;

	tbl.data = kmalloc(tbl.maxlen, GFP_KERNEL);
	if (!tbl.data)
		return -ENOMEM;

	n_keys = tcp_fastopen_get_cipher(net, NULL, (u64 *)key);
	if (!n_keys) {
		memset(&key[0], 0, TCP_FASTOPEN_KEY_LENGTH);
		n_keys = 1;
	}

	for (i = 0; i < n_keys * 4; i++)
		user_key[i] = le32_to_cpu(key[i]);

	for (i = 0; i < n_keys; i++) {
		off += snprintf(tbl.data + off, tbl.maxlen - off,
				"%08x-%08x-%08x-%08x",
				user_key[i * 4],
				user_key[i * 4 + 1],
				user_key[i * 4 + 2],
				user_key[i * 4 + 3]);

		if (WARN_ON_ONCE(off >= tbl.maxlen - 1))
			break;

		if (i + 1 < n_keys)
			off += snprintf(tbl.data + off, tbl.maxlen - off, ",");
	}

	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);

	if (write && ret == 0) {
		backup_data = strchr(tbl.data, ',');
		if (backup_data) {
			*backup_data = '\0';
			backup_data++;
		}
		if (sscanf_key(tbl.data, key)) {
			ret = -EINVAL;
			goto bad_key;
		}
		if (backup_data) {
			if (sscanf_key(backup_data, key + 4)) {
				ret = -EINVAL;
				goto bad_key;
			}
		}
		tcp_fastopen_reset_cipher(net, NULL, key,
					  backup_data ? key + 4 : NULL);
	}

bad_key:
	kfree(tbl.data);
	return ret;
}

static int proc_tfo_blackhole_detect_timeout(const struct ctl_table *table,
					     int write, void *buffer,
					     size_t *lenp, loff_t *ppos)
{
	struct net *net = container_of(table->data, struct net,
	    ipv4.sysctl_tcp_fastopen_blackhole_timeout);
	struct ctl_table tmp = *table;
	int ret;

	tmp.extra1 = SYSCTL_ZERO;

	ret = proc_dointvec_minmax(&tmp, write, buffer, lenp, ppos);
	if (write && ret == 0)
		atomic_set(&net->ipv4.tfo_active_disable_times, 0);

	return ret;
}

static int proc_dointvec_minmax_one(const struct ctl_table *table, int write,
				    void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table tmp = *table;

	tmp.extra1 = SYSCTL_ONE;

	return proc_dointvec_minmax(&tmp, write, buffer, lenp, ppos);
}

static int proc_tcp_available_ulp(const struct ctl_table *ctl,
				  int write, void *buffer, size_t *lenp,
				  loff_t *ppos)
{
	struct ctl_table tbl = { .maxlen = TCP_ULP_BUF_MAX, };
	int ret;

	tbl.data = kmalloc(tbl.maxlen, GFP_USER);
	if (!tbl.data)
		return -ENOMEM;
	tcp_get_available_ulp(tbl.data, TCP_ULP_BUF_MAX);
	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	kfree(tbl.data);

	return ret;
}

static int proc_tcp_ehash_entries(const struct ctl_table *table, int write,
				  void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = container_of(table->data, struct net,
				       ipv4.sysctl_tcp_child_ehash_entries);
	struct inet_hashinfo *hinfo = net->ipv4.tcp_death_row.hashinfo;
	int tcp_ehash_entries;
	struct ctl_table tbl;

	tcp_ehash_entries = hinfo->ehash_mask + 1;

	/* A negative number indicates that the child netns
	 * shares the global ehash.
	 */
	if (!net_eq(net, &init_net) && !hinfo->pernet)
		tcp_ehash_entries *= -1;

	memset(&tbl, 0, sizeof(tbl));
	tbl.data = &tcp_ehash_entries;
	tbl.maxlen = sizeof(int);

	return proc_dointvec(&tbl, write, buffer, lenp, ppos);
}

static int proc_udp_hash_entries(const struct ctl_table *table, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = container_of(table->data, struct net,
				       ipv4.sysctl_udp_child_hash_entries);
	int udp_hash_entries;
	struct ctl_table tbl;

	udp_hash_entries = net->ipv4.udp_table->mask + 1;

	/* A negative number indicates that the child netns
	 * shares the global udp_table.
	 */
	if (!net_eq(net, &init_net) && net->ipv4.udp_table == &udp_table)
		udp_hash_entries *= -1;

	memset(&tbl, 0, sizeof(tbl));
	tbl.data = &udp_hash_entries;
	tbl.maxlen = sizeof(int);

	return proc_dointvec(&tbl, write, buffer, lenp, ppos);
}

#ifdef CONFIG_IP_ROUTE_MULTIPATH
static int proc_fib_multipath_hash_policy(const struct ctl_table *table, int write,
					  void *buffer, size_t *lenp,
					  loff_t *ppos)
{
	struct net *net = container_of(table->data, struct net,
	    ipv4.sysctl_fib_multipath_hash_policy);
	struct ctl_table tmp = *table;
	int ret;

	tmp.extra1 = SYSCTL_UINT_ZERO;
	tmp.extra2 = SYSCTL_UINT_THREE;

	ret = proc_dou8vec_minmax(&tmp, write, buffer, lenp, ppos);
	if (write && ret == 0)
		call_netevent_notifiers(NETEVENT_IPV4_MPATH_HASH_UPDATE, net);

	return ret;
}

static int proc_fib_multipath_hash_fields(const struct ctl_table *table, int write,
					  void *buffer, size_t *lenp,
					  loff_t *ppos)
{
	struct net *net;
	struct ctl_table tmp = *table;
	int ret;

	net = container_of(table->data, struct net,
			   ipv4.sysctl_fib_multipath_hash_fields);
	tmp.extra1 = SYSCTL_ONE;
	tmp.extra2 = &fib_multipath_hash_fields_all_mask;

	ret = proc_douintvec_minmax(&tmp, write, buffer, lenp, ppos);
	if (write && ret == 0)
		call_netevent_notifiers(NETEVENT_IPV4_MPATH_HASH_UPDATE, net);

	return ret;
}

static u32 proc_fib_multipath_hash_rand_seed __ro_after_init;

static void proc_fib_multipath_hash_init_rand_seed(void)
{
	get_random_bytes(&proc_fib_multipath_hash_rand_seed,
			 sizeof(proc_fib_multipath_hash_rand_seed));
}

static void proc_fib_multipath_hash_set_seed(struct net *net, u32 user_seed)
{
	struct sysctl_fib_multipath_hash_seed new = {
		.user_seed = user_seed,
		.mp_seed = (user_seed ? user_seed :
			    proc_fib_multipath_hash_rand_seed),
	};

	WRITE_ONCE(net->ipv4.sysctl_fib_multipath_hash_seed.user_seed, new.user_seed);
	WRITE_ONCE(net->ipv4.sysctl_fib_multipath_hash_seed.mp_seed, new.mp_seed);
}

static int proc_fib_multipath_hash_seed(const struct ctl_table *table, int write,
					void *buffer, size_t *lenp,
					loff_t *ppos)
{
	struct sysctl_fib_multipath_hash_seed *mphs;
	struct net *net = table->data;
	struct ctl_table tmp;
	u32 user_seed;
	int ret;

	mphs = &net->ipv4.sysctl_fib_multipath_hash_seed;
	user_seed = READ_ONCE(mphs->user_seed);

	tmp = *table;
	tmp.data = &user_seed;

	ret = proc_douintvec_minmax(&tmp, write, buffer, lenp, ppos);

	if (write && ret == 0) {
		proc_fib_multipath_hash_set_seed(net, user_seed);
		call_netevent_notifiers(NETEVENT_IPV4_MPATH_HASH_UPDATE, net);
	}

	return ret;
}
#else

static void proc_fib_multipath_hash_init_rand_seed(void)
{
}

static void proc_fib_multipath_hash_set_seed(struct net *net, u32 user_seed)
{
}

#endif

static struct ctl_table ipv4_table[] = {
	{
		.procname	= "tcp_max_orphans",
		.data		= &sysctl_tcp_max_orphans,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "inet_peer_threshold",
		.data		= &inet_peer_threshold,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "inet_peer_minttl",
		.data		= &inet_peer_minttl,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "inet_peer_maxttl",
		.data		= &inet_peer_maxttl,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "tcp_mem",
		.maxlen		= sizeof(sysctl_tcp_mem),
		.data		= &sysctl_tcp_mem,
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{
		.procname	= "tcp_low_latency",
		.data		= &sysctl_tcp_low_latency,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
#ifdef CONFIG_NETLABEL
	{
		.procname	= "cipso_cache_enable",
		.data		= &cipso_v4_cache_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "cipso_cache_bucket_size",
		.data		= &cipso_v4_cache_bucketsize,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "cipso_rbm_optfmt",
		.data		= &cipso_v4_rbm_optfmt,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "cipso_rbm_strictvalid",
		.data		= &cipso_v4_rbm_strictvalid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif /* CONFIG_NETLABEL */
	{
		.procname	= "tcp_available_ulp",
		.maxlen		= TCP_ULP_BUF_MAX,
		.mode		= 0444,
		.proc_handler   = proc_tcp_available_ulp,
	},
	{
		.procname	= "udp_mem",
		.data		= &sysctl_udp_mem,
		.maxlen		= sizeof(sysctl_udp_mem),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{
		.procname	= "fib_sync_mem",
		.data		= &sysctl_fib_sync_mem,
		.maxlen		= sizeof(sysctl_fib_sync_mem),
		.mode		= 0644,
		.proc_handler	= proc_douintvec_minmax,
		.extra1		= &sysctl_fib_sync_mem_min,
		.extra2		= &sysctl_fib_sync_mem_max,
	},
};

static umode_t ipv4_init_net_writable_mode(const struct sysctl_context *ctx)
{
	return net_eq(ctx->ns.net_ns, &init_net) ? 0644 : 0444;
}

static void *ipv4_netns_data(const struct sysctl_context *ctx)
{
	return ctx->ns.net_ns;
}

#define IPV4_DATA(type, name, field)					\
static type *ipv4_ ## name ## _data(const struct sysctl_context *ctx)	\
{									\
	return &ctx->ns.net_ns->ipv4.field;				\
}

#define IPV4_SYSCTL_DATA(type, name)	IPV4_DATA(type, name, sysctl_ ## name)

IPV4_DATA(int, tcp_max_tw_buckets, tcp_death_row.sysctl_max_tw_buckets)
IPV4_DATA(void, ping_group_range, ping_group_range.range)
IPV4_DATA(void, ip_local_reserved_ports, sysctl_local_reserved_ports)
IPV4_DATA(u8, ip_forward_use_pmtu, sysctl_ip_fwd_use_pmtu)
IPV4_DATA(void, ip_forward_update_priority, sysctl_ip_fwd_update_priority)
IPV4_DATA(u8, igmp_link_local_mcast_reports, sysctl_igmp_llm_reports)
IPV4_DATA(void, tcp_congestion_control, tcp_congestion_control)
IPV4_DATA(int, tcp_max_syn_backlog, sysctl_max_syn_backlog)
IPV4_DATA(void, tcp_fastopen_key, sysctl_tcp_fastopen)
IPV4_DATA(void, tcp_fastopen_blackhole_timeout_sec, sysctl_tcp_fastopen_blackhole_timeout)
IPV4_DATA(void, ip_unprivileged_port_start, sysctl_ip_prot_sock)
IPV4_DATA(u8, tcp_no_metrics_save, sysctl_tcp_nometrics_save)
IPV4_DATA(void, tcp_ehash_entries, sysctl_tcp_child_ehash_entries)
IPV4_DATA(void, udp_hash_entries, sysctl_udp_child_hash_entries)

IPV4_SYSCTL_DATA(u8, icmp_echo_ignore_all)
IPV4_SYSCTL_DATA(u8, icmp_echo_enable_probe)
IPV4_SYSCTL_DATA(u8, icmp_echo_ignore_broadcasts)
IPV4_SYSCTL_DATA(u8, icmp_ignore_bogus_error_responses)
IPV4_SYSCTL_DATA(u8, icmp_errors_use_inbound_ifaddr)
IPV4_SYSCTL_DATA(u8, icmp_errors_extension_mask)
IPV4_SYSCTL_DATA(void, icmp_ratelimit)
IPV4_SYSCTL_DATA(int, icmp_ratemask)
IPV4_SYSCTL_DATA(int, icmp_msgs_per_sec)
IPV4_SYSCTL_DATA(int, icmp_msgs_burst)
#ifdef CONFIG_NET_L3_MASTER_DEV
IPV4_SYSCTL_DATA(u8, raw_l3mdev_accept)
#endif
IPV4_SYSCTL_DATA(u8, tcp_ecn)
IPV4_SYSCTL_DATA(u8, tcp_ecn_option)
IPV4_SYSCTL_DATA(u8, tcp_ecn_option_beacon)
IPV4_SYSCTL_DATA(u8, tcp_ecn_fallback)
IPV4_SYSCTL_DATA(u8, ip_dynaddr)
IPV4_SYSCTL_DATA(u8, ip_early_demux)
IPV4_SYSCTL_DATA(u8, udp_early_demux)
IPV4_SYSCTL_DATA(u8, tcp_early_demux)
IPV4_SYSCTL_DATA(u8, nexthop_compat_mode)
IPV4_SYSCTL_DATA(u8, ip_default_ttl)
IPV4_SYSCTL_DATA(unsigned int, ip_local_port_step_width)
IPV4_SYSCTL_DATA(u8, ip_no_pmtu_disc)
IPV4_SYSCTL_DATA(u8, ip_nonlocal_bind)
IPV4_SYSCTL_DATA(u8, ip_autobind_reuse)
IPV4_SYSCTL_DATA(u8, fwmark_reflect)
IPV4_SYSCTL_DATA(u8, tcp_fwmark_accept)
IPV4_SYSCTL_DATA(u8, tcp_mtu_probing)
#ifdef CONFIG_NET_L3_MASTER_DEV
IPV4_SYSCTL_DATA(u8, tcp_l3mdev_accept)
#endif
IPV4_SYSCTL_DATA(int, tcp_base_mss)
IPV4_SYSCTL_DATA(int, tcp_min_snd_mss)
IPV4_SYSCTL_DATA(int, tcp_mtu_probe_floor)
IPV4_SYSCTL_DATA(int, tcp_probe_threshold)
IPV4_SYSCTL_DATA(unsigned int, tcp_probe_interval)
IPV4_SYSCTL_DATA(int, igmp_max_memberships)
IPV4_SYSCTL_DATA(int, igmp_max_msf)
#ifdef CONFIG_IP_MULTICAST
IPV4_SYSCTL_DATA(int, igmp_qrv)
#endif
IPV4_SYSCTL_DATA(void, tcp_keepalive_time)
IPV4_SYSCTL_DATA(u8, tcp_keepalive_probes)
IPV4_SYSCTL_DATA(void, tcp_keepalive_intvl)
IPV4_SYSCTL_DATA(u8, tcp_syn_retries)
IPV4_SYSCTL_DATA(u8, tcp_synack_retries)
#ifdef CONFIG_SYN_COOKIES
IPV4_SYSCTL_DATA(u8, tcp_syncookies)
#endif
IPV4_SYSCTL_DATA(u8, tcp_migrate_req)
IPV4_SYSCTL_DATA(int, tcp_reordering)
IPV4_SYSCTL_DATA(u8, tcp_retries1)
IPV4_SYSCTL_DATA(u8, tcp_retries2)
IPV4_SYSCTL_DATA(u8, tcp_orphan_retries)
IPV4_SYSCTL_DATA(void, tcp_fin_timeout)
IPV4_SYSCTL_DATA(unsigned int, tcp_notsent_lowat)
IPV4_SYSCTL_DATA(u8, tcp_tw_reuse)
IPV4_SYSCTL_DATA(unsigned int, tcp_tw_reuse_delay)
IPV4_SYSCTL_DATA(int, tcp_fastopen)
#ifdef CONFIG_IP_ROUTE_MULTIPATH
IPV4_SYSCTL_DATA(u8, fib_multipath_use_neigh)
IPV4_SYSCTL_DATA(void, fib_multipath_hash_policy)
IPV4_SYSCTL_DATA(void, fib_multipath_hash_fields)
#endif
#ifdef CONFIG_NET_L3_MASTER_DEV
IPV4_SYSCTL_DATA(u8, udp_l3mdev_accept)
#endif
IPV4_SYSCTL_DATA(u8, tcp_sack)
IPV4_SYSCTL_DATA(u8, tcp_window_scaling)
IPV4_SYSCTL_DATA(u8, tcp_timestamps)
IPV4_SYSCTL_DATA(u8, tcp_early_retrans)
IPV4_SYSCTL_DATA(u8, tcp_recovery)
IPV4_SYSCTL_DATA(u8, tcp_thin_linear_timeouts)
IPV4_SYSCTL_DATA(u8, tcp_slow_start_after_idle)
IPV4_SYSCTL_DATA(u8, tcp_retrans_collapse)
IPV4_SYSCTL_DATA(u8, tcp_stdurg)
IPV4_SYSCTL_DATA(u8, tcp_rfc1337)
IPV4_SYSCTL_DATA(u8, tcp_abort_on_overflow)
IPV4_SYSCTL_DATA(u8, tcp_fack)
IPV4_SYSCTL_DATA(int, tcp_max_reordering)
IPV4_SYSCTL_DATA(u8, tcp_dsack)
IPV4_SYSCTL_DATA(u8, tcp_app_win)
IPV4_SYSCTL_DATA(int, tcp_adv_win_scale)
IPV4_SYSCTL_DATA(u8, tcp_frto)
IPV4_SYSCTL_DATA(u8, tcp_no_ssthresh_metrics_save)
IPV4_SYSCTL_DATA(u8, tcp_moderate_rcvbuf)
IPV4_SYSCTL_DATA(int, tcp_rcvbuf_low_rtt)
IPV4_SYSCTL_DATA(u8, tcp_tso_win_divisor)
IPV4_SYSCTL_DATA(u8, tcp_workaround_signed_windows)
IPV4_SYSCTL_DATA(int, tcp_limit_output_bytes)
IPV4_SYSCTL_DATA(int, tcp_challenge_ack_limit)
IPV4_SYSCTL_DATA(u8, tcp_min_tso_segs)
IPV4_SYSCTL_DATA(u8, tcp_tso_rtt_log)
IPV4_SYSCTL_DATA(int, tcp_min_rtt_wlen)
IPV4_SYSCTL_DATA(u8, tcp_autocorking)
IPV4_SYSCTL_DATA(void, tcp_invalid_ratelimit)
IPV4_SYSCTL_DATA(int, tcp_pacing_ss_ratio)
IPV4_SYSCTL_DATA(int, tcp_pacing_ca_ratio)
IPV4_SYSCTL_DATA(void, tcp_wmem)
IPV4_SYSCTL_DATA(void, tcp_rmem)
IPV4_SYSCTL_DATA(unsigned long, tcp_comp_sack_delay_ns)
IPV4_SYSCTL_DATA(int, tcp_comp_sack_rtt_percent)
IPV4_SYSCTL_DATA(unsigned long, tcp_comp_sack_slack_ns)
IPV4_SYSCTL_DATA(u8, tcp_comp_sack_nr)
IPV4_SYSCTL_DATA(u8, tcp_backlog_ack_defer)
IPV4_SYSCTL_DATA(u8, tcp_reflect_tos)
IPV4_SYSCTL_DATA(unsigned int, tcp_child_ehash_entries)
IPV4_SYSCTL_DATA(unsigned int, udp_child_hash_entries)
IPV4_SYSCTL_DATA(int, udp_rmem_min)
IPV4_SYSCTL_DATA(int, udp_wmem_min)
IPV4_SYSCTL_DATA(u8, fib_notify_on_flag_change)
IPV4_SYSCTL_DATA(u8, tcp_plb_enabled)
IPV4_SYSCTL_DATA(u8, tcp_plb_idle_rehash_rounds)
IPV4_SYSCTL_DATA(u8, tcp_plb_rehash_rounds)
IPV4_SYSCTL_DATA(u8, tcp_plb_suspend_rto_sec)
IPV4_SYSCTL_DATA(int, tcp_plb_cong_thresh)
IPV4_SYSCTL_DATA(u8, tcp_syn_linear_timeouts)
IPV4_SYSCTL_DATA(u8, tcp_shrink_window)
IPV4_SYSCTL_DATA(u8, tcp_pingpong_thresh)
IPV4_SYSCTL_DATA(int, tcp_rto_min_us)
IPV4_SYSCTL_DATA(int, tcp_rto_max_ms)

static const struct sysctl_field ipv4_net_table[] = {
	SYSCTL_FIELD_INT("tcp_max_tw_buckets", 0644,
			ipv4_tcp_max_tw_buckets_data),
	SYSCTL_FIELD_STATIC_U8_MINMAX("icmp_echo_ignore_all", 0644,
			ipv4_icmp_echo_ignore_all_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
	SYSCTL_FIELD_STATIC_U8_MINMAX("icmp_echo_enable_probe", 0644,
			ipv4_icmp_echo_enable_probe_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
	SYSCTL_FIELD_STATIC_U8_MINMAX("icmp_echo_ignore_broadcasts", 0644,
			ipv4_icmp_echo_ignore_broadcasts_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
	SYSCTL_FIELD_STATIC_U8_MINMAX("icmp_ignore_bogus_error_responses", 0644,
			ipv4_icmp_ignore_bogus_error_responses_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
	SYSCTL_FIELD_STATIC_U8_MINMAX("icmp_errors_use_inbound_ifaddr", 0644,
			ipv4_icmp_errors_use_inbound_ifaddr_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
	SYSCTL_FIELD_STATIC_U8_MINMAX("icmp_errors_extension_mask", 0644,
			ipv4_icmp_errors_extension_mask_data,
			SYSCTL_UINT_ZERO, &icmp_errors_extension_mask_all),
	SYSCTL_FIELD_CUSTOM("icmp_ratelimit", 0644,
			sizeof(int),
			ipv4_icmp_ratelimit_data,
			proc_dointvec_ms_jiffies),
	SYSCTL_FIELD_INT("icmp_ratemask", 0644,
			ipv4_icmp_ratemask_data),
	SYSCTL_FIELD_STATIC_INT_MINMAX("icmp_msgs_per_sec", 0644,
			ipv4_icmp_msgs_per_sec_data,
			SYSCTL_ZERO, NULL),
	SYSCTL_FIELD_STATIC_INT_MINMAX("icmp_msgs_burst", 0644,
			ipv4_icmp_msgs_burst_data,
			SYSCTL_ZERO, NULL),
	SYSCTL_FIELD_CUSTOM("ping_group_range", 0644,
			sizeof(gid_t) * 2,
			ipv4_ping_group_range_data,
			ipv4_ping_group_range),
#ifdef CONFIG_NET_L3_MASTER_DEV
	SYSCTL_FIELD_STATIC_U8_MINMAX("raw_l3mdev_accept", 0644,
			ipv4_raw_l3mdev_accept_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
#endif
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_ecn", 0644,
			ipv4_tcp_ecn_data,
			SYSCTL_UINT_ZERO, &tcp_ecn_mode_max),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_ecn_option", 0644,
			ipv4_tcp_ecn_option_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_THREE),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_ecn_option_beacon", 0644,
			ipv4_tcp_ecn_option_beacon_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_THREE),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_ecn_fallback", 0644,
			ipv4_tcp_ecn_fallback_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
	SYSCTL_FIELD_U8("ip_dynaddr", 0644,
			ipv4_ip_dynaddr_data),
	SYSCTL_FIELD_U8("ip_early_demux", 0644,
			ipv4_ip_early_demux_data),
	SYSCTL_FIELD_U8("udp_early_demux", 0644,
			ipv4_udp_early_demux_data),
	SYSCTL_FIELD_U8("tcp_early_demux", 0644,
			ipv4_tcp_early_demux_data),
	SYSCTL_FIELD_STATIC_U8_MINMAX("nexthop_compat_mode", 0644,
			ipv4_nexthop_compat_mode_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
	SYSCTL_FIELD_STATIC_U8_MINMAX("ip_default_ttl", 0644,
			ipv4_ip_default_ttl_data,
			&ip_ttl_min, &ip_ttl_max),
	SYSCTL_FIELD_CUSTOM("ip_local_port_range", 0644,
			0,
			ipv4_netns_data,
			ipv4_local_port_range),
	SYSCTL_FIELD_UINT("ip_local_port_step_width", 0644,
			ipv4_ip_local_port_step_width_data),
	SYSCTL_FIELD_CUSTOM("ip_local_reserved_ports", 0644,
			65536,
			ipv4_ip_local_reserved_ports_data,
			proc_do_large_bitmap),
	SYSCTL_FIELD_U8("ip_no_pmtu_disc", 0644,
			ipv4_ip_no_pmtu_disc_data),
	SYSCTL_FIELD_U8("ip_forward_use_pmtu", 0644,
			ipv4_ip_forward_use_pmtu_data),
	SYSCTL_FIELD_CUSTOM("ip_forward_update_priority", 0644,
			sizeof(u8),
			ipv4_ip_forward_update_priority_data,
			ipv4_fwd_update_priority),
	SYSCTL_FIELD_U8("ip_nonlocal_bind", 0644,
			ipv4_ip_nonlocal_bind_data),
	SYSCTL_FIELD_STATIC_U8_MINMAX("ip_autobind_reuse", 0644,
			ipv4_ip_autobind_reuse_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
	SYSCTL_FIELD_U8("fwmark_reflect", 0644,
			ipv4_fwmark_reflect_data),
	SYSCTL_FIELD_U8("tcp_fwmark_accept", 0644,
			ipv4_tcp_fwmark_accept_data),
#ifdef CONFIG_NET_L3_MASTER_DEV
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_l3mdev_accept", 0644,
			ipv4_tcp_l3mdev_accept_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
#endif
	SYSCTL_FIELD_U8("tcp_mtu_probing", 0644,
			ipv4_tcp_mtu_probing_data),
	SYSCTL_FIELD_INT("tcp_base_mss", 0644,
			ipv4_tcp_base_mss_data),
	SYSCTL_FIELD_STATIC_INT_MINMAX("tcp_min_snd_mss", 0644,
			ipv4_tcp_min_snd_mss_data,
			&tcp_min_snd_mss_min, &tcp_min_snd_mss_max),
	SYSCTL_FIELD_STATIC_INT_MINMAX("tcp_mtu_probe_floor", 0644,
			ipv4_tcp_mtu_probe_floor_data,
			&tcp_min_snd_mss_min, &tcp_min_snd_mss_max),
	SYSCTL_FIELD_INT("tcp_probe_threshold", 0644,
			ipv4_tcp_probe_threshold_data),
	SYSCTL_FIELD_STATIC_UINT_MINMAX("tcp_probe_interval", 0644,
			ipv4_tcp_probe_interval_data,
			NULL, &u32_max_div_HZ),
	SYSCTL_FIELD_U8("igmp_link_local_mcast_reports", 0644,
			ipv4_igmp_link_local_mcast_reports_data),
	SYSCTL_FIELD_INT("igmp_max_memberships", 0644,
			ipv4_igmp_max_memberships_data),
	SYSCTL_FIELD_INT("igmp_max_msf", 0644,
			ipv4_igmp_max_msf_data),
#ifdef CONFIG_IP_MULTICAST
	SYSCTL_FIELD_STATIC_INT_MINMAX("igmp_qrv", 0644,
			ipv4_igmp_qrv_data,
			SYSCTL_ONE, NULL),
#endif
	SYSCTL_FIELD_CUSTOM("tcp_congestion_control", 0644,
			TCP_CA_NAME_MAX,
			ipv4_tcp_congestion_control_data,
			proc_tcp_congestion_control),
	SYSCTL_FIELD_CUSTOM("tcp_available_congestion_control", 0444,
			TCP_CA_BUF_MAX,
			NULL,
			proc_tcp_available_congestion_control),
	SYSCTL_FIELD_CUSTOM_MODE("tcp_allowed_congestion_control", 0644,
			ipv4_init_net_writable_mode, TCP_CA_BUF_MAX, NULL,
			proc_allowed_congestion_control),
	SYSCTL_FIELD_CUSTOM("tcp_keepalive_time", 0644,
			sizeof(int),
			ipv4_tcp_keepalive_time_data,
			proc_dointvec_jiffies),
	SYSCTL_FIELD_U8("tcp_keepalive_probes", 0644,
			ipv4_tcp_keepalive_probes_data),
	SYSCTL_FIELD_CUSTOM("tcp_keepalive_intvl", 0644,
			sizeof(int),
			ipv4_tcp_keepalive_intvl_data,
			proc_dointvec_jiffies),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_syn_retries", 0644,
			ipv4_tcp_syn_retries_data,
			&tcp_syn_retries_min, &tcp_syn_retries_max),
	SYSCTL_FIELD_U8("tcp_synack_retries", 0644,
			ipv4_tcp_synack_retries_data),
#ifdef CONFIG_SYN_COOKIES
	SYSCTL_FIELD_U8("tcp_syncookies", 0644,
			ipv4_tcp_syncookies_data),
#endif
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_migrate_req", 0644,
			ipv4_tcp_migrate_req_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
	SYSCTL_FIELD_INT("tcp_reordering", 0644,
			ipv4_tcp_reordering_data),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_retries1", 0644,
			ipv4_tcp_retries1_data,
			NULL, &tcp_retr1_max),
	SYSCTL_FIELD_U8("tcp_retries2", 0644,
			ipv4_tcp_retries2_data),
	SYSCTL_FIELD_U8("tcp_orphan_retries", 0644,
			ipv4_tcp_orphan_retries_data),
	SYSCTL_FIELD_CUSTOM("tcp_fin_timeout", 0644,
			sizeof(int),
			ipv4_tcp_fin_timeout_data,
			proc_dointvec_jiffies),
	SYSCTL_FIELD_UINT("tcp_notsent_lowat", 0644,
			ipv4_tcp_notsent_lowat_data),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_tw_reuse", 0644,
			ipv4_tcp_tw_reuse_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_TWO),
	SYSCTL_FIELD_STATIC_UINT_MINMAX("tcp_tw_reuse_delay", 0644,
			ipv4_tcp_tw_reuse_delay_data,
			SYSCTL_UINT_ONE, &tcp_tw_reuse_delay_max),
	SYSCTL_FIELD_INT("tcp_max_syn_backlog", 0644,
			ipv4_tcp_max_syn_backlog_data),
	SYSCTL_FIELD_INT("tcp_fastopen", 0644,
			ipv4_tcp_fastopen_data),
	SYSCTL_FIELD_CUSTOM("tcp_fastopen_key", 0600,
			((TCP_FASTOPEN_KEY_LENGTH * 2 * TCP_FASTOPEN_KEY_MAX) + (TCP_FASTOPEN_KEY_MAX * 5)),
			ipv4_tcp_fastopen_key_data,
			proc_tcp_fastopen_key),
	SYSCTL_FIELD_CUSTOM("tcp_fastopen_blackhole_timeout_sec", 0644,
			sizeof(int),
			ipv4_tcp_fastopen_blackhole_timeout_sec_data,
			proc_tfo_blackhole_detect_timeout),
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	SYSCTL_FIELD_STATIC_U8_MINMAX("fib_multipath_use_neigh", 0644,
			ipv4_fib_multipath_use_neigh_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
	SYSCTL_FIELD_CUSTOM("fib_multipath_hash_policy", 0644,
			sizeof(u8),
			ipv4_fib_multipath_hash_policy_data,
			proc_fib_multipath_hash_policy),
	SYSCTL_FIELD_CUSTOM("fib_multipath_hash_fields", 0644,
			sizeof(u32),
			ipv4_fib_multipath_hash_fields_data,
			proc_fib_multipath_hash_fields),
	SYSCTL_FIELD_CUSTOM("fib_multipath_hash_seed", 0644,
			sizeof(u32),
			ipv4_netns_data,
			proc_fib_multipath_hash_seed),
#endif
	SYSCTL_FIELD_CUSTOM("ip_unprivileged_port_start", 0644,
			sizeof(int),
			ipv4_ip_unprivileged_port_start_data,
			ipv4_privileged_ports),
#ifdef CONFIG_NET_L3_MASTER_DEV
	SYSCTL_FIELD_STATIC_U8_MINMAX("udp_l3mdev_accept", 0644,
			ipv4_udp_l3mdev_accept_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
#endif
	SYSCTL_FIELD_U8("tcp_sack", 0644,
			ipv4_tcp_sack_data),
	SYSCTL_FIELD_U8("tcp_window_scaling", 0644,
			ipv4_tcp_window_scaling_data),
	SYSCTL_FIELD_U8("tcp_timestamps", 0644,
			ipv4_tcp_timestamps_data),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_early_retrans", 0644,
			ipv4_tcp_early_retrans_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_FOUR),
	SYSCTL_FIELD_U8("tcp_recovery", 0644,
			ipv4_tcp_recovery_data),
	SYSCTL_FIELD_U8("tcp_thin_linear_timeouts", 0644,
			ipv4_tcp_thin_linear_timeouts_data),
	SYSCTL_FIELD_U8("tcp_slow_start_after_idle", 0644,
			ipv4_tcp_slow_start_after_idle_data),
	SYSCTL_FIELD_U8("tcp_retrans_collapse", 0644,
			ipv4_tcp_retrans_collapse_data),
	SYSCTL_FIELD_U8("tcp_stdurg", 0644,
			ipv4_tcp_stdurg_data),
	SYSCTL_FIELD_U8("tcp_rfc1337", 0644,
			ipv4_tcp_rfc1337_data),
	SYSCTL_FIELD_U8("tcp_abort_on_overflow", 0644,
			ipv4_tcp_abort_on_overflow_data),
	SYSCTL_FIELD_U8("tcp_fack", 0644,
			ipv4_tcp_fack_data),
	SYSCTL_FIELD_INT("tcp_max_reordering", 0644,
			ipv4_tcp_max_reordering_data),
	SYSCTL_FIELD_U8("tcp_dsack", 0644,
			ipv4_tcp_dsack_data),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_app_win", 0644,
			ipv4_tcp_app_win_data,
			SYSCTL_UINT_ZERO, &tcp_app_win_max),
	SYSCTL_FIELD_STATIC_INT_MINMAX("tcp_adv_win_scale", 0644,
			ipv4_tcp_adv_win_scale_data,
			&tcp_adv_win_scale_min, &tcp_adv_win_scale_max),
	SYSCTL_FIELD_U8("tcp_frto", 0644,
			ipv4_tcp_frto_data),
	SYSCTL_FIELD_U8("tcp_no_metrics_save", 0644,
			ipv4_tcp_no_metrics_save_data),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_no_ssthresh_metrics_save", 0644,
			ipv4_tcp_no_ssthresh_metrics_save_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
	SYSCTL_FIELD_U8("tcp_moderate_rcvbuf", 0644,
			ipv4_tcp_moderate_rcvbuf_data),
	SYSCTL_FIELD_STATIC_INT_MINMAX("tcp_rcvbuf_low_rtt", 0644,
			ipv4_tcp_rcvbuf_low_rtt_data,
			SYSCTL_ZERO, SYSCTL_INT_MAX),
	SYSCTL_FIELD_U8("tcp_tso_win_divisor", 0644,
			ipv4_tcp_tso_win_divisor_data),
	SYSCTL_FIELD_U8("tcp_workaround_signed_windows", 0644,
			ipv4_tcp_workaround_signed_windows_data),
	SYSCTL_FIELD_INT("tcp_limit_output_bytes", 0644,
			ipv4_tcp_limit_output_bytes_data),
	SYSCTL_FIELD_INT("tcp_challenge_ack_limit", 0644,
			ipv4_tcp_challenge_ack_limit_data),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_min_tso_segs", 0644,
			ipv4_tcp_min_tso_segs_data,
			SYSCTL_UINT_ONE, NULL),
	SYSCTL_FIELD_U8("tcp_tso_rtt_log", 0644,
			ipv4_tcp_tso_rtt_log_data),
	SYSCTL_FIELD_STATIC_INT_MINMAX("tcp_min_rtt_wlen", 0644,
			ipv4_tcp_min_rtt_wlen_data,
			SYSCTL_ZERO, &one_day_secs),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_autocorking", 0644,
			ipv4_tcp_autocorking_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
	SYSCTL_FIELD_CUSTOM("tcp_invalid_ratelimit", 0644,
			sizeof(int),
			ipv4_tcp_invalid_ratelimit_data,
			proc_dointvec_ms_jiffies),
	SYSCTL_FIELD_STATIC_INT_MINMAX("tcp_pacing_ss_ratio", 0644,
			ipv4_tcp_pacing_ss_ratio_data,
			SYSCTL_ZERO, SYSCTL_ONE_THOUSAND),
	SYSCTL_FIELD_STATIC_INT_MINMAX("tcp_pacing_ca_ratio", 0644,
			ipv4_tcp_pacing_ca_ratio_data,
			SYSCTL_ZERO, SYSCTL_ONE_THOUSAND),
	SYSCTL_FIELD_CUSTOM("tcp_wmem", 0644,
			sizeof(init_net.ipv4.sysctl_tcp_wmem),
			ipv4_tcp_wmem_data,
			proc_dointvec_minmax_one),
	SYSCTL_FIELD_CUSTOM("tcp_rmem", 0644,
			sizeof(init_net.ipv4.sysctl_tcp_rmem),
			ipv4_tcp_rmem_data,
			proc_dointvec_minmax_one),
	SYSCTL_FIELD_ULONG("tcp_comp_sack_delay_ns", 0644,
			ipv4_tcp_comp_sack_delay_ns_data),
	SYSCTL_FIELD_STATIC_INT_MINMAX("tcp_comp_sack_rtt_percent", 0644,
			ipv4_tcp_comp_sack_rtt_percent_data,
			SYSCTL_ONE, SYSCTL_ONE_THOUSAND),
	SYSCTL_FIELD_ULONG("tcp_comp_sack_slack_ns", 0644,
			ipv4_tcp_comp_sack_slack_ns_data),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_comp_sack_nr", 0644,
			ipv4_tcp_comp_sack_nr_data,
			SYSCTL_UINT_ZERO, NULL),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_backlog_ack_defer", 0644,
			ipv4_tcp_backlog_ack_defer_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_reflect_tos", 0644,
			ipv4_tcp_reflect_tos_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
	SYSCTL_FIELD_CUSTOM("tcp_ehash_entries", 0444,
			0,
			ipv4_tcp_ehash_entries_data,
			proc_tcp_ehash_entries),
	SYSCTL_FIELD_STATIC_UINT_MINMAX("tcp_child_ehash_entries", 0644,
			ipv4_tcp_child_ehash_entries_data,
			SYSCTL_UINT_ZERO, &tcp_child_ehash_entries_max),
	SYSCTL_FIELD_CUSTOM("udp_hash_entries", 0444,
			0,
			ipv4_udp_hash_entries_data,
			proc_udp_hash_entries),
	SYSCTL_FIELD_STATIC_UINT_MINMAX("udp_child_hash_entries", 0644,
			ipv4_udp_child_hash_entries_data,
			SYSCTL_UINT_ZERO, &udp_child_hash_entries_max),
	SYSCTL_FIELD_STATIC_INT_MINMAX("udp_rmem_min", 0644,
			ipv4_udp_rmem_min_data, SYSCTL_ONE, NULL),
	SYSCTL_FIELD_STATIC_INT_MINMAX("udp_wmem_min", 0644,
			ipv4_udp_wmem_min_data, SYSCTL_ONE, NULL),
	SYSCTL_FIELD_STATIC_U8_MINMAX("fib_notify_on_flag_change", 0644,
			ipv4_fib_notify_on_flag_change_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_TWO),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_plb_enabled", 0644,
			ipv4_tcp_plb_enabled_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_plb_idle_rehash_rounds", 0644,
			ipv4_tcp_plb_idle_rehash_rounds_data,
			NULL, &tcp_plb_max_rounds),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_plb_rehash_rounds", 0644,
			ipv4_tcp_plb_rehash_rounds_data,
			NULL, &tcp_plb_max_rounds),
	SYSCTL_FIELD_U8("tcp_plb_suspend_rto_sec", 0644,
			ipv4_tcp_plb_suspend_rto_sec_data),
	SYSCTL_FIELD_STATIC_INT_MINMAX("tcp_plb_cong_thresh", 0644,
			ipv4_tcp_plb_cong_thresh_data,
			SYSCTL_ZERO, &tcp_plb_max_cong_thresh),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_syn_linear_timeouts", 0644,
			ipv4_tcp_syn_linear_timeouts_data,
			SYSCTL_UINT_ZERO, &tcp_syn_linear_timeouts_max),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_shrink_window", 0644,
			ipv4_tcp_shrink_window_data,
			SYSCTL_UINT_ZERO, SYSCTL_UINT_ONE),
	SYSCTL_FIELD_STATIC_U8_MINMAX("tcp_pingpong_thresh", 0644,
			ipv4_tcp_pingpong_thresh_data,
			SYSCTL_UINT_ONE, NULL),
	SYSCTL_FIELD_STATIC_INT_MINMAX("tcp_rto_min_us", 0644,
			ipv4_tcp_rto_min_us_data,
			SYSCTL_ONE, NULL),
	SYSCTL_FIELD_STATIC_INT_MINMAX("tcp_rto_max_ms", 0644,
			ipv4_tcp_rto_max_ms_data,
			SYSCTL_ONE_THOUSAND, &tcp_rto_max_max),
};

static __net_init int ipv4_sysctl_init_net(struct net *net)
{
	struct sysctl_context ctx = {
		.ns.net_ns = net,
	};

	net->ipv4.ipv4_hdr = register_sysctl_fields(&net->sysctls, "net/ipv4",
						    ipv4_net_table, &ctx);
	if (!net->ipv4.ipv4_hdr)
		return -ENOMEM;

	net->ipv4.sysctl_local_reserved_ports = kzalloc(65536 / 8, GFP_KERNEL);
	if (!net->ipv4.sysctl_local_reserved_ports)
		goto err_ports;

	proc_fib_multipath_hash_set_seed(net, 0);

	return 0;

err_ports:
	unregister_net_sysctl_table(net->ipv4.ipv4_hdr);
	return -ENOMEM;
}

static __net_exit void ipv4_sysctl_exit_net(struct net *net)
{
	kfree(net->ipv4.sysctl_local_reserved_ports);
	unregister_net_sysctl_table(net->ipv4.ipv4_hdr);
}

static __net_initdata struct pernet_operations ipv4_sysctl_ops = {
	.init = ipv4_sysctl_init_net,
	.exit = ipv4_sysctl_exit_net,
};

static __init int sysctl_ipv4_init(void)
{
	struct ctl_table_header *hdr;

	hdr = register_net_sysctl(&init_net, "net/ipv4", ipv4_table);
	if (!hdr)
		return -ENOMEM;

	proc_fib_multipath_hash_init_rand_seed();

	if (register_pernet_subsys(&ipv4_sysctl_ops)) {
		unregister_net_sysctl_table(hdr);
		return -ENOMEM;
	}

	return 0;
}

__initcall(sysctl_ipv4_init);

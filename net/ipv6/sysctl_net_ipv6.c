// SPDX-License-Identifier: GPL-2.0
/*
 * sysctl_net_ipv6.c: sysctl interface to net IPV6 subsystem.
 *
 * Changes:
 * YOSHIFUJI Hideaki @USAGI:	added icmp sysctl table.
 */

#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/export.h>
#include <net/ndisc.h>
#include <net/ipv6.h>
#include <net/addrconf.h>
#include <net/inet_frag.h>
#include <net/netevent.h>
#include <net/ip_fib.h>
#ifdef CONFIG_NETLABEL
#include <net/calipso.h>
#endif
#include <linux/ioam6.h>

static int flowlabel_reflect_max = 0x7;
static int auto_flowlabels_max = IP6_AUTO_FLOW_LABEL_MAX;
static u32 rt6_multipath_hash_fields_all_mask =
	FIB_MULTIPATH_HASH_FIELD_ALL_MASK;
static u32 ioam6_id_max = IOAM6_DEFAULT_ID;
static u64 ioam6_id_wide_max = IOAM6_DEFAULT_ID_WIDE;

static int proc_rt6_multipath_hash_policy(const struct ctl_table *table, int write,
					  void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = table->data;
	const struct ctl_table tmp = {
		.procname	= table->procname,
		.data		= &net->ipv6.sysctl.multipath_hash_policy,
		.maxlen		= table->maxlen,
		.mode		= table->mode,
		.extra1		= table->extra1,
		.extra2		= table->extra2,
	};
	int ret;

	ret = proc_dou8vec_minmax(&tmp, write, buffer, lenp, ppos);
	if (write && ret == 0)
		call_netevent_notifiers(NETEVENT_IPV6_MPATH_HASH_UPDATE, net);

	return ret;
}

static int
proc_rt6_multipath_hash_fields(const struct ctl_table *table, int write, void *buffer,
			       size_t *lenp, loff_t *ppos)
{
	struct net *net = table->data;
	const struct ctl_table tmp = {
		.procname	= table->procname,
		.data		= &net->ipv6.sysctl.multipath_hash_fields,
		.maxlen		= table->maxlen,
		.mode		= table->mode,
		.extra1		= table->extra1,
		.extra2		= table->extra2,
	};
	int ret;

	ret = proc_douintvec_minmax(&tmp, write, buffer, lenp, ppos);
	if (write && ret == 0)
		call_netevent_notifiers(NETEVENT_IPV6_MPATH_HASH_UPDATE, net);

	return ret;
}

#define IPV6_DATA(name, expr)						\
static void *ipv6_ ## name ## _data(const struct ctl_context *ctx)	\
{									\
	struct net *net = ctx->ns.net_ns;				\
	return (expr);							\
}

IPV6_DATA(bindv6only, &net->ipv6.sysctl.bindv6only)
IPV6_DATA(anycast_src_echo_reply, &net->ipv6.sysctl.anycast_src_echo_reply)
IPV6_DATA(flowlabel_consistency, &net->ipv6.sysctl.flowlabel_consistency)
IPV6_DATA(auto_flowlabels, &net->ipv6.sysctl.auto_flowlabels)
IPV6_DATA(fwmark_reflect, &net->ipv6.sysctl.fwmark_reflect)
IPV6_DATA(idgen_retries, &net->ipv6.sysctl.idgen_retries)
IPV6_DATA(idgen_delay, &net->ipv6.sysctl.idgen_delay)
IPV6_DATA(flowlabel_state_ranges, &net->ipv6.sysctl.flowlabel_state_ranges)
IPV6_DATA(ip_nonlocal_bind, &net->ipv6.sysctl.ip_nonlocal_bind)
IPV6_DATA(flowlabel_reflect, &net->ipv6.sysctl.flowlabel_reflect)
IPV6_DATA(max_dst_opts_cnt, &net->ipv6.sysctl.max_dst_opts_cnt)
IPV6_DATA(max_hbh_opts_cnt, &net->ipv6.sysctl.max_hbh_opts_cnt)
IPV6_DATA(max_dst_opts_len, &net->ipv6.sysctl.max_dst_opts_len)
IPV6_DATA(max_hbh_opts_len, &net->ipv6.sysctl.max_hbh_opts_len)
IPV6_DATA(net, net)
IPV6_DATA(seg6_flowlabel, &net->ipv6.sysctl.seg6_flowlabel)
IPV6_DATA(fib_notify_on_flag_change, &net->ipv6.sysctl.fib_notify_on_flag_change)
IPV6_DATA(ioam6_id, &net->ipv6.sysctl.ioam6_id)
IPV6_DATA(ioam6_id_wide, &net->ipv6.sysctl.ioam6_id_wide)

static const struct ctl_field ipv6_table[] = {
	{
		.table = {
			.procname	= "bindv6only",
			.maxlen		= sizeof(u8),
			.mode		= 0644,
			.proc_handler	= proc_dou8vec_minmax,
		},
		.data = ipv6_bindv6only_data,
	},
	{
		.table = {
			.procname	= "anycast_src_echo_reply",
			.maxlen		= sizeof(u8),
			.mode		= 0644,
			.proc_handler	= proc_dou8vec_minmax,
		},
		.data = ipv6_anycast_src_echo_reply_data,
	},
	{
		.table = {
			.procname	= "flowlabel_consistency",
			.maxlen		= sizeof(u8),
			.mode		= 0644,
			.proc_handler	= proc_dou8vec_minmax,
		},
		.data = ipv6_flowlabel_consistency_data,
	},
	{
		.table = {
			.procname	= "auto_flowlabels",
			.maxlen		= sizeof(u8),
			.mode		= 0644,
			.proc_handler	= proc_dou8vec_minmax,
			.extra2		= &auto_flowlabels_max,
		},
		.data = ipv6_auto_flowlabels_data,
	},
	{
		.table = {
			.procname	= "fwmark_reflect",
			.maxlen		= sizeof(u8),
			.mode		= 0644,
			.proc_handler	= proc_dou8vec_minmax,
		},
		.data = ipv6_fwmark_reflect_data,
	},
	{
		.table = {
			.procname	= "idgen_retries",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = ipv6_idgen_retries_data,
	},
	{
		.table = {
			.procname	= "idgen_delay",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_jiffies,
		},
		.data = ipv6_idgen_delay_data,
	},
	{
		.table = {
			.procname	= "flowlabel_state_ranges",
			.maxlen		= sizeof(u8),
			.mode		= 0644,
			.proc_handler	= proc_dou8vec_minmax,
		},
		.data = ipv6_flowlabel_state_ranges_data,
	},
	{
		.table = {
			.procname	= "ip_nonlocal_bind",
			.maxlen		= sizeof(u8),
			.mode		= 0644,
			.proc_handler	= proc_dou8vec_minmax,
		},
		.data = ipv6_ip_nonlocal_bind_data,
	},
	{
		.table = {
			.procname	= "flowlabel_reflect",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ZERO,
			.extra2		= &flowlabel_reflect_max,
		},
		.data = ipv6_flowlabel_reflect_data,
	},
	{
		.table = {
			.procname	= "max_dst_opts_number",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = ipv6_max_dst_opts_cnt_data,
	},
	{
		.table = {
			.procname	= "max_hbh_opts_number",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = ipv6_max_hbh_opts_cnt_data,
	},
	{
		.table = {
			.procname	= "max_dst_opts_length",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = ipv6_max_dst_opts_len_data,
	},
	{
		.table = {
			.procname	= "max_hbh_length",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = ipv6_max_hbh_opts_len_data,
	},
	{
		.table = {
			.procname	= "fib_multipath_hash_policy",
			.maxlen		= sizeof(u8),
			.mode		= 0644,
			.proc_handler	= proc_rt6_multipath_hash_policy,
			.extra1		= SYSCTL_ZERO,
			.extra2		= SYSCTL_THREE,
		},
		.data = ipv6_net_data,
	},
	{
		.table = {
			.procname	= "fib_multipath_hash_fields",
			.maxlen		= sizeof(u32),
			.mode		= 0644,
			.proc_handler	= proc_rt6_multipath_hash_fields,
			.extra1		= SYSCTL_ONE,
			.extra2		= &rt6_multipath_hash_fields_all_mask,
		},
		.data = ipv6_net_data,
	},
	{
		.table = {
			.procname	= "seg6_flowlabel",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = ipv6_seg6_flowlabel_data,
	},
	{
		.table = {
			.procname	= "fib_notify_on_flag_change",
			.maxlen		= sizeof(u8),
			.mode		= 0644,
			.proc_handler	= proc_dou8vec_minmax,
			.extra1		= SYSCTL_ZERO,
			.extra2		= SYSCTL_TWO,
		},
		.data = ipv6_fib_notify_on_flag_change_data,
	},
	{
		.table = {
			.procname	= "ioam6_id",
			.maxlen		= sizeof(u32),
			.mode		= 0644,
			.proc_handler	= proc_douintvec_minmax,
			.extra2		= &ioam6_id_max,
		},
		.data = ipv6_ioam6_id_data,
	},
	{
		.table = {
			.procname	= "ioam6_id_wide",
			.maxlen		= sizeof(u64),
			.mode		= 0644,
			.proc_handler	= proc_doulongvec_minmax,
			.extra2		= &ioam6_id_wide_max,
		},
		.data = ipv6_ioam6_id_wide_data,
	},
};

static struct ctl_table ipv6_rotable[] = {
	{
		.procname	= "mld_max_msf",
		.data		= &sysctl_mld_max_msf,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "mld_qrv",
		.data		= &sysctl_mld_qrv,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE
	},
#ifdef CONFIG_NETLABEL
	{
		.procname	= "calipso_cache_enable",
		.data		= &calipso_cache_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "calipso_cache_bucket_size",
		.data		= &calipso_cache_bucketsize,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif /* CONFIG_NETLABEL */
};

static int __net_init ipv6_sysctl_net_init(struct net *net)
{
	int err;

	err = -ENOMEM;
	net->ipv6.sysctl.hdr = register_net_sysctl_fields(net, "net/ipv6",
							  ipv6_table,
							  ARRAY_SIZE(ipv6_table));
	if (!net->ipv6.sysctl.hdr)
		goto out;

	net->ipv6.sysctl.route_hdr = register_net_sysctl_fields(net,
								"net/ipv6/route",
								ipv6_route_sysctl_fields(),
								ipv6_route_sysctl_field_count(net));
	if (!net->ipv6.sysctl.route_hdr)
		goto out_unregister_ipv6_table;

	net->ipv6.sysctl.icmp_hdr = register_net_sysctl_fields(net,
							       "net/ipv6/icmp",
							       ipv6_icmp_sysctl_fields(),
							       ipv6_icmp_sysctl_field_count());
	if (!net->ipv6.sysctl.icmp_hdr)
		goto out_unregister_route_table;

	err = 0;
out:
	return err;
out_unregister_route_table:
	unregister_net_sysctl_table(net->ipv6.sysctl.route_hdr);
out_unregister_ipv6_table:
	unregister_net_sysctl_table(net->ipv6.sysctl.hdr);
	goto out;
}

static void __net_exit ipv6_sysctl_net_exit(struct net *net)
{
	unregister_net_sysctl_table(net->ipv6.sysctl.icmp_hdr);
	unregister_net_sysctl_table(net->ipv6.sysctl.route_hdr);
	unregister_net_sysctl_table(net->ipv6.sysctl.hdr);
}

static struct pernet_operations ipv6_sysctl_net_ops = {
	.init = ipv6_sysctl_net_init,
	.exit = ipv6_sysctl_net_exit,
};

static struct ctl_table_header *ip6_header;

int ipv6_sysctl_register(void)
{
	int err = -ENOMEM;

	ip6_header = register_net_sysctl(&init_net, "net/ipv6", ipv6_rotable);
	if (!ip6_header)
		goto out;

	err = register_pernet_subsys(&ipv6_sysctl_net_ops);
	if (err)
		goto err_pernet;
out:
	return err;

err_pernet:
	unregister_net_sysctl_table(ip6_header);
	goto out;
}

void ipv6_sysctl_unregister(void)
{
	unregister_net_sysctl_table(ip6_header);
	unregister_pernet_subsys(&ipv6_sysctl_net_ops);
}

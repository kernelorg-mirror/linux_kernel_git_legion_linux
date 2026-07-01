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
static unsigned int auto_flowlabels_max = IP6_AUTO_FLOW_LABEL_MAX;
static unsigned int rt6_multipath_hash_fields_all_mask =
	FIB_MULTIPATH_HASH_FIELD_ALL_MASK;
static unsigned int ioam6_id_max = IOAM6_DEFAULT_ID;
static u64 ioam6_id_wide_max = IOAM6_DEFAULT_ID_WIDE;

static int proc_rt6_multipath_hash_policy(const struct ctl_table *table, int write,
					  void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table tmp = *table;
	struct net *net;
	int ret;

	net = container_of(table->data, struct net,
			   ipv6.sysctl.multipath_hash_policy);
	tmp.extra1 = SYSCTL_UINT_ZERO;
	tmp.extra2 = SYSCTL_UINT_THREE;
	ret = proc_dou8vec_minmax(&tmp, write, buffer, lenp, ppos);
	if (write && ret == 0)
		call_netevent_notifiers(NETEVENT_IPV6_MPATH_HASH_UPDATE, net);

	return ret;
}

static int
proc_rt6_multipath_hash_fields(const struct ctl_table *table, int write, void *buffer,
			       size_t *lenp, loff_t *ppos)
{
	struct ctl_table tmp = *table;
	struct net *net;
	int ret;

	net = container_of(table->data, struct net,
			   ipv6.sysctl.multipath_hash_fields);
	tmp.extra1 = SYSCTL_UINT_ONE;
	tmp.extra2 = &rt6_multipath_hash_fields_all_mask;
	ret = proc_douintvec_minmax(&tmp, write, buffer, lenp, ppos);
	if (write && ret == 0)
		call_netevent_notifiers(NETEVENT_IPV6_MPATH_HASH_UPDATE, net);

	return ret;
}

#define IPV6_SYSCTL_DATA(type, name, field)				\
static type *ipv6_##name##_data(const struct sysctl_context *ctx)		\
{									\
	return &ctx->ns.net_ns->ipv6.sysctl.field;			\
}

#define IPV6_SYSCTL_CUSTOM_DATA(name, field)				\
static void *ipv6_##name##_data(const struct sysctl_context *ctx)		\
{									\
	return &ctx->ns.net_ns->ipv6.sysctl.field;			\
}

IPV6_SYSCTL_DATA(u8, bindv6only, bindv6only)
IPV6_SYSCTL_DATA(u8, anycast_src_echo_reply, anycast_src_echo_reply)
IPV6_SYSCTL_DATA(u8, flowlabel_consistency, flowlabel_consistency)
IPV6_SYSCTL_DATA(u8, auto_flowlabels, auto_flowlabels)
IPV6_SYSCTL_DATA(u8, fwmark_reflect, fwmark_reflect)
IPV6_SYSCTL_DATA(int, idgen_retries, idgen_retries)
IPV6_SYSCTL_CUSTOM_DATA(idgen_delay, idgen_delay)
IPV6_SYSCTL_DATA(u8, flowlabel_state_ranges, flowlabel_state_ranges)
IPV6_SYSCTL_DATA(u8, ip_nonlocal_bind, ip_nonlocal_bind)
IPV6_SYSCTL_DATA(int, flowlabel_reflect, flowlabel_reflect)
IPV6_SYSCTL_DATA(int, max_dst_opts_number, max_dst_opts_cnt)
IPV6_SYSCTL_DATA(int, max_hbh_opts_number, max_hbh_opts_cnt)
IPV6_SYSCTL_DATA(int, max_dst_opts_length, max_dst_opts_len)
IPV6_SYSCTL_DATA(int, max_hbh_length, max_hbh_opts_len)
IPV6_SYSCTL_CUSTOM_DATA(fib_multipath_hash_policy, multipath_hash_policy)
IPV6_SYSCTL_CUSTOM_DATA(fib_multipath_hash_fields, multipath_hash_fields)
IPV6_SYSCTL_DATA(int, seg6_flowlabel, seg6_flowlabel)
IPV6_SYSCTL_DATA(u8, fib_notify_on_flag_change, fib_notify_on_flag_change)
IPV6_SYSCTL_DATA(unsigned int, ioam6_id, ioam6_id)
IPV6_SYSCTL_CUSTOM_DATA(ioam6_id_wide, ioam6_id_wide)

static int proc_ioam6_id_wide(const struct ctl_table *table, int write,
			      void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table tmp = *table;

	tmp.extra2 = &ioam6_id_wide_max;
	return proc_doulongvec_minmax(&tmp, write, buffer, lenp, ppos);
}

static const struct sysctl_field ipv6_table[] = {
	SYSCTL_FIELD_U8("bindv6only", 0644, ipv6_bindv6only_data),
	SYSCTL_FIELD_U8("anycast_src_echo_reply", 0644,
		     ipv6_anycast_src_echo_reply_data),
	SYSCTL_FIELD_U8("flowlabel_consistency", 0644,
		     ipv6_flowlabel_consistency_data),
	SYSCTL_FIELD_STATIC_U8_MINMAX("auto_flowlabels", 0644,
				   ipv6_auto_flowlabels_data, NULL,
				   &auto_flowlabels_max),
	SYSCTL_FIELD_U8("fwmark_reflect", 0644, ipv6_fwmark_reflect_data),
	SYSCTL_FIELD_INT("idgen_retries", 0644, ipv6_idgen_retries_data),
	SYSCTL_FIELD_CUSTOM("idgen_delay", 0644, sizeof(int),
			 ipv6_idgen_delay_data, proc_dointvec_jiffies),
	SYSCTL_FIELD_U8("flowlabel_state_ranges", 0644,
		     ipv6_flowlabel_state_ranges_data),
	SYSCTL_FIELD_U8("ip_nonlocal_bind", 0644, ipv6_ip_nonlocal_bind_data),
	SYSCTL_FIELD_STATIC_INT_MINMAX("flowlabel_reflect", 0644,
				    ipv6_flowlabel_reflect_data,
				    SYSCTL_ZERO, &flowlabel_reflect_max),
	SYSCTL_FIELD_INT("max_dst_opts_number", 0644,
		      ipv6_max_dst_opts_number_data),
	SYSCTL_FIELD_INT("max_hbh_opts_number", 0644,
		      ipv6_max_hbh_opts_number_data),
	SYSCTL_FIELD_INT("max_dst_opts_length", 0644,
		      ipv6_max_dst_opts_length_data),
	SYSCTL_FIELD_INT("max_hbh_length", 0644, ipv6_max_hbh_length_data),
	SYSCTL_FIELD_CUSTOM("fib_multipath_hash_policy", 0644, sizeof(u8),
			 ipv6_fib_multipath_hash_policy_data,
			 proc_rt6_multipath_hash_policy),
	SYSCTL_FIELD_CUSTOM("fib_multipath_hash_fields", 0644, sizeof(u32),
			 ipv6_fib_multipath_hash_fields_data,
			 proc_rt6_multipath_hash_fields),
	SYSCTL_FIELD_INT("seg6_flowlabel", 0644, ipv6_seg6_flowlabel_data),
	SYSCTL_FIELD_STATIC_U8_MINMAX("fib_notify_on_flag_change", 0644,
				   ipv6_fib_notify_on_flag_change_data,
				   SYSCTL_UINT_ZERO, SYSCTL_UINT_TWO),
	SYSCTL_FIELD_STATIC_UINT_MINMAX("ioam6_id", 0644, ipv6_ioam6_id_data,
				     NULL, &ioam6_id_max),
	SYSCTL_FIELD_CUSTOM("ioam6_id_wide", 0644, sizeof(u64),
			 ipv6_ioam6_id_wide_data, proc_ioam6_id_wide),
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
	struct sysctl_context ctx = {
		.ns.net_ns = net,
	};
	int err = -ENOMEM;

	net->ipv6.sysctl.hdr = register_sysctl_fields(&net->sysctls, "net/ipv6",
						      ipv6_table, &ctx);
	if (!net->ipv6.sysctl.hdr)
		goto out;

	err = ipv6_route_sysctl_register(&ctx);
	if (err)
		goto out_err;

	err = ipv6_icmp_sysctl_register(&ctx);
	if (err)
		goto out_err;

	err = 0;
out:
	return err;
out_err:
	unregister_net_sysctl_table(net->ipv6.sysctl.route_hdr);
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

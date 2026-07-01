// SPDX-License-Identifier: GPL-2.0-or-later
/* SCTP kernel implementation
 * (C) Copyright IBM Corp. 2002, 2004
 * Copyright (c) 2002 Intel Corp.
 *
 * This file is part of the SCTP kernel implementation
 *
 * Sysctl related interfaces for SCTP.
 *
 * Please send any bug reports or fixes you make to the
 * email address(es):
 *    lksctp developers <linux-sctp@vger.kernel.org>
 *
 * Written or modified by:
 *    Mingqin Liu           <liuming@us.ibm.com>
 *    Jon Grimm             <jgrimm@us.ibm.com>
 *    Ardelle Fan           <ardelle.fan@intel.com>
 *    Ryan Layer            <rmlayer@us.ibm.com>
 *    Sridhar Samudrala     <sri@us.ibm.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <net/sctp/structs.h>
#include <net/sctp/sctp.h>
#include <linux/sysctl.h>

static unsigned int timer_max = 86400000; /* ms in one day */
static unsigned int sack_timer_min = 1;
static unsigned int sack_timer_max = 500;
static int addr_scope_max = SCTP_SCOPE_POLICY_MAX;
static int rwnd_scale_max = 16;
static int rto_alpha_min = 0;
static int rto_beta_min = 0;
static int rto_alpha_max = 1000;
static int rto_beta_max = 1000;
static int pf_expose_max = SCTP_PF_EXPOSE_MAX;
static int ps_retrans_max = SCTP_PS_RETRANS_MAX;
static int udp_port_max = 65535;

static unsigned long max_autoclose_min = 0;
static unsigned long max_autoclose_max =
	(MAX_SCHEDULE_TIMEOUT / HZ > UINT_MAX)
	? UINT_MAX : MAX_SCHEDULE_TIMEOUT / HZ;

static int proc_sctp_do_hmac_alg(const struct ctl_table *ctl, int write,
				 void *buffer, size_t *lenp, loff_t *ppos);
static int proc_sctp_do_rto_min(const struct ctl_table *ctl, int write,
				void *buffer, size_t *lenp, loff_t *ppos);
static int proc_sctp_do_rto_max(const struct ctl_table *ctl, int write, void *buffer,
				size_t *lenp, loff_t *ppos);
static int proc_sctp_do_udp_port(const struct ctl_table *ctl, int write, void *buffer,
				 size_t *lenp, loff_t *ppos);
static int proc_sctp_do_alpha(const struct ctl_table *ctl, int write,
			      void *buffer, size_t *lenp, loff_t *ppos);
static int proc_sctp_do_beta(const struct ctl_table *ctl, int write,
			     void *buffer, size_t *lenp, loff_t *ppos);
static int proc_sctp_do_auth(const struct ctl_table *ctl, int write,
			     void *buffer, size_t *lenp, loff_t *ppos);
static int proc_sctp_do_probe_interval(const struct ctl_table *ctl, int write,
				       void *buffer, size_t *lenp, loff_t *ppos);

static struct ctl_table sctp_table[] = {
	{
		.procname	= "sctp_mem",
		.data		= &sysctl_sctp_mem,
		.maxlen		= sizeof(sysctl_sctp_mem),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax
	},
	{
		.procname	= "sctp_rmem",
		.data		= &sysctl_sctp_rmem,
		.maxlen		= sizeof(sysctl_sctp_rmem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "sctp_wmem",
		.data		= &sysctl_sctp_wmem,
		.maxlen		= sizeof(sysctl_sctp_wmem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
};

static int *sctp_ps_retrans_max_data(const struct ctl_context *ctx)
{
	return &ps_retrans_max;
}

#define SCTP_DATA(type, field)						\
static type *sctp_ ## field ## _data(const struct ctl_context *ctx)	\
{									\
	return &ctx->ns.net_ns->sctp.field;				\
}

#define SCTP_CUSTOM_DATA(field)						\
static void *sctp_ ## field ## _data(const struct ctl_context *ctx)	\
{									\
	return &ctx->ns.net_ns->sctp.field;				\
}

SCTP_CUSTOM_DATA(rto_min)
SCTP_CUSTOM_DATA(rto_max)
SCTP_DATA(int, pf_retrans)
SCTP_DATA(int, ps_retrans)
SCTP_DATA(unsigned int, rto_initial)
SCTP_CUSTOM_DATA(rto_alpha)
SCTP_CUSTOM_DATA(rto_beta)
SCTP_DATA(int, max_burst)
SCTP_DATA(int, cookie_preserve_enable)
SCTP_CUSTOM_DATA(cookie_auth_enable)
SCTP_DATA(unsigned int, valid_cookie_life)
SCTP_DATA(unsigned int, sack_timeout)
SCTP_DATA(unsigned int, hb_interval)
SCTP_DATA(int, max_retrans_association)
SCTP_DATA(int, max_retrans_path)
SCTP_DATA(int, max_retrans_init)
SCTP_DATA(int, sndbuf_policy)
SCTP_DATA(int, rcvbuf_policy)
SCTP_DATA(int, default_auto_asconf)
SCTP_DATA(int, addip_enable)
SCTP_DATA(int, addip_noauth)
SCTP_DATA(int, prsctp_enable)
SCTP_DATA(int, reconf_enable)
SCTP_CUSTOM_DATA(auth_enable)
SCTP_DATA(int, intl_enable)
SCTP_DATA(int, ecn_enable)
SCTP_CUSTOM_DATA(probe_interval)
SCTP_CUSTOM_DATA(udp_port)
SCTP_DATA(int, encap_port)
SCTP_DATA(int, scope_policy)
SCTP_DATA(int, rwnd_upd_shift)
SCTP_DATA(unsigned long, max_autoclose)
SCTP_DATA(int, pf_enable)
SCTP_DATA(int, pf_expose)
#ifdef CONFIG_NET_L3_MASTER_DEV
SCTP_DATA(int, l3mdev_accept)
#endif

static const struct ctl_field sctp_net_table[] = {
	CTL_FIELD_CUSTOM("rto_min", 0644, sizeof(unsigned int),
			 sctp_rto_min_data, proc_sctp_do_rto_min),
	CTL_FIELD_CUSTOM("rto_max", 0644, sizeof(unsigned int),
			 sctp_rto_max_data, proc_sctp_do_rto_max),
	CTL_FIELD_INT_MINMAX("pf_retrans", 0644, sctp_pf_retrans_data,
			     SYSCTL_ZERO, sctp_ps_retrans_data),
	CTL_FIELD_INT_MINMAX("ps_retrans", 0644, sctp_ps_retrans_data,
			     sctp_pf_retrans_data, sctp_ps_retrans_max_data),
	CTL_FIELD_STATIC_UINT_MINMAX("rto_initial", 0644,
				     sctp_rto_initial_data,
				     SYSCTL_UINT_ONE, &timer_max),
	CTL_FIELD_CUSTOM("rto_alpha_exp_divisor", 0644, sizeof(int),
			 sctp_rto_alpha_data, proc_sctp_do_alpha),
	CTL_FIELD_CUSTOM("rto_beta_exp_divisor", 0644, sizeof(int),
			 sctp_rto_beta_data, proc_sctp_do_beta),
	CTL_FIELD_STATIC_INT_MINMAX("max_burst", 0644, sctp_max_burst_data,
				    SYSCTL_ZERO, SYSCTL_INT_MAX),
	CTL_FIELD_INT("cookie_preserve_enable", 0644,
		      sctp_cookie_preserve_enable_data),
	CTL_FIELD_CUSTOM("cookie_hmac_alg", 0644, 8,
			 sctp_cookie_auth_enable_data, proc_sctp_do_hmac_alg),
	CTL_FIELD_STATIC_UINT_MINMAX("valid_cookie_life", 0644,
				     sctp_valid_cookie_life_data,
				     SYSCTL_UINT_ONE, &timer_max),
	CTL_FIELD_STATIC_UINT_MINMAX("sack_timeout", 0644,
				     sctp_sack_timeout_data,
				     &sack_timer_min, &sack_timer_max),
	CTL_FIELD_STATIC_UINT_MINMAX("hb_interval", 0644,
				     sctp_hb_interval_data,
				     SYSCTL_UINT_ONE, &timer_max),
	CTL_FIELD_STATIC_INT_MINMAX("association_max_retrans", 0644,
				    sctp_max_retrans_association_data,
				    SYSCTL_ONE, SYSCTL_INT_MAX),
	CTL_FIELD_STATIC_INT_MINMAX("path_max_retrans", 0644,
				    sctp_max_retrans_path_data,
				    SYSCTL_ONE, SYSCTL_INT_MAX),
	CTL_FIELD_STATIC_INT_MINMAX("max_init_retransmits", 0644,
				    sctp_max_retrans_init_data,
				    SYSCTL_ONE, SYSCTL_INT_MAX),
	CTL_FIELD_INT("sndbuf_policy", 0644, sctp_sndbuf_policy_data),
	CTL_FIELD_INT("rcvbuf_policy", 0644, sctp_rcvbuf_policy_data),
	CTL_FIELD_INT("default_auto_asconf", 0644,
		      sctp_default_auto_asconf_data),
	CTL_FIELD_INT("addip_enable", 0644, sctp_addip_enable_data),
	CTL_FIELD_INT("addip_noauth_enable", 0644, sctp_addip_noauth_data),
	CTL_FIELD_INT("prsctp_enable", 0644, sctp_prsctp_enable_data),
	CTL_FIELD_INT("reconf_enable", 0644, sctp_reconf_enable_data),
	CTL_FIELD_CUSTOM("auth_enable", 0644, sizeof(int),
			 sctp_auth_enable_data, proc_sctp_do_auth),
	CTL_FIELD_INT("intl_enable", 0644, sctp_intl_enable_data),
	CTL_FIELD_INT("ecn_enable", 0644, sctp_ecn_enable_data),
	CTL_FIELD_CUSTOM("plpmtud_probe_interval", 0644, sizeof(int),
			 sctp_probe_interval_data,
			 proc_sctp_do_probe_interval),
	CTL_FIELD_CUSTOM("udp_port", 0644, sizeof(int),
			 sctp_udp_port_data, proc_sctp_do_udp_port),
	CTL_FIELD_STATIC_INT_MINMAX("encap_port", 0644,
				    sctp_encap_port_data,
				    SYSCTL_ZERO, &udp_port_max),
	CTL_FIELD_STATIC_INT_MINMAX("addr_scope_policy", 0644,
				    sctp_scope_policy_data,
				    SYSCTL_ZERO, &addr_scope_max),
	CTL_FIELD_STATIC_INT_MINMAX("rwnd_update_shift", 0644,
				    sctp_rwnd_upd_shift_data,
				    SYSCTL_ONE, &rwnd_scale_max),
	CTL_FIELD_STATIC_ULONG_MINMAX("max_autoclose", 0644,
				      sctp_max_autoclose_data,
				      &max_autoclose_min, &max_autoclose_max),
#ifdef CONFIG_NET_L3_MASTER_DEV
	CTL_FIELD_STATIC_INT_MINMAX("l3mdev_accept", 0644,
				    sctp_l3mdev_accept_data,
				    SYSCTL_ZERO, SYSCTL_ONE),
#endif
	CTL_FIELD_INT("pf_enable", 0644, sctp_pf_enable_data),
	CTL_FIELD_STATIC_INT_MINMAX("pf_expose", 0644, sctp_pf_expose_data,
				    SYSCTL_ZERO, &pf_expose_max),
};

static int proc_sctp_do_hmac_alg(const struct ctl_table *ctl, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = container_of(ctl->data, struct net,
				       sctp.cookie_auth_enable);
	struct ctl_table tbl;
	char tmp[8] = {0};
	int ret;

	memset(&tbl, 0, sizeof(struct ctl_table));

	if (write) {
		tbl.data = tmp;
		tbl.maxlen = sizeof(tmp) - 1;
		ret = proc_dostring(&tbl, 1, buffer, lenp, ppos);
		if (ret)
			return ret;
		if (!strcmp(tmp, "sha256")) {
			net->sctp.cookie_auth_enable = 1;
			return 0;
		}
		if (!strcmp(tmp, "none")) {
			net->sctp.cookie_auth_enable = 0;
			return 0;
		}
		return -EINVAL;
	}
	if (net->sctp.cookie_auth_enable)
		tbl.data = (char *)"sha256";
	else
		tbl.data = (char *)"none";
	tbl.maxlen = strlen(tbl.data);
	return proc_dostring(&tbl, 0, buffer, lenp, ppos);
}

static int proc_sctp_do_rto_min(const struct ctl_table *ctl, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = container_of(ctl->data, struct net, sctp.rto_min);
	struct ctl_table tbl;
	int ret, new_value;

	memset(&tbl, 0, sizeof(struct ctl_table));
	tbl.maxlen = sizeof(unsigned int);

	if (write)
		tbl.data = &new_value;
	else
		tbl.data = &net->sctp.rto_min;

	ret = proc_dointvec(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0) {
		if (new_value > (int) net->sctp.rto_max || new_value < 1)
			return -EINVAL;

		net->sctp.rto_min = new_value;
	}

	return ret;
}

static int proc_sctp_do_rto_max(const struct ctl_table *ctl, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = container_of(ctl->data, struct net, sctp.rto_max);
	struct ctl_table tbl;
	int ret, new_value;

	memset(&tbl, 0, sizeof(struct ctl_table));
	tbl.maxlen = sizeof(unsigned int);

	if (write)
		tbl.data = &new_value;
	else
		tbl.data = &net->sctp.rto_max;

	ret = proc_dointvec(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0) {
		if (new_value > (int) timer_max ||
		    new_value < (int) net->sctp.rto_min)
			return -EINVAL;

		net->sctp.rto_max = new_value;
	}

	return ret;
}

static int proc_sctp_do_alpha_beta(const struct ctl_table *ctl, int write,
				   void *buffer, size_t *lenp, loff_t *ppos)
{
	if (write)
		pr_warn_once("Changing rto_alpha or rto_beta may lead to "
			     "suboptimal rtt/srtt estimations!\n");

	return proc_dointvec_minmax(ctl, write, buffer, lenp, ppos);
}

static int proc_sctp_do_alpha(const struct ctl_table *ctl, int write,
			      void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table tmp = *ctl;

	tmp.extra1 = &rto_alpha_min;
	tmp.extra2 = &rto_alpha_max;

	return proc_sctp_do_alpha_beta(&tmp, write, buffer, lenp, ppos);
}

static int proc_sctp_do_beta(const struct ctl_table *ctl, int write,
			     void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table tmp = *ctl;

	tmp.extra1 = &rto_beta_min;
	tmp.extra2 = &rto_beta_max;

	return proc_sctp_do_alpha_beta(&tmp, write, buffer, lenp, ppos);
}

static int proc_sctp_do_auth(const struct ctl_table *ctl, int write,
			     void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = container_of(ctl->data, struct net, sctp.auth_enable);
	struct ctl_table tbl;
	int new_value, ret;

	memset(&tbl, 0, sizeof(struct ctl_table));
	tbl.maxlen = sizeof(unsigned int);

	if (write)
		tbl.data = &new_value;
	else
		tbl.data = &net->sctp.auth_enable;

	ret = proc_dointvec(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0) {
		struct sock *sk = net->sctp.ctl_sock;

		net->sctp.auth_enable = new_value;
		/* Update the value in the control socket */
		lock_sock(sk);
		sctp_sk(sk)->ep->auth_enable = new_value;
		release_sock(sk);
	}

	return ret;
}

static DEFINE_MUTEX(sctp_sysctl_mutex);

static int proc_sctp_do_udp_port(const struct ctl_table *ctl, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = container_of(ctl->data, struct net, sctp.udp_port);
	struct ctl_table tbl;
	int ret, new_value;

	memset(&tbl, 0, sizeof(struct ctl_table));
	tbl.maxlen = sizeof(unsigned int);

	if (write)
		tbl.data = &new_value;
	else
		tbl.data = &net->sctp.udp_port;

	ret = proc_dointvec(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0) {
		struct sock *sk = net->sctp.ctl_sock;

		if (new_value > udp_port_max || new_value < 0)
			return -EINVAL;

		mutex_lock(&sctp_sysctl_mutex);
		net->sctp.udp_port = new_value;
		sctp_udp_sock_stop(net);
		if (new_value) {
			ret = sctp_udp_sock_start(net);
			if (ret)
				net->sctp.udp_port = 0;
		}

		/* Update the value in the control socket */
		lock_sock(sk);
		sctp_sk(sk)->udp_port = htons(net->sctp.udp_port);
		release_sock(sk);
		mutex_unlock(&sctp_sysctl_mutex);
	}

	return ret;
}

static int proc_sctp_do_probe_interval(const struct ctl_table *ctl, int write,
				       void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = container_of(ctl->data, struct net,
				       sctp.probe_interval);
	struct ctl_table tbl;
	int ret, new_value;

	memset(&tbl, 0, sizeof(struct ctl_table));
	tbl.maxlen = sizeof(unsigned int);

	if (write)
		tbl.data = &new_value;
	else
		tbl.data = &net->sctp.probe_interval;

	ret = proc_dointvec(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0) {
		if (new_value && new_value < SCTP_PROBE_TIMER_MIN)
			return -EINVAL;

		net->sctp.probe_interval = new_value;
	}

	return ret;
}

int sctp_sysctl_net_register(struct net *net)
{
	net->sctp.sysctl_header = register_net_sysctl_fields_sz(net, "net/sctp",
								sctp_net_table,
								ARRAY_SIZE(sctp_net_table));
	if (net->sctp.sysctl_header == NULL)
		return -ENOMEM;

	return 0;
}

void sctp_sysctl_net_unregister(struct net *net)
{
	unregister_net_sysctl_table(net->sctp.sysctl_header);
}

static struct ctl_table_header *sctp_sysctl_header;

/* Sysctl registration.  */
void sctp_sysctl_register(void)
{
	sctp_sysctl_header = register_net_sysctl(&init_net, "net/sctp", sctp_table);
}

/* Sysctl deregistration.  */
void sctp_sysctl_unregister(void)
{
	unregister_net_sysctl_table(sctp_sysctl_header);
}

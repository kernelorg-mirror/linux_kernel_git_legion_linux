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

static int timer_max = 86400000; /* ms in one day */
static int sack_timer_min = 1;
static int sack_timer_max = 500;
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
static int proc_sctp_do_alpha_beta(const struct ctl_table *ctl, int write,
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

#define SCTP_DATA(name, expr)						\
static void *sctp_ ## name ## _data(const struct ctl_context *ctx)	\
{									\
	struct net *net = ctx->ns.net_ns;				\
	return (expr);							\
}

SCTP_DATA(net, net)
SCTP_DATA(rto_initial, &net->sctp.rto_initial)
SCTP_DATA(rto_min, &net->sctp.rto_min)
SCTP_DATA(rto_max, &net->sctp.rto_max)
SCTP_DATA(rto_alpha, &net->sctp.rto_alpha)
SCTP_DATA(rto_beta, &net->sctp.rto_beta)
SCTP_DATA(max_burst, &net->sctp.max_burst)
SCTP_DATA(cookie_preserve_enable, &net->sctp.cookie_preserve_enable)
SCTP_DATA(valid_cookie_life, &net->sctp.valid_cookie_life)
SCTP_DATA(sack_timeout, &net->sctp.sack_timeout)
SCTP_DATA(hb_interval, &net->sctp.hb_interval)
SCTP_DATA(max_retrans_association, &net->sctp.max_retrans_association)
SCTP_DATA(max_retrans_path, &net->sctp.max_retrans_path)
SCTP_DATA(max_retrans_init, &net->sctp.max_retrans_init)
SCTP_DATA(sndbuf_policy, &net->sctp.sndbuf_policy)
SCTP_DATA(rcvbuf_policy, &net->sctp.rcvbuf_policy)
SCTP_DATA(default_auto_asconf, &net->sctp.default_auto_asconf)
SCTP_DATA(addip_enable, &net->sctp.addip_enable)
SCTP_DATA(addip_noauth, &net->sctp.addip_noauth)
SCTP_DATA(prsctp_enable, &net->sctp.prsctp_enable)
SCTP_DATA(reconf_enable, &net->sctp.reconf_enable)
SCTP_DATA(intl_enable, &net->sctp.intl_enable)
SCTP_DATA(ecn_enable, &net->sctp.ecn_enable)
SCTP_DATA(pf_retrans, &net->sctp.pf_retrans)
SCTP_DATA(ps_retrans, &net->sctp.ps_retrans)
SCTP_DATA(encap_port, &net->sctp.encap_port)
SCTP_DATA(scope_policy, &net->sctp.scope_policy)
SCTP_DATA(rwnd_upd_shift, &net->sctp.rwnd_upd_shift)
SCTP_DATA(max_autoclose, &net->sctp.max_autoclose)
#ifdef CONFIG_NET_L3_MASTER_DEV
SCTP_DATA(l3mdev_accept, &net->sctp.l3mdev_accept)
#endif
SCTP_DATA(pf_enable, &net->sctp.pf_enable)
SCTP_DATA(pf_expose, &net->sctp.pf_expose)

static const struct ctl_field sctp_net_table[] = {
	{
		.table = {
			.procname	= "rto_min",
			.maxlen		= sizeof(unsigned int),
			.mode		= 0644,
			.proc_handler	= proc_sctp_do_rto_min,
			.extra1		= SYSCTL_ONE,
		},
		.data   = sctp_net_data,
		.extra2 = sctp_rto_max_data,
	},
	{
		.table = {
			.procname	= "rto_max",
			.maxlen		= sizeof(unsigned int),
			.mode		= 0644,
			.proc_handler	= proc_sctp_do_rto_max,
			.extra2		= &timer_max,
		},
		.data   = sctp_net_data,
		.extra1 = sctp_rto_min_data,
	},
	{
		.table = {
			.procname	= "pf_retrans",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ZERO,
		},
		.data   = sctp_pf_retrans_data,
		.extra2 = sctp_ps_retrans_data,
	},
	{
		.table = {
			.procname	= "ps_retrans",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra2		= &ps_retrans_max,
		},
		.data   = sctp_ps_retrans_data,
		.extra1 = sctp_pf_retrans_data,
	},
	{
		.table = {
			.procname	= "rto_initial",
			.maxlen		= sizeof(unsigned int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ONE,
			.extra2		= &timer_max,
		},
		.data = sctp_rto_initial_data,
	},
	{
		.table = {
			.procname	= "rto_alpha_exp_divisor",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_sctp_do_alpha_beta,
			.extra1		= &rto_alpha_min,
			.extra2		= &rto_alpha_max,
		},
		.data = sctp_rto_alpha_data,
	},
	{
		.table = {
			.procname	= "rto_beta_exp_divisor",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_sctp_do_alpha_beta,
			.extra1		= &rto_beta_min,
			.extra2		= &rto_beta_max,
		},
		.data = sctp_rto_beta_data,
	},
	{
		.table = {
			.procname	= "max_burst",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ZERO,
			.extra2		= SYSCTL_INT_MAX,
		},
		.data = sctp_max_burst_data,
	},
	{
		.table = {
			.procname	= "cookie_preserve_enable",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = sctp_cookie_preserve_enable_data,
	},
	{
		.table = {
			.procname	= "cookie_hmac_alg",
			.maxlen		= 8,
			.mode		= 0644,
			.proc_handler	= proc_sctp_do_hmac_alg,
		},
		.data = sctp_net_data,
	},
	{
		.table = {
			.procname	= "valid_cookie_life",
			.maxlen		= sizeof(unsigned int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ONE,
			.extra2		= &timer_max,
		},
		.data = sctp_valid_cookie_life_data,
	},
	{
		.table = {
			.procname	= "sack_timeout",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= &sack_timer_min,
			.extra2		= &sack_timer_max,
		},
		.data = sctp_sack_timeout_data,
	},
	{
		.table = {
			.procname	= "hb_interval",
			.maxlen		= sizeof(unsigned int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ONE,
			.extra2		= &timer_max,
		},
		.data = sctp_hb_interval_data,
	},
	{
		.table = {
			.procname	= "association_max_retrans",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ONE,
			.extra2		= SYSCTL_INT_MAX,
		},
		.data = sctp_max_retrans_association_data,
	},
	{
		.table = {
			.procname	= "path_max_retrans",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ONE,
			.extra2		= SYSCTL_INT_MAX,
		},
		.data = sctp_max_retrans_path_data,
	},
	{
		.table = {
			.procname	= "max_init_retransmits",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ONE,
			.extra2		= SYSCTL_INT_MAX,
		},
		.data = sctp_max_retrans_init_data,
	},
	{
		.table = {
			.procname	= "sndbuf_policy",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = sctp_sndbuf_policy_data,
	},
	{
		.table = {
			.procname	= "rcvbuf_policy",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = sctp_rcvbuf_policy_data,
	},
	{
		.table = {
			.procname	= "default_auto_asconf",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = sctp_default_auto_asconf_data,
	},
	{
		.table = {
			.procname	= "addip_enable",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = sctp_addip_enable_data,
	},
	{
		.table = {
			.procname	= "addip_noauth_enable",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = sctp_addip_noauth_data,
	},
	{
		.table = {
			.procname	= "prsctp_enable",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = sctp_prsctp_enable_data,
	},
	{
		.table = {
			.procname	= "reconf_enable",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = sctp_reconf_enable_data,
	},
	{
		.table = {
			.procname	= "auth_enable",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_sctp_do_auth,
		},
		.data = sctp_net_data,
	},
	{
		.table = {
			.procname	= "intl_enable",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = sctp_intl_enable_data,
	},
	{
		.table = {
			.procname	= "ecn_enable",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = sctp_ecn_enable_data,
	},
	{
		.table = {
			.procname	= "plpmtud_probe_interval",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_sctp_do_probe_interval,
		},
		.data = sctp_net_data,
	},
	{
		.table = {
			.procname	= "udp_port",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_sctp_do_udp_port,
			.extra1		= SYSCTL_ZERO,
			.extra2		= &udp_port_max,
		},
		.data = sctp_net_data,
	},
	{
		.table = {
			.procname	= "encap_port",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ZERO,
			.extra2		= &udp_port_max,
		},
		.data = sctp_encap_port_data,
	},
	{
		.table = {
			.procname	= "addr_scope_policy",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ZERO,
			.extra2		= &addr_scope_max,
		},
		.data = sctp_scope_policy_data,
	},
	{
		.table = {
			.procname	= "rwnd_update_shift",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ONE,
			.extra2		= &rwnd_scale_max,
		},
		.data = sctp_rwnd_upd_shift_data,
	},
	{
		.table = {
			.procname	= "max_autoclose",
			.maxlen		= sizeof(unsigned long),
			.mode		= 0644,
			.proc_handler	= proc_doulongvec_minmax,
			.extra1		= &max_autoclose_min,
			.extra2		= &max_autoclose_max,
		},
		.data = sctp_max_autoclose_data,
	},
#ifdef CONFIG_NET_L3_MASTER_DEV
	{
		.table = {
			.procname	= "l3mdev_accept",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ZERO,
			.extra2		= SYSCTL_ONE,
		},
		.data = sctp_l3mdev_accept_data,
	},
#endif
	{
		.table = {
			.procname	= "pf_enable",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec,
		},
		.data = sctp_pf_enable_data,
	},
	{
		.table = {
			.procname	= "pf_expose",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= SYSCTL_ZERO,
			.extra2		= &pf_expose_max,
		},
		.data = sctp_pf_expose_data,
	},
};

static int proc_sctp_do_hmac_alg(const struct ctl_table *ctl, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = ctl->data;
	char tmp[8] = {0};
	int ret;

	if (write) {
		const struct ctl_table tbl = {
			.data	= tmp,
			.maxlen	= sizeof(tmp) - 1,
		};

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

	{
		const char *hmac = net->sctp.cookie_auth_enable ? "sha256" :
				    "none";
		const struct ctl_table tbl = {
			.data	= (void *)hmac,
			.maxlen	= strlen(hmac),
		};

		return proc_dostring(&tbl, 0, buffer, lenp, ppos);
	}
}

static int proc_sctp_do_rto_min(const struct ctl_table *ctl, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = ctl->data;
	unsigned int min = *(unsigned int *) ctl->extra1;
	unsigned int max = *(unsigned int *) ctl->extra2;
	unsigned int new_value;
	int ret;
	const struct ctl_table tbl = {
		.data	= write ? &new_value : &net->sctp.rto_min,
		.maxlen	= sizeof(unsigned int),
	};

	ret = proc_dointvec(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0) {
		if (new_value > max || new_value < min)
			return -EINVAL;

		net->sctp.rto_min = new_value;
	}

	return ret;
}

static int proc_sctp_do_rto_max(const struct ctl_table *ctl, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = ctl->data;
	unsigned int min = *(unsigned int *) ctl->extra1;
	unsigned int max = *(unsigned int *) ctl->extra2;
	unsigned int new_value;
	int ret;
	const struct ctl_table tbl = {
		.data	= write ? &new_value : &net->sctp.rto_max,
		.maxlen	= sizeof(unsigned int),
	};

	ret = proc_dointvec(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0) {
		if (new_value > max || new_value < min)
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

static int proc_sctp_do_auth(const struct ctl_table *ctl, int write,
			     void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = ctl->data;
	int new_value, ret;
	const struct ctl_table tbl = {
		.data	= write ? &new_value : &net->sctp.auth_enable,
		.maxlen	= sizeof(unsigned int),
	};

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
	struct net *net = ctl->data;
	unsigned int min = *(unsigned int *)ctl->extra1;
	unsigned int max = *(unsigned int *)ctl->extra2;
	int ret, new_value;
	const struct ctl_table tbl = {
		.data	= write ? &new_value : &net->sctp.udp_port,
		.maxlen	= sizeof(unsigned int),
	};

	ret = proc_dointvec(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0) {
		struct sock *sk = net->sctp.ctl_sock;

		if (new_value > max || new_value < min)
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
	struct net *net = ctl->data;
	unsigned int new_value;
	int ret;
	const struct ctl_table tbl = {
		.data	= write ? &new_value : &net->sctp.probe_interval,
		.maxlen	= sizeof(unsigned int),
	};

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
	net->sctp.sysctl_header = register_net_sysctl_fields(net, "net/sctp",
							     sctp_net_table,
							     ARRAY_SIZE(sctp_net_table));
	if (!net->sctp.sysctl_header)
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

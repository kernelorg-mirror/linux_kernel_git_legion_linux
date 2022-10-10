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

static int proc_sctp_do_hmac_alg(struct ctl_table *ctl, int write,
				 void *buffer, size_t *lenp, loff_t *ppos);
static ssize_t proc_sctp_do_alpha_beta_write(struct ctl_context *ctx, struct file *file,
					     char *buffer, size_t *lenp, loff_t *ppos);

static struct ctl_fops proc_sctp_do_alpha_beta_fops = {
	.read  = sysctl_read_intvec,
	.write = proc_sctp_do_alpha_beta_write,
};

static ssize_t proc_sctp_do_rto_min_read(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos);
static ssize_t proc_sctp_do_rto_min_write(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos);

static struct ctl_fops proc_sctp_do_rto_min_fops = {
	.read  = proc_sctp_do_rto_min_read,
	.write = proc_sctp_do_rto_min_write,
};

static ssize_t proc_sctp_do_rto_max_read(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos);
static ssize_t proc_sctp_do_rto_max_write(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos);

static struct ctl_fops proc_sctp_do_rto_max_fops = {
	.read  = proc_sctp_do_rto_max_read,
	.write = proc_sctp_do_rto_max_write,
};

static ssize_t proc_sctp_do_auth_read(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos);
static ssize_t proc_sctp_do_auth_write(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos);

static struct ctl_fops proc_sctp_do_auth_fops = {
	.read  = proc_sctp_do_auth_read,
	.write = proc_sctp_do_auth_write,
};

static ssize_t proc_sctp_do_udp_port_read(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos);
static ssize_t proc_sctp_do_udp_port_write(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos);

static struct ctl_fops proc_sctp_do_udp_port_fops = {
	.read  = proc_sctp_do_udp_port_read,
	.write = proc_sctp_do_udp_port_write,
};

static ssize_t proc_sctp_do_probe_interval_read(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos);
static ssize_t proc_sctp_do_probe_interval_write(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos);

static struct ctl_fops proc_sctp_do_probe_interval_fops = {
	.read  = proc_sctp_do_probe_interval_read,
	.write = proc_sctp_do_probe_interval_write,
};

static struct ctl_table sctp_table[] = {
	{
		.procname	= "sctp_mem",
		.data		= &sysctl_sctp_mem,
		.maxlen		= sizeof(sysctl_sctp_mem),
		.mode		= 0644,
		.proc_handler	= &sysctl_ulongvec_fops,
	},
	{
		.procname	= "sctp_rmem",
		.data		= &sysctl_sctp_rmem,
		.maxlen		= sizeof(sysctl_sctp_rmem),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
	},
	{
		.procname	= "sctp_wmem",
		.data		= &sysctl_sctp_wmem,
		.maxlen		= sizeof(sysctl_sctp_wmem),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
	},

	{ /* sentinel */ }
};

static struct ctl_table sctp_net_table[] = {
	{
		.procname	= "rto_initial",
		.data		= &init_net.sctp.rto_initial,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
		.extra1         = SYSCTL_ONE,
		.extra2         = &timer_max
	},
	{
		.procname	= "rto_min",
		.data		= &init_net.sctp.rto_min,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.ctl_fops	= &proc_sctp_do_rto_min_fops,
		.extra1         = SYSCTL_ONE,
		.extra2         = &init_net.sctp.rto_max
	},
	{
		.procname	= "rto_max",
		.data		= &init_net.sctp.rto_max,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.ctl_fops	= &proc_sctp_do_rto_max_fops,
		.extra1         = &init_net.sctp.rto_min,
		.extra2         = &timer_max
	},
	{
		.procname	= "rto_alpha_exp_divisor",
		.data		= &init_net.sctp.rto_alpha,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &proc_sctp_do_alpha_beta_fops,
		.extra1		= &rto_alpha_min,
		.extra2		= &rto_alpha_max,
	},
	{
		.procname	= "rto_beta_exp_divisor",
		.data		= &init_net.sctp.rto_beta,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &proc_sctp_do_alpha_beta_fops,
		.extra1		= &rto_beta_min,
		.extra2		= &rto_beta_max,
	},
	{
		.procname	= "max_burst",
		.data		= &init_net.sctp.max_burst,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_INT_MAX,
	},
	{
		.procname	= "cookie_preserve_enable",
		.data		= &init_net.sctp.cookie_preserve_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
	},
	{
		.procname	= "cookie_hmac_alg",
		.data		= &init_net.sctp.sctp_hmac_alg,
		.maxlen		= 8,
		.mode		= 0644,
		.proc_handler	= proc_sctp_do_hmac_alg,
	},
	{
		.procname	= "valid_cookie_life",
		.data		= &init_net.sctp.valid_cookie_life,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
		.extra1         = SYSCTL_ONE,
		.extra2         = &timer_max
	},
	{
		.procname	= "sack_timeout",
		.data		= &init_net.sctp.sack_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
		.extra1         = &sack_timer_min,
		.extra2         = &sack_timer_max,
	},
	{
		.procname	= "hb_interval",
		.data		= &init_net.sctp.hb_interval,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
		.extra1         = SYSCTL_ONE,
		.extra2         = &timer_max
	},
	{
		.procname	= "association_max_retrans",
		.data		= &init_net.sctp.max_retrans_association,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
		.extra1		= SYSCTL_ONE,
		.extra2		= SYSCTL_INT_MAX,
	},
	{
		.procname	= "path_max_retrans",
		.data		= &init_net.sctp.max_retrans_path,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
		.extra1		= SYSCTL_ONE,
		.extra2		= SYSCTL_INT_MAX,
	},
	{
		.procname	= "max_init_retransmits",
		.data		= &init_net.sctp.max_retrans_init,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
		.extra1		= SYSCTL_ONE,
		.extra2		= SYSCTL_INT_MAX,
	},
	{
		.procname	= "pf_retrans",
		.data		= &init_net.sctp.pf_retrans,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &init_net.sctp.ps_retrans,
	},
	{
		.procname	= "ps_retrans",
		.data		= &init_net.sctp.ps_retrans,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
		.extra1		= &init_net.sctp.pf_retrans,
		.extra2		= &ps_retrans_max,
	},
	{
		.procname	= "sndbuf_policy",
		.data		= &init_net.sctp.sndbuf_policy,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
	},
	{
		.procname	= "rcvbuf_policy",
		.data		= &init_net.sctp.rcvbuf_policy,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
	},
	{
		.procname	= "default_auto_asconf",
		.data		= &init_net.sctp.default_auto_asconf,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
	},
	{
		.procname	= "addip_enable",
		.data		= &init_net.sctp.addip_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
	},
	{
		.procname	= "addip_noauth_enable",
		.data		= &init_net.sctp.addip_noauth,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
	},
	{
		.procname	= "prsctp_enable",
		.data		= &init_net.sctp.prsctp_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
	},
	{
		.procname	= "reconf_enable",
		.data		= &init_net.sctp.reconf_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
	},
	{
		.procname	= "auth_enable",
		.data		= &init_net.sctp.auth_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &proc_sctp_do_auth_fops,
	},
	{
		.procname	= "intl_enable",
		.data		= &init_net.sctp.intl_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
	},
	{
		.procname	= "ecn_enable",
		.data		= &init_net.sctp.ecn_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
	},
	{
		.procname	= "plpmtud_probe_interval",
		.data		= &init_net.sctp.probe_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &proc_sctp_do_probe_interval_fops,
	},
	{
		.procname	= "udp_port",
		.data		= &init_net.sctp.udp_port,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &proc_sctp_do_udp_port_fops,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &udp_port_max,
	},
	{
		.procname	= "encap_port",
		.data		= &init_net.sctp.encap_port,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &udp_port_max,
	},
	{
		.procname	= "addr_scope_policy",
		.data		= &init_net.sctp.scope_policy,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &addr_scope_max,
	},
	{
		.procname	= "rwnd_update_shift",
		.data		= &init_net.sctp.rwnd_upd_shift,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
		.extra1		= SYSCTL_ONE,
		.extra2		= &rwnd_scale_max,
	},
	{
		.procname	= "max_autoclose",
		.data		= &init_net.sctp.max_autoclose,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= &sysctl_ulongvec_fops,
		.extra1		= &max_autoclose_min,
		.extra2		= &max_autoclose_max,
	},
	{
		.procname	= "pf_enable",
		.data		= &init_net.sctp.pf_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
	},
	{
		.procname	= "pf_expose",
		.data		= &init_net.sctp.pf_expose,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.ctl_fops	= &sysctl_intvec_fops,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &pf_expose_max,
	},

	{ /* sentinel */ }
};

static int proc_sctp_do_hmac_alg(struct ctl_table *ctl, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	struct ctl_table tbl;
	bool changed = false;
	char *none = "none";
	char tmp[8] = {0};
	int ret;

	memset(&tbl, 0, sizeof(struct ctl_table));

	if (write) {
		tbl.data = tmp;
		tbl.maxlen = sizeof(tmp);
	} else {
		tbl.data = net->sctp.sctp_hmac_alg ? : none;
		tbl.maxlen = strlen(tbl.data);
	}

	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0) {
#ifdef CONFIG_CRYPTO_MD5
		if (!strncmp(tmp, "md5", 3)) {
			net->sctp.sctp_hmac_alg = "md5";
			changed = true;
		}
#endif
#ifdef CONFIG_CRYPTO_SHA1
		if (!strncmp(tmp, "sha1", 4)) {
			net->sctp.sctp_hmac_alg = "sha1";
			changed = true;
		}
#endif
		if (!strncmp(tmp, "none", 4)) {
			net->sctp.sctp_hmac_alg = NULL;
			changed = true;
		}
		if (!changed)
			ret = -EINVAL;
	}

	return ret;
}

static ssize_t proc_sctp_do_rto_min_write(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;

	return sysctl_write_intvec_data(&net->sctp.rto_min, ctx->ctl_table, buffer, lenp, ppos,
			sysctl_conv_intvec,
			ctx->ctl_table->extra1,
			ctx->ctl_table->extra2);
}

static ssize_t proc_sctp_do_rto_min_read(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;

	return sysctl_read_intvec_data(&net->sctp.rto_min, ctx->ctl_table, buffer, lenp, ppos,
			sysctl_conv_intvec,
			ctx->ctl_table->extra1,
			ctx->ctl_table->extra2);
}

static ssize_t proc_sctp_do_rto_max_write(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;

	return sysctl_write_intvec_data(&net->sctp.rto_max, ctx->ctl_table, buffer, lenp, ppos,
			sysctl_conv_intvec,
			ctx->ctl_table->extra1,
			ctx->ctl_table->extra2);
}

static ssize_t proc_sctp_do_rto_max_read(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;

	return sysctl_read_intvec_data(&net->sctp.rto_max, ctx->ctl_table, buffer, lenp, ppos,
			sysctl_conv_intvec,
			ctx->ctl_table->extra1,
			ctx->ctl_table->extra2);
}

static ssize_t proc_sctp_do_alpha_beta_write(struct ctl_context *ctx, struct file *file,
		char *buffer, size_t *lenp, loff_t *ppos)
{
	pr_warn_once("Changing rto_alpha or rto_beta may lead to "
		     "suboptimal rtt/srtt estimations!\n");

	return sysctl_write_intvec(ctx, file, buffer, lenp, ppos);
}

static ssize_t proc_sctp_do_auth_write(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	int new_value;
	ssize_t ret;

	ret = sysctl_write_intvec_data(&new_value, ctx->ctl_table, buffer, lenp, ppos,
			sysctl_conv_intvec,
			ctx->ctl_table->extra1,
			ctx->ctl_table->extra2);

	if (ret == 0) {
		struct sock *sk = net->sctp.ctl_sock;

		net->sctp.auth_enable = new_value;
		/* Update the value in the control socket */
		lock_sock(sk);
		sctp_sk(sk)->ep->auth_enable = new_value;
		release_sock(sk);
	}

	return ret;
}

static ssize_t proc_sctp_do_auth_read(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;

	return sysctl_read_intvec_data(&net->sctp.auth_enable, ctx->ctl_table,
			buffer, lenp, ppos, sysctl_conv_intvec, NULL, NULL);
}

static ssize_t proc_sctp_do_udp_port_write(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	int new_value;
	ssize_t ret;

	ret = sysctl_write_intvec_data(&new_value, ctx->ctl_table, buffer, lenp, ppos,
			sysctl_conv_intvec,
			ctx->ctl_table->extra1,
			ctx->ctl_table->extra2);
	if (ret == 0) {
		struct sock *sk = net->sctp.ctl_sock;

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
	}

	return ret;
}

static ssize_t proc_sctp_do_udp_port_read(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;

	return sysctl_read_intvec_data(&net->sctp.udp_port, ctx->ctl_table,
			buffer, lenp, ppos, sysctl_conv_intvec, NULL, NULL);
}

static ssize_t proc_sctp_do_probe_interval_write(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	int new_value;
	ssize_t ret;

	ret = sysctl_write_intvec_data(&new_value, ctx->ctl_table, buffer, lenp, ppos,
			sysctl_conv_intvec,
			ctx->ctl_table->extra1,
			ctx->ctl_table->extra2);
	if (ret == 0) {
		if (new_value && new_value < SCTP_PROBE_TIMER_MIN)
			return -EINVAL;

		net->sctp.probe_interval = new_value;
	}

	return ret;
}

static ssize_t proc_sctp_do_probe_interval_read(struct ctl_context *ctx,
		struct file *file, char *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;

	return sysctl_read_intvec_data(&net->sctp.probe_interval, ctx->ctl_table,
			buffer, lenp, ppos, sysctl_conv_intvec, NULL, NULL);
}

int sctp_sysctl_net_register(struct net *net)
{
	struct ctl_table *table;
	int i;

	table = kmemdup(sctp_net_table, sizeof(sctp_net_table), GFP_KERNEL);
	if (!table)
		return -ENOMEM;

	for (i = 0; table[i].data; i++)
		table[i].data += (char *)(&net->sctp) - (char *)&init_net.sctp;

	net->sctp.sysctl_header = register_net_sysctl(net, "net/sctp", table);
	if (net->sctp.sysctl_header == NULL) {
		kfree(table);
		return -ENOMEM;
	}
	return 0;
}

void sctp_sysctl_net_unregister(struct net *net)
{
	struct ctl_table *table;

	table = net->sctp.sysctl_header->ctl_table_arg;
	unregister_net_sysctl_table(net->sctp.sysctl_header);
	kfree(table);
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

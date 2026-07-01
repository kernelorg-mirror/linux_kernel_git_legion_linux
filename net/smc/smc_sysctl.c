// SPDX-License-Identifier: GPL-2.0
/*
 *  Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  smc_sysctl.c: sysctl interface to SMC subsystem.
 *
 *  Copyright (c) 2022, Alibaba Inc.
 *
 *  Author: Tony Lu <tonylu@linux.alibaba.com>
 *
 */

#include <linux/init.h>
#include <linux/sysctl.h>
#include <linux/bpf.h>
#include <net/net_namespace.h>

#include "smc.h"
#include "smc_core.h"
#include "smc_llc.h"
#include "smc_sysctl.h"
#include "smc_hs_bpf.h"

static int min_sndbuf = SMC_BUF_MIN_SIZE;
static int min_rcvbuf = SMC_BUF_MIN_SIZE;
static int max_sndbuf = INT_MAX / 2;
static int max_rcvbuf = INT_MAX / 2;
static const int net_smc_wmem_init = (64 * 1024);
static const int net_smc_rmem_init = (64 * 1024);
static int links_per_lgr_min = SMC_LINKS_ADD_LNK_MIN;
static int links_per_lgr_max = SMC_LINKS_ADD_LNK_MAX;
static int conns_per_lgr_min = SMC_CONN_PER_LGR_MIN;
static int conns_per_lgr_max = SMC_CONN_PER_LGR_MAX;
static unsigned int smcr_max_wr_min = 2;
static unsigned int smcr_max_wr_max = 2048;

#if IS_ENABLED(CONFIG_SMC_HS_CTRL_BPF)
static int smc_net_replace_smc_hs_ctrl(struct net *net, const char *name)
{
	struct smc_hs_ctrl *ctrl = NULL;

	rcu_read_lock();
	/* null or empty name ask to clear current ctrl */
	if (name && name[0]) {
		ctrl = smc_hs_ctrl_find_by_name(name);
		if (!ctrl) {
			rcu_read_unlock();
			return -EINVAL;
		}
		/* no change, just return */
		if (ctrl == rcu_dereference(net->smc.hs_ctrl)) {
			rcu_read_unlock();
			return 0;
		}
		if (!bpf_try_module_get(ctrl, ctrl->owner)) {
			rcu_read_unlock();
			return -EBUSY;
		}
	}
	/* xhcg old ctrl with the new one atomically */
	ctrl = unrcu_pointer(xchg(&net->smc.hs_ctrl, RCU_INITIALIZER(ctrl)));
	/* release old ctrl */
	if (ctrl)
		bpf_module_put(ctrl, ctrl->owner);

	rcu_read_unlock();
	return 0;
}

static int proc_smc_hs_ctrl(const struct ctl_table *ctl, int write,
			    void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = container_of(ctl->data, struct net, smc.hs_ctrl);
	char val[SMC_HS_CTRL_NAME_MAX];
	const struct ctl_table tbl = {
		.data = val,
		.maxlen = SMC_HS_CTRL_NAME_MAX,
	};
	struct smc_hs_ctrl *ctrl;
	int ret;

	rcu_read_lock();
	ctrl = rcu_dereference(net->smc.hs_ctrl);
	if (ctrl)
		memcpy(val, ctrl->name, sizeof(ctrl->name));
	else
		val[0] = '\0';
	rcu_read_unlock();

	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	if (ret)
		return ret;

	if (write)
		ret = smc_net_replace_smc_hs_ctrl(net, val);
	return ret;
}
#endif /* CONFIG_SMC_HS_CTRL_BPF */

#define SMC_SYSCTL_DATA(type, name)					\
static type *smc_##name##_data(const struct ctl_context *ctx)		\
{									\
	return &ctx->ns.net_ns->smc.sysctl_##name;			\
}

#define SMC_SYSCTL_CUSTOM_DATA(name)					\
static void *smc_##name##_data(const struct ctl_context *ctx)		\
{									\
	return &ctx->ns.net_ns->smc.sysctl_##name;			\
}

SMC_SYSCTL_DATA(unsigned int, autocorking_size)
SMC_SYSCTL_DATA(unsigned int, smcr_buf_type)
SMC_SYSCTL_CUSTOM_DATA(smcr_testlink_time)
SMC_SYSCTL_DATA(int, wmem)
SMC_SYSCTL_DATA(int, rmem)
SMC_SYSCTL_DATA(int, max_links_per_lgr)
SMC_SYSCTL_DATA(int, max_conns_per_lgr)
SMC_SYSCTL_DATA(unsigned int, smcr_max_send_wr)
SMC_SYSCTL_DATA(unsigned int, smcr_max_recv_wr)

static void *smc_limit_smc_hs_data(const struct ctl_context *ctx)
{
	return &ctx->ns.net_ns->smc.limit_smc_hs;
}

static int proc_smc_limit_smc_hs(const struct ctl_table *ctl, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	bool *limit_smc_hs = ctl->data;
	struct ctl_table tmp = *ctl;
	int val = READ_ONCE(*limit_smc_hs);
	int ret;

	tmp.data = &val;
	tmp.maxlen = sizeof(val);
	tmp.extra1 = SYSCTL_ZERO;
	tmp.extra2 = SYSCTL_ONE;

	ret = proc_dointvec_minmax(&tmp, write, buffer, lenp, ppos);
	if (write && !ret)
		WRITE_ONCE(*limit_smc_hs, val);

	return ret;
}

#if IS_ENABLED(CONFIG_SMC_HS_CTRL_BPF)
static void *smc_hs_ctrl_data(const struct ctl_context *ctx)
{
	return &ctx->ns.net_ns->smc.hs_ctrl;
}
#endif

static const struct ctl_field smc_table[] = {
	CTL_FIELD_UINT("autocorking_size", 0644, smc_autocorking_size_data),
	CTL_FIELD_STATIC_UINT_MINMAX("smcr_buf_type", 0644,
				     smc_smcr_buf_type_data,
				     SYSCTL_UINT_ZERO, SYSCTL_UINT_TWO),
	CTL_FIELD_CUSTOM("smcr_testlink_time", 0644, sizeof(int),
			 smc_smcr_testlink_time_data, proc_dointvec_jiffies),
	CTL_FIELD_STATIC_INT_MINMAX("wmem", 0644, smc_wmem_data,
				    &min_sndbuf, &max_sndbuf),
	CTL_FIELD_STATIC_INT_MINMAX("rmem", 0644, smc_rmem_data,
				    &min_rcvbuf, &max_rcvbuf),
	CTL_FIELD_STATIC_INT_MINMAX("smcr_max_links_per_lgr", 0644,
				    smc_max_links_per_lgr_data,
				    &links_per_lgr_min, &links_per_lgr_max),
	CTL_FIELD_STATIC_INT_MINMAX("smcr_max_conns_per_lgr", 0644,
				    smc_max_conns_per_lgr_data,
				    &conns_per_lgr_min, &conns_per_lgr_max),
	CTL_FIELD_CUSTOM("limit_smc_hs", 0644, sizeof(bool),
			 smc_limit_smc_hs_data, proc_smc_limit_smc_hs),
	CTL_FIELD_STATIC_UINT_MINMAX("smcr_max_send_wr", 0644,
				     smc_smcr_max_send_wr_data,
				     &smcr_max_wr_min, &smcr_max_wr_max),
	CTL_FIELD_STATIC_UINT_MINMAX("smcr_max_recv_wr", 0644,
				     smc_smcr_max_recv_wr_data,
				     &smcr_max_wr_min, &smcr_max_wr_max),
#if IS_ENABLED(CONFIG_SMC_HS_CTRL_BPF)
	CTL_FIELD_CUSTOM("hs_ctrl", 0644, SMC_HS_CTRL_NAME_MAX,
			 smc_hs_ctrl_data, proc_smc_hs_ctrl),
#endif
};

int __net_init smc_sysctl_net_init(struct net *net)
{
	if (!net_eq(net, &init_net)) {
#if IS_ENABLED(CONFIG_SMC_HS_CTRL_BPF)
		struct smc_hs_ctrl *ctrl;

		rcu_read_lock();
		ctrl = rcu_dereference(init_net.smc.hs_ctrl);
		if (ctrl && ctrl->flags & SMC_HS_CTRL_FLAG_INHERITABLE &&
		    bpf_try_module_get(ctrl, ctrl->owner))
			rcu_assign_pointer(net->smc.hs_ctrl, ctrl);
		rcu_read_unlock();
#endif /* CONFIG_SMC_HS_CTRL_BPF */
	}

	net->smc.smc_hdr = register_net_sysctl_fields_sz(net, "net/smc",
							 smc_table,
							 ARRAY_SIZE(smc_table));
	if (!net->smc.smc_hdr)
		goto err_alloc;

	net->smc.sysctl_autocorking_size = SMC_AUTOCORKING_DEFAULT_SIZE;
	net->smc.sysctl_smcr_buf_type = SMCR_PHYS_CONT_BUFS;
	net->smc.sysctl_smcr_testlink_time = SMC_LLC_TESTLINK_DEFAULT_TIME;
	WRITE_ONCE(net->smc.sysctl_wmem, net_smc_wmem_init);
	WRITE_ONCE(net->smc.sysctl_rmem, net_smc_rmem_init);
	net->smc.sysctl_max_links_per_lgr = SMC_LINKS_PER_LGR_MAX_PREFER;
	net->smc.sysctl_max_conns_per_lgr = SMC_CONN_PER_LGR_PREFER;
	net->smc.sysctl_smcr_max_send_wr = SMCR_MAX_SEND_WR_DEF;
	net->smc.sysctl_smcr_max_recv_wr = SMCR_MAX_RECV_WR_DEF;
	/* disable handshake limitation by default */
	net->smc.limit_smc_hs = false;

	return 0;

err_alloc:
#if IS_ENABLED(CONFIG_SMC_HS_CTRL_BPF)
	smc_net_replace_smc_hs_ctrl(net, NULL);
#endif /* CONFIG_SMC_HS_CTRL_BPF */
	return -ENOMEM;
}

void __net_exit smc_sysctl_net_exit(struct net *net)
{
	unregister_net_sysctl_table(net->smc.smc_hdr);
#if IS_ENABLED(CONFIG_SMC_HS_CTRL_BPF)
	smc_net_replace_smc_hs_ctrl(net, NULL);
#endif /* CONFIG_SMC_HS_CTRL_BPF */
}

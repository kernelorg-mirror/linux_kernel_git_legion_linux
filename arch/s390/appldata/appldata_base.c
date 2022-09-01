// SPDX-License-Identifier: GPL-2.0
/*
 * Base infrastructure for Linux-z/VM Monitor Stream, Stage 1.
 * Exports appldata_register_ops() and appldata_unregister_ops() for the
 * data gathering modules.
 *
 * Copyright IBM Corp. 2003, 2009
 *
 * Author: Gerald Schaefer <gerald.schaefer@de.ibm.com>
 */

#define KMSG_COMPONENT	"appldata"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/module.h>
#include <linux/sched/stat.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/sysctl.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/workqueue.h>
#include <linux/suspend.h>
#include <linux/platform_device.h>
#include <asm/appldata.h>
#include <asm/vtimer.h>
#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/smp.h>

#include "appldata.h"


#define APPLDATA_CPU_INTERVAL	10000		/* default (CPU) time for
						   sampling interval in
						   milliseconds */

#define TOD_MICRO	0x01000			/* nr. of TOD clock units
						   for 1 microsecond */

static struct platform_device *appldata_pdev;

/*
 * /proc entries (sysctl)
 */
static const char appldata_proc_name[APPLDATA_PROC_NAME_LENGTH] = "appldata";

/*
 * Timer
 */
static struct vtimer_list appldata_timer;

static DEFINE_SPINLOCK(appldata_timer_lock);
static int appldata_interval = APPLDATA_CPU_INTERVAL;
static int appldata_timer_active;
static int appldata_timer_suspended = 0;

/*
 * Work queue
 */
static struct workqueue_struct *appldata_wq;
static void appldata_work_fn(struct work_struct *work);
static DECLARE_WORK(appldata_work, appldata_work_fn);


/*
 * Ops list
 */
static DEFINE_MUTEX(appldata_ops_mutex);
static LIST_HEAD(appldata_ops_list);


/*************************** timer, work, DIAG *******************************/
/*
 * appldata_timer_function()
 *
 * schedule work and reschedule timer
 */
static void appldata_timer_function(unsigned long data)
{
	queue_work(appldata_wq, (struct work_struct *) data);
}

/*
 * appldata_work_fn()
 *
 * call data gathering function for each (active) module
 */
static void appldata_work_fn(struct work_struct *work)
{
	struct list_head *lh;
	struct appldata_ops *ops;

	mutex_lock(&appldata_ops_mutex);
	list_for_each(lh, &appldata_ops_list) {
		ops = list_entry(lh, struct appldata_ops, list);
		if (ops->active == 1) {
			ops->callback(ops->data);
		}
	}
	mutex_unlock(&appldata_ops_mutex);
}

static struct appldata_product_id appldata_id = {
	.prod_nr    = {0xD3, 0xC9, 0xD5, 0xE4,
		       0xE7, 0xD2, 0xD9},	/* "LINUXKR" */
	.prod_fn    = 0xD5D3,			/* "NL" */
	.version_nr = 0xF2F6,			/* "26" */
	.release_nr = 0xF0F1,			/* "01" */
};

/*
 * appldata_diag()
 *
 * prepare parameter list, issue DIAG 0xDC
 */
int appldata_diag(char record_nr, u16 function, unsigned long buffer,
			u16 length, char *mod_lvl)
{
	struct appldata_parameter_list *parm_list;
	struct appldata_product_id *id;
	int rc;

	parm_list = kmalloc(sizeof(*parm_list), GFP_KERNEL);
	id = kmemdup(&appldata_id, sizeof(appldata_id), GFP_KERNEL);
	rc = -ENOMEM;
	if (parm_list && id) {
		id->record_nr = record_nr;
		id->mod_lvl = (mod_lvl[0]) << 8 | mod_lvl[1];
		rc = appldata_asm(parm_list, id, function,
				  (void *) buffer, length);
	}
	kfree(id);
	kfree(parm_list);
	return rc;
}
/************************ timer, work, DIAG <END> ****************************/


/****************************** /proc stuff **********************************/

#define APPLDATA_ADD_TIMER	0
#define APPLDATA_DEL_TIMER	1
#define APPLDATA_MOD_TIMER	2

/*
 * __appldata_vtimer_setup()
 *
 * Add, delete or modify virtual timers on all online cpus.
 * The caller needs to get the appldata_timer_lock spinlock.
 */
static void __appldata_vtimer_setup(int cmd)
{
	u64 timer_interval = (u64) appldata_interval * 1000 * TOD_MICRO;

	switch (cmd) {
	case APPLDATA_ADD_TIMER:
		if (appldata_timer_active)
			break;
		appldata_timer.expires = timer_interval;
		add_virt_timer_periodic(&appldata_timer);
		appldata_timer_active = 1;
		break;
	case APPLDATA_DEL_TIMER:
		del_virt_timer(&appldata_timer);
		if (!appldata_timer_active)
			break;
		appldata_timer_active = 0;
		break;
	case APPLDATA_MOD_TIMER:
		if (!appldata_timer_active)
			break;
		mod_virt_timer_periodic(&appldata_timer, timer_interval);
	}
}

/*
 * appldata_timer_write()
 *
 * Start/Stop timer, show status of timer (0 = not active, 1 = active)
 */
static ssize_t
appldata_timer_write(struct ctl_context *ctx, struct file *file,
		char *buffer, size_t *lenp, loff_t *ppos)
{
	int timer_active = appldata_timer_active;
	ssize_t rc;

	rc = do_proc_dointvec_w(&timer_active, ctx->ctl_table,
			buffer, lenp, ppos,
			do_proc_dointvec_minmax_conv,
			SYSCTL_ZERO,
			SYSCTL_ONE);
	if (rc < 0)
		return rc;

	spin_lock(&appldata_timer_lock);
	if (timer_active)
		__appldata_vtimer_setup(APPLDATA_ADD_TIMER);
	else
		__appldata_vtimer_setup(APPLDATA_DEL_TIMER);
	spin_unlock(&appldata_timer_lock);
	return 0;
}

static ssize_t
appldata_timer_read(struct ctl_context *ctx, struct file *file,
		char *buffer, size_t *lenp, loff_t *ppos)
{
	int timer_active = appldata_timer_active;

	return do_proc_dointvec_r(&timer_active, ctx->ctl_table,
			buffer, lenp, ppos,
			do_proc_dointvec_minmax_conv, NULL, NULL);
}


/*
 * appldata_interval_write()
 *
 * Set (CPU) timer interval for collection of data (in milliseconds), show
 * current timer interval.
 */
static ssize_t
appldata_interval_write(struct ctl_context *ctx, struct file *file,
		char *buffer, size_t *lenp, loff_t *ppos)
{
	int interval = appldata_interval;
	ssize_t rc;

	rc = do_proc_dointvec_w(&interval, ctx->ctl_table,
			buffer, lenp, ppos,
			do_proc_dointvec_minmax_conv,
			SYSCTL_ONE,
			NULL);

	if (rc < 0)
		return rc;

	spin_lock(&appldata_timer_lock);
	appldata_interval = interval;
	__appldata_vtimer_setup(APPLDATA_MOD_TIMER);
	spin_unlock(&appldata_timer_lock);
	return 0;
}

static ssize_t
appldata_interval_read(struct ctl_context *ctx, struct file *file,
		char *buffer, size_t *lenp, loff_t *ppos)
{
	int interval = appldata_interval;

	return do_proc_dointvec_r(&interval, ctx->ctl_table,
			buffer, lenp, ppos,
			do_proc_dointvec_minmax_conv, NULL, NULL);
}

static struct ctl_fops appldata_timer_fops = {
	.read  = appldata_timer_read,
	.write = appldata_timer_write,
};

static struct ctl_fops appldata_interval_fops = {
	.read  = appldata_interval_read,
	.write = appldata_interval_write,
};

static struct ctl_table_header *appldata_sysctl_header;
static struct ctl_table appldata_table[] = {
	{
		.procname	= "timer",
		.mode		= S_IRUGO | S_IWUSR,
		.ctl_fops	= &appldata_timer_fops,
	},
	{
		.procname	= "interval",
		.mode		= S_IRUGO | S_IWUSR,
		.ctl_fops	= &appldata_interval_fops,
	},
	{ },
};

static struct ctl_table appldata_dir_table[] = {
	{
		.procname	= appldata_proc_name,
		.maxlen		= 0,
		.mode		= S_IRUGO | S_IXUGO,
		.child		= appldata_table,
	},
	{ },
};

/*
 * appldata_generic_read()
 *
 * Generic start/stop monitoring and DIAG, show status of
 * monitoring (0 = not in process, 1 = in process)
 */
static ssize_t
appldata_generic_read(struct ctl_context *ctx, struct file *file,
		      char *buffer, size_t *lenp, loff_t *ppos)
{
	struct appldata_ops *ops = NULL, *tmp_ops;
	struct list_head *lh;
	ssize_t rc;
	int found, active;

	found = 0;
	mutex_lock(&appldata_ops_mutex);
	list_for_each(lh, &appldata_ops_list) {
		tmp_ops = list_entry(lh, struct appldata_ops, list);
		if (&tmp_ops->ctl_table[2] == ctx->ctl_table) {
			found = 1;
		}
	}
	if (!found) {
		mutex_unlock(&appldata_ops_mutex);
		return -ENODEV;
	}
	ops = ctx->ctl_table->data;
	if (!try_module_get(ops->owner)) {	// protect this function
		mutex_unlock(&appldata_ops_mutex);
		return -ENODEV;
	}
	mutex_unlock(&appldata_ops_mutex);

	active = ops->active;

	rc = do_proc_dointvec_r(&active, ctx->ctl_table,
			buffer, lenp, ppos,
			do_proc_dointvec_minmax_conv, NULL, NULL);

	module_put(ops->owner);
	return rc;
}

/*
 * appldata_generic_write()
 *
 * Generic start/stop monitoring and DIAG, show status of
 * monitoring (0 = not in process, 1 = in process)
 */
static ssize_t
appldata_generic_write(struct ctl_context *ctx, struct file *file,
		       char *buffer, size_t *lenp, loff_t *ppos)
{
	struct appldata_ops *ops = NULL, *tmp_ops;
	struct list_head *lh;
	ssize_t rc;
	int active, found;

	found = 0;
	mutex_lock(&appldata_ops_mutex);
	list_for_each(lh, &appldata_ops_list) {
		tmp_ops = list_entry(lh, struct appldata_ops, list);
		if (&tmp_ops->ctl_table[2] == ctx->ctl_table) {
			found = 1;
		}
	}
	if (!found) {
		mutex_unlock(&appldata_ops_mutex);
		return -ENODEV;
	}
	ops = ctx->ctl_table->data;
	if (!try_module_get(ops->owner)) {	// protect this function
		mutex_unlock(&appldata_ops_mutex);
		return -ENODEV;
	}
	mutex_unlock(&appldata_ops_mutex);

	active = ops->active;

	rc = do_proc_dointvec_w(&active, ctx->ctl_table,
			buffer, lenp, ppos,
			do_proc_dointvec_minmax_conv, SYSCTL_ZERO, SYSCTL_ONE);

	if (rc < 0) {
		module_put(ops->owner);
		return rc;
	}

	mutex_lock(&appldata_ops_mutex);
	if (active && (ops->active == 0)) {
		// protect work queue callback
		if (!try_module_get(ops->owner)) {
			mutex_unlock(&appldata_ops_mutex);
			module_put(ops->owner);
			return -ENODEV;
		}
		ops->callback(ops->data);	// init record
		rc = appldata_diag(ops->record_nr,
					APPLDATA_START_INTERVAL_REC,
					(unsigned long) ops->data, ops->size,
					ops->mod_lvl);
		if (rc != 0) {
			pr_err("Starting the data collection for %s "
			       "failed with rc=%d\n", ops->name, rc);
			module_put(ops->owner);
		} else
			ops->active = 1;
	} else if (!active && (ops->active == 1)) {
		ops->active = 0;
		rc = appldata_diag(ops->record_nr, APPLDATA_STOP_REC,
				(unsigned long) ops->data, ops->size,
				ops->mod_lvl);
		if (rc != 0)
			pr_err("Stopping the data collection for %s "
			       "failed with rc=%d\n", ops->name, rc);
		module_put(ops->owner);
	}
	mutex_unlock(&appldata_ops_mutex);
	module_put(ops->owner);
	return 0;
}

static struct ctl_fops appldata_generic_fops = {
	.read  = appldata_generic_read,
	.write = appldata_generic_write,
};

/*************************** /proc stuff <END> *******************************/


/************************* module-ops management *****************************/
/*
 * appldata_register_ops()
 *
 * update ops list, register /proc/sys entries
 */
int appldata_register_ops(struct appldata_ops *ops)
{
	if (ops->size > APPLDATA_MAX_REC_SIZE)
		return -EINVAL;

	ops->ctl_table = kcalloc(4, sizeof(struct ctl_table), GFP_KERNEL);
	if (!ops->ctl_table)
		return -ENOMEM;

	mutex_lock(&appldata_ops_mutex);
	list_add(&ops->list, &appldata_ops_list);
	mutex_unlock(&appldata_ops_mutex);

	ops->ctl_table[0].procname = appldata_proc_name;
	ops->ctl_table[0].maxlen   = 0;
	ops->ctl_table[0].mode     = S_IRUGO | S_IXUGO;
	ops->ctl_table[0].child    = &ops->ctl_table[2];

	ops->ctl_table[2].procname = ops->name;
	ops->ctl_table[2].mode     = S_IRUGO | S_IWUSR;
	ops->ctl_table[2].ctl_fops = &appldata_generic_fops;
	ops->ctl_table[2].data = ops;

	ops->sysctl_header = register_sysctl_table(ops->ctl_table);
	if (!ops->sysctl_header)
		goto out;
	return 0;
out:
	mutex_lock(&appldata_ops_mutex);
	list_del(&ops->list);
	mutex_unlock(&appldata_ops_mutex);
	kfree(ops->ctl_table);
	return -ENOMEM;
}

/*
 * appldata_unregister_ops()
 *
 * update ops list, unregister /proc entries, stop DIAG if necessary
 */
void appldata_unregister_ops(struct appldata_ops *ops)
{
	mutex_lock(&appldata_ops_mutex);
	list_del(&ops->list);
	mutex_unlock(&appldata_ops_mutex);
	unregister_sysctl_table(ops->sysctl_header);
	kfree(ops->ctl_table);
}
/********************** module-ops management <END> **************************/


/**************************** suspend / resume *******************************/
static int appldata_freeze(struct device *dev)
{
	struct appldata_ops *ops;
	int rc;
	struct list_head *lh;

	spin_lock(&appldata_timer_lock);
	if (appldata_timer_active) {
		__appldata_vtimer_setup(APPLDATA_DEL_TIMER);
		appldata_timer_suspended = 1;
	}
	spin_unlock(&appldata_timer_lock);

	mutex_lock(&appldata_ops_mutex);
	list_for_each(lh, &appldata_ops_list) {
		ops = list_entry(lh, struct appldata_ops, list);
		if (ops->active == 1) {
			rc = appldata_diag(ops->record_nr, APPLDATA_STOP_REC,
					(unsigned long) ops->data, ops->size,
					ops->mod_lvl);
			if (rc != 0)
				pr_err("Stopping the data collection for %s "
				       "failed with rc=%d\n", ops->name, rc);
		}
	}
	mutex_unlock(&appldata_ops_mutex);
	return 0;
}

static int appldata_restore(struct device *dev)
{
	struct appldata_ops *ops;
	int rc;
	struct list_head *lh;

	spin_lock(&appldata_timer_lock);
	if (appldata_timer_suspended) {
		__appldata_vtimer_setup(APPLDATA_ADD_TIMER);
		appldata_timer_suspended = 0;
	}
	spin_unlock(&appldata_timer_lock);

	mutex_lock(&appldata_ops_mutex);
	list_for_each(lh, &appldata_ops_list) {
		ops = list_entry(lh, struct appldata_ops, list);
		if (ops->active == 1) {
			ops->callback(ops->data);	// init record
			rc = appldata_diag(ops->record_nr,
					APPLDATA_START_INTERVAL_REC,
					(unsigned long) ops->data, ops->size,
					ops->mod_lvl);
			if (rc != 0) {
				pr_err("Starting the data collection for %s "
				       "failed with rc=%d\n", ops->name, rc);
			}
		}
	}
	mutex_unlock(&appldata_ops_mutex);
	return 0;
}

static int appldata_thaw(struct device *dev)
{
	return appldata_restore(dev);
}

static const struct dev_pm_ops appldata_pm_ops = {
	.freeze		= appldata_freeze,
	.thaw		= appldata_thaw,
	.restore	= appldata_restore,
};

static struct platform_driver appldata_pdrv = {
	.driver = {
		.name	= "appldata",
		.pm	= &appldata_pm_ops,
	},
};
/************************* suspend / resume <END> ****************************/


/******************************* init / exit *********************************/

/*
 * appldata_init()
 *
 * init timer, register /proc entries
 */
static int __init appldata_init(void)
{
	int rc;

	init_virt_timer(&appldata_timer);
	appldata_timer.function = appldata_timer_function;
	appldata_timer.data = (unsigned long) &appldata_work;

	rc = platform_driver_register(&appldata_pdrv);
	if (rc)
		return rc;

	appldata_pdev = platform_device_register_simple("appldata", -1, NULL,
							0);
	if (IS_ERR(appldata_pdev)) {
		rc = PTR_ERR(appldata_pdev);
		goto out_driver;
	}
	appldata_wq = alloc_ordered_workqueue("appldata", 0);
	if (!appldata_wq) {
		rc = -ENOMEM;
		goto out_device;
	}

	appldata_sysctl_header = register_sysctl_table(appldata_dir_table);
	return 0;

out_device:
	platform_device_unregister(appldata_pdev);
out_driver:
	platform_driver_unregister(&appldata_pdrv);
	return rc;
}

__initcall(appldata_init);

/**************************** init / exit <END> ******************************/

EXPORT_SYMBOL_GPL(appldata_register_ops);
EXPORT_SYMBOL_GPL(appldata_unregister_ops);
EXPORT_SYMBOL_GPL(appldata_diag);

#ifdef CONFIG_SWAP
EXPORT_SYMBOL_GPL(si_swapinfo);
#endif
EXPORT_SYMBOL_GPL(nr_threads);
EXPORT_SYMBOL_GPL(nr_running);
EXPORT_SYMBOL_GPL(nr_iowait);

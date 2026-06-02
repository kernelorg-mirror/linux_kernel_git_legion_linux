// SPDX-License-Identifier: GPL-2.0
/* Sysctl interface for parport devices.
 * 
 * Authors: David Campbell
 *          Tim Waugh <tim@cyberelk.demon.co.uk>
 *          Philip Blundell <philb@gnu.org>
 *          Andrea Arcangeli
 *          Riccardo Facchetti <fizban@tin.it>
 *
 * based on work by Grant Guenther <grant@torque.net>
 *              and Philip Blundell
 *
 * Cleaned up include files - Russell King <linux@arm.uk.linux.org>
 */

#include <linux/string.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/parport.h>
#include <linux/ctype.h>
#include <linux/sysctl.h>
#include <linux/device.h>

#include <linux/uaccess.h>

#if defined(CONFIG_SYSCTL) && defined(CONFIG_PROC_FS)

#define PARPORT_MIN_TIMESLICE_VALUE 1ul 
#define PARPORT_MAX_TIMESLICE_VALUE ((unsigned long) HZ)
#define PARPORT_MIN_SPINTIME_VALUE 1
#define PARPORT_MAX_SPINTIME_VALUE 1000

static int do_active_device(const struct ctl_table *table, int write,
		      void *result, size_t *lenp, loff_t *ppos)
{
	struct parport *port = (struct parport *)table->extra1;
	char buffer[256];
	struct pardevice *dev;
	int len = 0;

	if (write)		/* can't happen anyway */
		return -EACCES;

	if (*ppos) {
		*lenp = 0;
		return 0;
	}
	
	for (dev = port->devices; dev ; dev = dev->next) {
		if(dev == port->cad) {
			len += scnprintf(buffer, sizeof(buffer), "%s\n", dev->name);
		}
	}

	if(!len) {
		len += scnprintf(buffer, sizeof(buffer), "%s\n", "none");
	}

	if (len > *lenp)
		len = *lenp;
	else
		*lenp = len;

	*ppos += len;
	memcpy(result, buffer, len);
	return 0;
}

#ifdef CONFIG_PARPORT_1284
static int do_autoprobe(const struct ctl_table *table, int write,
			void *result, size_t *lenp, loff_t *ppos)
{
	struct parport_device_info *info = table->extra2;
	const char *str;
	char buffer[256];
	int len = 0;

	if (write) /* permissions stop this */
		return -EACCES;

	if (*ppos) {
		*lenp = 0;
		return 0;
	}
	
	if ((str = info->class_name) != NULL)
		len += scnprintf (buffer + len, sizeof(buffer) - len, "CLASS:%s;\n", str);

	if ((str = info->model) != NULL)
		len += scnprintf (buffer + len, sizeof(buffer) - len, "MODEL:%s;\n", str);

	if ((str = info->mfr) != NULL)
		len += scnprintf (buffer + len, sizeof(buffer) - len, "MANUFACTURER:%s;\n", str);

	if ((str = info->description) != NULL)
		len += scnprintf (buffer + len, sizeof(buffer) - len, "DESCRIPTION:%s;\n", str);

	if ((str = info->cmdset) != NULL)
		len += scnprintf (buffer + len, sizeof(buffer) - len, "COMMAND SET:%s;\n", str);

	if (len > *lenp)
		len = *lenp;
	else
		*lenp = len;

	*ppos += len;

	memcpy(result, buffer, len);
	return 0;
}
#endif /* IEEE1284.3 support. */

static int do_hardware_base_addr(const struct ctl_table *table, int write,
				 void *result, size_t *lenp, loff_t *ppos)
{
	struct parport *port = (struct parport *)table->extra1;
	char buffer[64];
	int len = 0;

	if (*ppos) {
		*lenp = 0;
		return 0;
	}

	if (write) /* permissions prevent this anyway */
		return -EACCES;

	len += scnprintf (buffer, sizeof(buffer), "%lu\t%lu\n", port->base, port->base_hi);

	if (len > *lenp)
		len = *lenp;
	else
		*lenp = len;

	*ppos += len;
	memcpy(result, buffer, len);
	return 0;
}

static int do_hardware_irq(const struct ctl_table *table, int write,
			   void *result, size_t *lenp, loff_t *ppos)
{
	struct parport *port = (struct parport *)table->extra1;
	char buffer[20];
	int len = 0;

	if (*ppos) {
		*lenp = 0;
		return 0;
	}

	if (write) /* permissions prevent this anyway */
		return -EACCES;

	len += scnprintf (buffer, sizeof(buffer), "%d\n", port->irq);

	if (len > *lenp)
		len = *lenp;
	else
		*lenp = len;

	*ppos += len;
	memcpy(result, buffer, len);
	return 0;
}

static int do_hardware_dma(const struct ctl_table *table, int write,
			   void *result, size_t *lenp, loff_t *ppos)
{
	struct parport *port = (struct parport *)table->extra1;
	char buffer[20];
	int len = 0;

	if (*ppos) {
		*lenp = 0;
		return 0;
	}

	if (write) /* permissions prevent this anyway */
		return -EACCES;

	len += scnprintf (buffer, sizeof(buffer), "%d\n", port->dma);

	if (len > *lenp)
		len = *lenp;
	else
		*lenp = len;

	*ppos += len;
	memcpy(result, buffer, len);
	return 0;
}

static int do_hardware_modes(const struct ctl_table *table, int write,
			     void *result, size_t *lenp, loff_t *ppos)
{
	struct parport *port = (struct parport *)table->extra1;
	char buffer[40];
	int len = 0;

	if (*ppos) {
		*lenp = 0;
		return 0;
	}

	if (write) /* permissions prevent this anyway */
		return -EACCES;

	{
#define printmode(x)							\
do {									\
	if (port->modes & PARPORT_MODE_##x)				\
		len += scnprintf(buffer + len, sizeof(buffer) - len, "%s%s", f++ ? "," : "", #x); \
} while (0)
		int f = 0;
		printmode(PCSPP);
		printmode(TRISTATE);
		printmode(COMPAT);
		printmode(EPP);
		printmode(ECP);
		printmode(DMA);
#undef printmode
	}
	buffer[len++] = '\n';

	if (len > *lenp)
		len = *lenp;
	else
		*lenp = len;

	*ppos += len;
	memcpy(result, buffer, len);
	return 0;
}

static const unsigned long parport_min_timeslice_value =
PARPORT_MIN_TIMESLICE_VALUE;

static const unsigned long parport_max_timeslice_value =
PARPORT_MAX_TIMESLICE_VALUE;

static const  int parport_min_spintime_value =
PARPORT_MIN_SPINTIME_VALUE;

static const int parport_max_spintime_value =
PARPORT_MAX_SPINTIME_VALUE;


static void *parport_extra1(const struct ctl_context *ctx)
{
	return ctx->target.parport;
}

static void *parport_active_data(const struct ctl_context *ctx)
{
	return NULL;
}

static void *parport_spintime_data(const struct ctl_context *ctx)
{
	return &ctx->target.parport->spintime;
}

#ifdef CONFIG_PARPORT_1284
#define PARPORT_PROBE_INFO(number)					\
static void *parport_probe_info ## number(const struct ctl_context *ctx)	\
{									\
	return &ctx->target.parport->probe_info[number];		\
}

PARPORT_PROBE_INFO(0)
PARPORT_PROBE_INFO(1)
PARPORT_PROBE_INFO(2)
PARPORT_PROBE_INFO(3)
PARPORT_PROBE_INFO(4)
#endif /* IEEE 1284 support */

static const struct ctl_field parport_device_dir[] = {
	{
		.table = {
			.procname	= "active",
			.maxlen		= 0,
			.mode		= 0444,
			.proc_handler	= do_active_device,
		},
		.data   = parport_active_data,
		.extra1 = parport_extra1,
	},
};

static const struct ctl_field parport_vars[] = {
	{
		.table = {
			.procname	= "spintime",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra2		= (void*) &parport_max_spintime_value
		},
		.data   = parport_spintime_data,
		.extra1 = parport_extra1,
	},
	{
		.table = {
			.procname	= "base-addr",
			.maxlen		= 0,
			.mode		= 0444,
			.proc_handler	= do_hardware_base_addr
		},
		.data   = parport_active_data,
		.extra1 = parport_extra1,
	},
	{
		.table = {
			.procname	= "irq",
			.maxlen		= 0,
			.mode		= 0444,
			.proc_handler	= do_hardware_irq
		},
		.data   = parport_active_data,
		.extra1 = parport_extra1,
	},
	{
		.table = {
			.procname	= "dma",
			.maxlen		= 0,
			.mode		= 0444,
			.proc_handler	= do_hardware_dma
		},
		.data   = parport_active_data,
		.extra1 = parport_extra1,
	},
	{
		.table = {
			.procname	= "modes",
			.maxlen		= 0,
			.mode		= 0444,
			.proc_handler	= do_hardware_modes
		},
		.data   = parport_active_data,
		.extra1 = parport_extra1,
	},
#ifdef CONFIG_PARPORT_1284
	{
		.table = {
			.procname	= "autoprobe",
			.maxlen		= 0,
			.mode		= 0444,
			.proc_handler	= do_autoprobe
		},
		.data   = parport_active_data,
		.extra2 = parport_probe_info0,
	},
	{
		.table = {
			.procname	= "autoprobe0",
			.maxlen		= 0,
			.mode		= 0444,
			.proc_handler	= do_autoprobe
		},
		.data   = parport_active_data,
		.extra2 = parport_probe_info1,
	},
	{
		.table = {
			.procname	= "autoprobe1",
			.maxlen		= 0,
			.mode		= 0444,
			.proc_handler	= do_autoprobe
		},
		.data   = parport_active_data,
		.extra2 = parport_probe_info2,
	},
	{
		.table = {
			.procname	= "autoprobe2",
			.maxlen		= 0,
			.mode		= 0444,
			.proc_handler	= do_autoprobe
		},
		.data   = parport_active_data,
		.extra2 = parport_probe_info3,
	},
	{
		.table = {
			.procname	= "autoprobe3",
			.maxlen		= 0,
			.mode		= 0444,
			.proc_handler	= do_autoprobe
		},
		.data   = parport_active_data,
		.extra2 = parport_probe_info4,
	},
#endif /* IEEE 1284 support */
};

static void *pardevice_timeslice_data(const struct ctl_context *ctx)
{
	return &ctx->target.pardevice->timeslice;
}

static const struct ctl_field parport_device_vars[] = {
	{
		.table = {
			.procname	= "timeslice",
			.maxlen		= sizeof(unsigned long),
			.mode		= 0644,
			.proc_handler	= proc_doulongvec_ms_jiffies_minmax,
			.extra1		= (void*) &parport_min_timeslice_value,
			.extra2		= (void*) &parport_max_timeslice_value
		},
		.data = pardevice_timeslice_data,
	},
};

struct parport_default_sysctl_table
{
	struct ctl_table_header *sysctl_header;
	struct ctl_table vars[2];
};

static struct parport_default_sysctl_table
parport_default_sysctl_table = {
	.sysctl_header	= NULL,
	{
		{
			.procname	= "timeslice",
			.data		= &parport_default_timeslice,
			.maxlen		= sizeof(parport_default_timeslice),
			.mode		= 0644,
			.proc_handler	= proc_doulongvec_ms_jiffies_minmax,
			.extra1		= (void*) &parport_min_timeslice_value,
			.extra2		= (void*) &parport_max_timeslice_value
		},
		{
			.procname	= "spintime",
			.data		= &parport_default_spintime,
			.maxlen		= sizeof(parport_default_spintime),
			.mode		= 0644,
			.proc_handler	= proc_dointvec_minmax,
			.extra1		= (void*) &parport_min_spintime_value,
			.extra2		= (void*) &parport_max_spintime_value
		},
	}
};

int parport_proc_register(struct parport *port)
{
	char *tmp_dir_path;
	struct ctl_context ctx = {
		.target.parport = port,
	};
	int err = 0;

	tmp_dir_path = kasprintf(GFP_KERNEL, "dev/parport/%s/devices", port->name);
	if (!tmp_dir_path)
		return -ENOMEM;

	port->devices_sysctl_header = register_sysctl_fields_ctx(tmp_dir_path, parport_device_dir,
								 ARRAY_SIZE(parport_device_dir), &ctx);
	if (!port->devices_sysctl_header) {
		err = -ENOENT;
		goto  exit_free_tmp_dir_path;
	}

	kfree(tmp_dir_path);

	tmp_dir_path = kasprintf(GFP_KERNEL, "dev/parport/%s", port->name);
	if (!tmp_dir_path) {
		err = -ENOMEM;
		goto unregister_devices_h;
	}

	port->port_sysctl_header = register_sysctl_fields_ctx(tmp_dir_path, parport_vars,
							      ARRAY_SIZE(parport_vars), &ctx);
	if (!port->port_sysctl_header) {
		err = -ENOENT;
		goto unregister_devices_h;
	}

	kfree(tmp_dir_path);
	return 0;

unregister_devices_h:
	unregister_sysctl_table(port->devices_sysctl_header);
	port->devices_sysctl_header = NULL;

exit_free_tmp_dir_path:
	kfree(tmp_dir_path);
	return err;
}

int parport_proc_unregister(struct parport *port)
{
	if (port->devices_sysctl_header) {
		unregister_sysctl_table(port->devices_sysctl_header);
		port->devices_sysctl_header = NULL;
	}
	if (port->port_sysctl_header) {
		unregister_sysctl_table(port->port_sysctl_header);
		port->port_sysctl_header = NULL;
	}
	return 0;
}

int parport_device_proc_register(struct pardevice *device)
{
	struct parport * port = device->port;
	char *tmp_dir_path;
	struct ctl_context ctx = {
		.target.pardevice = device,
	};

	/* Allocate a buffer for two paths: dev/parport/PORT/devices/DEVICE. */
	tmp_dir_path = kasprintf(GFP_KERNEL, "dev/parport/%s/devices/%s", port->name, device->name);
	if (!tmp_dir_path)
		return -ENOMEM;

	device->sysctl_header = register_sysctl_fields_ctx(tmp_dir_path, parport_device_vars,
							   ARRAY_SIZE(parport_device_vars),
							   &ctx);

	kfree(tmp_dir_path);
	return 0;
}

int parport_device_proc_unregister(struct pardevice *device)
{
	if (device->sysctl_header) {
		unregister_sysctl_table(device->sysctl_header);
		device->sysctl_header = NULL;
	}
	return 0;
}

static int __init parport_default_proc_register(void)
{
	int ret;

	parport_default_sysctl_table.sysctl_header =
		register_sysctl("dev/parport/default", parport_default_sysctl_table.vars);
	if (!parport_default_sysctl_table.sysctl_header)
		return -ENOMEM;
	ret = parport_bus_init();
	if (ret) {
		unregister_sysctl_table(parport_default_sysctl_table.
					sysctl_header);
		return ret;
	}
	return 0;
}

static void __exit parport_default_proc_unregister(void)
{
	if (parport_default_sysctl_table.sysctl_header) {
		unregister_sysctl_table(parport_default_sysctl_table.
					sysctl_header);
		parport_default_sysctl_table.sysctl_header = NULL;
	}
	parport_bus_exit();
}

#else /* no sysctl or no procfs*/

int parport_proc_register(struct parport *pp)
{
	return 0;
}

int parport_proc_unregister(struct parport *pp)
{
	return 0;
}

int parport_device_proc_register(struct pardevice *device)
{
	return 0;
}

int parport_device_proc_unregister(struct pardevice *device)
{
	return 0;
}

static int __init parport_default_proc_register (void)
{
	return parport_bus_init();
}

static void __exit parport_default_proc_unregister (void)
{
	parport_bus_exit();
}
#endif

subsys_initcall(parport_default_proc_register)
module_exit(parport_default_proc_unregister)

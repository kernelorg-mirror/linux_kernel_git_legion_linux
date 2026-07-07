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

static unsigned long parport_min_timeslice_value =
PARPORT_MIN_TIMESLICE_VALUE;

static unsigned long parport_max_timeslice_value =
PARPORT_MAX_TIMESLICE_VALUE;

static int parport_min_spintime_value =
PARPORT_MIN_SPINTIME_VALUE;

static int parport_max_spintime_value =
PARPORT_MAX_SPINTIME_VALUE;

static int *parport_spintime_data(const struct ctl_context *ctx)
{
	return &ctx->target.parport->spintime;
}

static void *pardevice_timeslice_data(const struct ctl_context *ctx)
{
	return &ctx->target.pardevice->timeslice;
}

static void *parport_data(const struct ctl_context *ctx)
{
	return ctx->target.parport;
}

static void *parport_min_timeslice_data(const struct ctl_context *ctx)
{
	return &parport_min_timeslice_value;
}

static void *parport_max_timeslice_data(const struct ctl_context *ctx)
{
	return &parport_max_timeslice_value;
}

#ifdef CONFIG_PARPORT_1284
#define PARPORT_PROBE_DATA(index)					\
static void *parport_probe_info_ ## index ## _data(const struct ctl_context *ctx) \
{									\
	return &ctx->target.parport->probe_info[index];			\
}

PARPORT_PROBE_DATA(0)
PARPORT_PROBE_DATA(1)
PARPORT_PROBE_DATA(2)
PARPORT_PROBE_DATA(3)
PARPORT_PROBE_DATA(4)
#endif

#define PARPORT_PORT_ENTRY(name, proc)					\
	{								\
		.procname	= name,					\
		.mode		= 0444,					\
		.type		= CTL_FIELD_CUSTOM,			\
		.ctl_custom	= {					\
			.proc_handler	= proc,				\
			.extra1		= parport_data,			\
			.maxlen		= 0,				\
		},							\
	}

#define PARPORT_PROBE_ENTRY(name, index)				\
	{								\
		.procname	= name,					\
		.mode		= 0444,					\
		.type		= CTL_FIELD_CUSTOM,			\
		.ctl_custom	= {					\
			.proc_handler	= do_autoprobe,			\
			.extra2		= parport_probe_info_ ## index ## _data, \
			.maxlen		= 0,				\
		},							\
	}

static const struct ctl_field parport_sysctl_table[] = {
	CTL_FIELD_STATIC_INT_MINMAX("spintime", 0644, parport_spintime_data,
				    &parport_min_spintime_value,
				    &parport_max_spintime_value),
	PARPORT_PORT_ENTRY("base-addr", do_hardware_base_addr),
	PARPORT_PORT_ENTRY("irq", do_hardware_irq),
	PARPORT_PORT_ENTRY("dma", do_hardware_dma),
	PARPORT_PORT_ENTRY("modes", do_hardware_modes),
#ifdef CONFIG_PARPORT_1284
	PARPORT_PROBE_ENTRY("autoprobe", 0),
	PARPORT_PROBE_ENTRY("autoprobe0", 1),
	PARPORT_PROBE_ENTRY("autoprobe1", 2),
	PARPORT_PROBE_ENTRY("autoprobe2", 3),
	PARPORT_PROBE_ENTRY("autoprobe3", 4),
#endif
};

static const struct ctl_field parport_device_dir_table[] = {
	PARPORT_PORT_ENTRY("active", do_active_device),
};

static const struct ctl_field parport_device_sysctl_table[] = {
	{
		.procname	= "timeslice",
		.mode		= 0644,
		.type		= CTL_FIELD_CUSTOM,
		.ctl_custom	= {
			.proc_handler	= proc_doulongvec_ms_jiffies_minmax,
			.data		= pardevice_timeslice_data,
			.extra1		= parport_min_timeslice_data,
			.extra2		= parport_max_timeslice_data,
			.maxlen		= sizeof(unsigned long),
		},
	}
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
	struct ctl_context ctx = {
		.target.parport = port,
	};
	char *tmp_dir_path;
	int err = 0;

	tmp_dir_path = kasprintf(GFP_KERNEL, "dev/parport/%s/devices", port->name);
	if (!tmp_dir_path) {
		err = -ENOMEM;
		goto out;
	}

	port->sysctl_devices_header =
		register_sysctl_ctx_sz(tmp_dir_path, parport_device_dir_table,
				       ARRAY_SIZE(parport_device_dir_table),
				       &ctx);
	if (port->sysctl_devices_header == NULL) {
		err = -ENOENT;
		goto  exit_free_tmp_dir_path;
	}

	kfree(tmp_dir_path);

	tmp_dir_path = kasprintf(GFP_KERNEL, "dev/parport/%s", port->name);
	if (!tmp_dir_path) {
		err = -ENOMEM;
		goto unregister_devices_h;
	}

	port->sysctl_table =
		register_sysctl_ctx_sz(tmp_dir_path, parport_sysctl_table,
				       ARRAY_SIZE(parport_sysctl_table),
				       &ctx);
	if (port->sysctl_table == NULL) {
		err = -ENOENT;
		goto unregister_devices_h;
	}

	kfree(tmp_dir_path);
	return 0;

unregister_devices_h:
	unregister_sysctl_table(port->sysctl_devices_header);
	port->sysctl_devices_header = NULL;

exit_free_tmp_dir_path:
	kfree(tmp_dir_path);

out:
	return err;
}

int parport_proc_unregister(struct parport *port)
{
	if (port->sysctl_devices_header) {
		unregister_sysctl_table(port->sysctl_devices_header);
		port->sysctl_devices_header = NULL;
	}
	if (port->sysctl_table) {
		unregister_sysctl_table(port->sysctl_table);
		port->sysctl_table = NULL;
	}
	return 0;
}

int parport_device_proc_register(struct pardevice *device)
{
	struct ctl_context ctx = {
		.target.pardevice = device,
	};
	struct parport * port = device->port;
	char *tmp_dir_path;
	int err = 0;

	/* Allocate a buffer for two paths: dev/parport/PORT/devices/DEVICE. */
	tmp_dir_path = kasprintf(GFP_KERNEL, "dev/parport/%s/devices/%s", port->name, device->name);
	if (!tmp_dir_path) {
		err = -ENOMEM;
		goto out;
	}

	device->sysctl_table =
		register_sysctl_ctx_sz(tmp_dir_path, parport_device_sysctl_table,
				       ARRAY_SIZE(parport_device_sysctl_table),
				       &ctx);

	kfree(tmp_dir_path);
	return 0;

out:
	return err;
}

int parport_device_proc_unregister(struct pardevice *device)
{
	if (device->sysctl_table) {
		unregister_sysctl_table(device->sysctl_table);
		device->sysctl_table = NULL;
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

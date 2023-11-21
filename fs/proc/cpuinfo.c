// SPDX-License-Identifier: GPL-2.0
#include <linux/cpufreq.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/cpuset.h>
#include <linux/cpumask.h>
#include "internal.h"

extern const struct seq_operations cpuinfo_op;

static bool cpu_allowed(struct seq_file *m, int cpu)
{
	struct task_struct *task;
	cpumask_var_t mask;
	bool allowed;

	if (cpu >= nr_cpu_ids)
		return false;

	task = get_proc_task(file_inode(m->file));
	if (!task)
		return false;

	if (!alloc_cpumask_var(&mask, GFP_KERNEL))
		return false;

	cpuset_cpus_allowed(task, mask);
	put_task_struct(task);

	allowed = cpumask_test_cpu(cpu, mask);
	free_cpumask_var(mask);

	return allowed;
}

static int task_cpuinfo_show(struct seq_file *m, void *v)
{
	return cpuinfo_op.show(m, v);
}

static void *task_cpuinfo_start(struct seq_file *m, loff_t *pos)
{
	if (cpusets_enabled()) {
		for (; *pos < nr_cpu_ids; (*pos)++) {
			if (cpu_allowed(m, *pos))
				return cpuinfo_op.start(m, pos);
		}
		return NULL;
	}
	return cpuinfo_op.start(m, pos);
}

static void *task_cpuinfo_next(struct seq_file *m, void *v, loff_t *pos)
{
	if (cpusets_enabled()) {
		for (; *pos < nr_cpu_ids; (*pos)++) {
			if (cpu_allowed(m, (*pos) + 1))
				return cpuinfo_op.next(m, v, pos);
		}
		return NULL;
	}
	return cpuinfo_op.next(m, v, pos);
}

static void task_cpuinfo_stop(struct seq_file *m, void *v)
{
	return cpuinfo_op.stop(m, v);
}

static const struct seq_operations task_cpuinfo_op = {
	.start	= task_cpuinfo_start,
	.next	= task_cpuinfo_next,
	.stop	= task_cpuinfo_stop,
	.show	= task_cpuinfo_show,
};

int proc_task_cpuinfo_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &task_cpuinfo_op);
}

static int cpuinfo_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &cpuinfo_op);
}

static const struct proc_ops cpuinfo_proc_ops = {
	.proc_flags	= PROC_ENTRY_PERMANENT,
	.proc_open	= cpuinfo_open,
	.proc_read_iter	= seq_read_iter,
	.proc_lseek	= seq_lseek,
	.proc_release	= seq_release,
};

static int __init proc_cpuinfo_init(void)
{
	proc_create("cpuinfo", 0, NULL, &cpuinfo_proc_ops);
	return 0;
}
fs_initcall(proc_cpuinfo_init);

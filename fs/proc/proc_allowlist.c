// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/fs/proc/proc_allowlist.c
 *
 *  Copyright (C) 2022
 *
 *  Author: Alexey Gladkov <legion@kernel.org>
 */
#include <linux/sizes.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rwlock.h>
#include "internal.h"

#define FILE_SEQFILE(f) ((struct seq_file *)((f)->private_data))
#define FILE_DATA(f) (FILE_SEQFILE(f)->private)

bool proc_has_allowlist(struct proc_fs_info *fs_info)
{
	bool ret;
	unsigned long flags;

	read_lock_irqsave(&fs_info->allowlist_lock, flags);
	ret = (fs_info->allowlist == NULL);
	read_unlock_irqrestore(&fs_info->allowlist_lock, flags);

	return ret;
}

bool proc_pde_access_allowed(struct proc_fs_info *fs_info, struct proc_dir_entry *de)
{
	bool ret = false;
	char *ptr;
	unsigned long flags;

	read_lock_irqsave(&fs_info->allowlist_lock, flags);

	if (!fs_info->allowlist) {
		read_unlock_irqrestore(&fs_info->allowlist_lock, flags);

		if (!pde_is_allowlist(de))
			ret = true;

		return ret;
	}

	ptr = fs_info->allowlist;

	while (*ptr != '\0') {
		struct proc_dir_entry *pde;
		char *sep, *end;
		size_t len, pathlen;

		if (!(sep = strchr(ptr, '\n')))
			pathlen = strlen(ptr);
		else
			pathlen = (sep - ptr);

		if (!pathlen)
			goto next;

		pde = de;
		end = NULL;
		len = pathlen;

		while (ptr != end && len > 0) {
			end = ptr + len - 1;

			while (1) {
				if (*end == '/') {
					end++;
					break;
				}
				if (end == ptr)
					break;
				end--;
			}

			if (proc_match(end, pde, ptr + len - end))
				goto next;

			len = end - ptr - 1;
			pde = pde->parent;
		}

		ret = true;
		break;
next:
		ptr += pathlen + 1;
	}

	read_unlock_irqrestore(&fs_info->allowlist_lock, flags);

	return ret;
}

static int show_allowlist(struct seq_file *m, void *v)
{
	struct proc_fs_info *fs_info = proc_sb_info(m->file->f_inode->i_sb);
	char *p = fs_info->allowlist;
	unsigned long flags;

	read_lock_irqsave(&fs_info->allowlist_lock, flags);
	if (p)
		seq_puts(m, p);
	read_unlock_irqrestore(&fs_info->allowlist_lock, flags);

	return 0;
}

static int open_allowlist(struct inode *inode, struct file *file)
{
	struct proc_fs_info *fs_info = proc_sb_info(inode->i_sb);
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	// we need this because shrink_dcache_sb() can't drop our own dentry.
	if (!proc_pde_access_allowed(fs_info, PDE(inode)))
		return -ENOENT;

	// we want a null-terminated string so not all 128K are available.
	ret = single_open_size(file, show_allowlist, NULL, SZ_128K);

	if (!ret && (file->f_mode & FMODE_WRITE) &&
	    (file->f_flags & O_APPEND) && !(file->f_flags & O_TRUNC))
		show_allowlist(FILE_SEQFILE(file), NULL);

	return ret;
}

static ssize_t write_allowlist(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
	struct seq_file *seq_file = FILE_SEQFILE(file);
	ssize_t ret;
	ssize_t n = count;
	const char *ptr = buffer;

	if ((seq_file->count + count) >= (seq_file->size - 1))
		return -EFBIG;

	while (n > 0) {
		char chunk[SZ_256];
		loff_t chkpos = 0;
		ssize_t i, len;

		len = simple_write_to_buffer(chunk, sizeof(chunk), &chkpos, ptr, n);
		if (len < 0)
			return len;

		for (i = 0; i < len; i++) {
			if (!isprint(chunk[i]) && chunk[i] != '\n')
				return -EINVAL;
		}

		ret = seq_write(seq_file, chunk, len);
		if (ret < 0)
			return -EINVAL;

		ptr += len;
		n -= len;
	}

	if (pos)
		*pos += count;

	return count;
}

static int close_allowlist(struct inode *inode, struct file *file)
{
	struct seq_file *seq_file = FILE_SEQFILE(file);
	struct proc_fs_info *fs_info = proc_sb_info(inode->i_sb);

	if (seq_file->buf && (file->f_mode & FMODE_WRITE)) {
		char *buf;

		if (!seq_get_buf(seq_file, &buf))
			return -EIO;
		*buf = '\0';

		if (strcmp(seq_file->buf, fs_info->allowlist)) {
			unsigned long flags;

			buf = kstrndup(seq_file->buf, seq_file->count, GFP_KERNEL_ACCOUNT);
			if (!buf)
				return -EIO;

			write_lock_irqsave(&fs_info->allowlist_lock, flags);

			shrink_dcache_sb(inode->i_sb);

			kfree(fs_info->allowlist);
			fs_info->allowlist = buf;

			write_unlock_irqrestore(&fs_info->allowlist_lock, flags);
		}
	}

	return single_release(inode, file);
}

static const struct proc_ops proc_allowlist_ops = {
	.proc_open	= open_allowlist,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_write	= write_allowlist,
	.proc_release	= close_allowlist,
};

static int __init proc_allowlist_init(void)
{
	struct proc_dir_entry *pde;
	pde = proc_create("allowlist", S_IRUSR | S_IWUSR, NULL, &proc_allowlist_ops);
	pde_make_permanent(pde);
	pde_make_allowlist(pde);
	return 0;
}
fs_initcall(proc_allowlist_init);

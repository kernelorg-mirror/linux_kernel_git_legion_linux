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
#include <linux/list_sort.h>
#include "internal.h"

#define FILE_SEQFILE(f) ((struct seq_file *)((f)->private_data))
#define FILE_DATA(f) (FILE_SEQFILE(f)->private)

int proc_allowlist_append(struct list_head *allowlist, const char *path, size_t len)
{
	struct allowlist_entry *new;

	if (!len)
		return 0;

	new = kmalloc(sizeof(*new), GFP_KERNEL_ACCOUNT);
	if (!new)
		goto nomem;

	new->path = kstrndup(path, len, GFP_KERNEL_ACCOUNT);
	if (!new->path)
		goto nomem;

	INIT_LIST_HEAD(&new->list);
	list_add_tail(&new->list, allowlist);

	return 0;
nomem:
	if (new) {
		kfree(new->path);
		kfree(new);
	}
	return -ENOMEM;
}

void proc_allowlist_free(struct list_head *allowlist)
{
	struct list_head *el, *next;
	struct allowlist_entry *entry;

	list_for_each_safe(el, next, allowlist) {
		entry = list_entry(el, struct allowlist_entry, list);
		kfree(entry->path);
		kfree(entry);
	}
}

bool proc_pde_access_allowed(struct proc_fs_info *fs_info, struct proc_dir_entry *de)
{
	bool ret = false;
	unsigned long flags;
	struct list_head *el, *next;

	if (!(fs_info->subset & PROC_SUBSET_ALLOWLIST)) {
		if (!pde_is_allowlist(de))
			ret = true;

		return ret;
	}

	read_lock_irqsave(&fs_info->allowlist_lock, flags);

	list_for_each_safe(el, next, &fs_info->allowlist) {
		struct allowlist_entry *entry = list_entry(el, struct allowlist_entry, list);

		struct proc_dir_entry *pde = de;
		char  *end = NULL;
		char  *ptr = entry->path;
		size_t len = strlen(entry->path);

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
next:		;
	}

	read_unlock_irqrestore(&fs_info->allowlist_lock, flags);

	return ret;
}

static int show_allowlist(struct seq_file *m, void *v)
{
	struct proc_fs_info *fs_info = proc_sb_info(m->file->f_inode->i_sb);
	unsigned long flags;
	struct list_head *el, *next;
	struct allowlist_entry *entry;

	read_lock_irqsave(&fs_info->allowlist_lock, flags);

	list_for_each_safe(el, next, &fs_info->allowlist) {
		entry = list_entry(el, struct allowlist_entry, list);
		seq_puts(m, entry->path);
		seq_puts(m, "\n");
	}

	read_unlock_irqrestore(&fs_info->allowlist_lock, flags);

	return 0;
}

static int open_allowlist(struct inode *inode, struct file *file)
{
	struct proc_fs_info *fs_info = proc_sb_info(inode->i_sb);
	int ret;

	if (!ns_capable(current_user_ns(), CAP_SYS_ADMIN))
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

static int allowlist_cmp(void *priv, const struct list_head *a, const struct list_head *b)
{
	struct allowlist_entry *ia = list_entry(a, struct allowlist_entry, list);
	struct allowlist_entry *ib = list_entry(b, struct allowlist_entry, list);

	return strcmp(ia->path, ib->path);
}

static int recreate_allowlist(struct proc_fs_info *fs_info, const char *buf, size_t buflen)
{
	const char *ptr = buf;
	size_t len = buflen;
	size_t lineno = 1;
	int ret = 0;
	LIST_HEAD(allowlist);

	while (len > 0) {
		char *sep;
		size_t pathlen;

		if (!(sep = memchr(ptr, '\n', len)))
			pathlen = buflen;
		else
			pathlen = (sep - ptr);

		if (pathlen > 0) {
			ret = -ENAMETOOLONG;
			if (pathlen >= PATH_MAX) {
				pr_crit("allowlist:%lu: pathname is too long\n", lineno);
				goto err;
			}

			ret = -EINVAL;
			if (*ptr == '/') {
				pr_crit("allowlist:%lu: the name must be relative to the mount point\n", lineno);
				goto err;
			}
			if (!isalpha(*ptr)) {
				pr_crit("allowlist:%lu: name must start with a letter\n", lineno);
				goto err;
			}

			proc_allowlist_append(&allowlist, ptr, pathlen);
		}

		ptr += pathlen + 1;
		len -= pathlen + 1;

		lineno++;
	}

	proc_allowlist_free(&fs_info->allowlist);
	INIT_LIST_HEAD(&fs_info->allowlist);

	if (!list_empty(&allowlist)) {
		list_replace(&allowlist, &fs_info->allowlist);
		list_sort(NULL, &fs_info->allowlist, allowlist_cmp);
	}

	return 0;
err:
	proc_allowlist_free(&allowlist);
	return ret;
}

static int close_allowlist(struct inode *inode, struct file *file)
{
	struct seq_file *seq_file = FILE_SEQFILE(file);
	struct proc_fs_info *fs_info = proc_sb_info(inode->i_sb);

	if (seq_file->buf && (file->f_mode & FMODE_WRITE)) {
		unsigned long flags;
		char *buf;

		if (!seq_get_buf(seq_file, &buf))
			return -EIO;
		*buf = '\0';

		write_lock_irqsave(&fs_info->allowlist_lock, flags);

		if (recreate_allowlist(fs_info, seq_file->buf, seq_file->count) < 0) {
			write_unlock_irqrestore(&fs_info->allowlist_lock, flags);
			return -EIO;
		}

		shrink_dcache_sb(inode->i_sb);
		write_unlock_irqrestore(&fs_info->allowlist_lock, flags);
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
	pde = proc_create("allowlist", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, NULL, &proc_allowlist_ops);
	pde_make_permanent(pde);
	pde_make_allowlist(pde);
	return 0;
}
fs_initcall(proc_allowlist_init);

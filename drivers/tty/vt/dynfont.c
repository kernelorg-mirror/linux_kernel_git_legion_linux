// SPDX-License-Identifier: GPL-2.0
/*
 * Dynamic console font loader.
 *
 * Loads a PSF2 v1 indexed Unicode console font via request_firmware() and
 * dynamically swaps unused glyph slots on VT glyph misses.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/bsearch.h>
#include <linux/console.h>
#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/font.h>
#include <linux/init.h>
#include <linux/kd.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/unaligned.h>
#include <linux/vt.h>
#include <linux/vt_kern.h>
#include <linux/workqueue.h>

#define DYNFONT_MAX_WIDTH	64
#define DYNFONT_MAX_HEIGHT	128
#define DYNFONT_MAX_SLOTS	512
#define DYNFONT_MAX_UCS		0x10ffff
#define DYNFONT_GLYPH_NONE	0xffffffffU

#define PSF2_MAGIC0		0x72
#define PSF2_MAGIC1		0xb5
#define PSF2_MAGIC2		0x4a
#define PSF2_MAGIC3		0x86
#define PSF2_V1_VERSION		1
#define PSF2_HAS_UNICODE_TABLE	0x01

struct psf2_v1_header {
	u8 magic[4];
	__le32 version;
	__le32 headersize;
	__le32 flags;
	__le32 length;
	__le32 charsize;
	__le32 height;
	__le32 width;
	__le32 index_count;
};

struct psf2_v1_entry {
	__le32 ucs;
	__le32 glyph;
};

static char *fw_name = "dynfont-8x16.psfu";
module_param(fw_name, charp, 0444);
MODULE_PARM_DESC(fw_name, "Firmware filename with PSF2 v1 Unicode console font");

static DEFINE_MUTEX(dynfont_mutex);
static struct platform_device *dynfont_pdev;
static const struct firmware *dynfont_fw;
static const u8 *dynfont_bitmaps;
static const struct psf2_v1_entry *dynfont_index;
static u32 dynfont_index_count;
static unsigned int dynfont_width;
static unsigned int dynfont_height;
static unsigned int dynfont_glyph_size;
static u8 *dynfont_init_buf;
static u32 dynfont_init_glyph[256];
static bool dynfont_notifier_registered;
static char dynfont_loaded_name[128];
static u16 dynfont_cursor[MAX_NR_CONSOLES];
static DECLARE_BITMAP(dynfont_initialized_vcs, MAX_NR_CONSOLES);
static DECLARE_BITMAP(dynfont_pending_vcs, MAX_NR_CONSOLES);
static u32 dynfont_slot_glyph[MAX_NR_CONSOLES][DYNFONT_MAX_SLOTS];

static atomic64_t dynfont_stat_loaded = ATOMIC64_INIT(0);
static atomic64_t dynfont_stat_evictions = ATOMIC64_INIT(0);
static atomic64_t dynfont_stat_nospace = ATOMIC64_INIT(0);
static atomic64_t dynfont_stat_notfound = ATOMIC64_INIT(0);

#define DYNFONT_STAT_ATTR(_name)					\
static ssize_t _name##_show(struct device *dev,				\
			    struct device_attribute *attr, char *buf)	\
{									\
	return sysfs_emit(buf, "%lld\n",				\
			  atomic64_read(&dynfont_stat_##_name));	\
}									\
static DEVICE_ATTR_RO(_name)

DYNFONT_STAT_ATTR(loaded);
DYNFONT_STAT_ATTR(evictions);
DYNFONT_STAT_ATTR(nospace);
DYNFONT_STAT_ATTR(notfound);

static struct attribute *dynfont_stats_attrs[] = {
	&dev_attr_loaded.attr,
	&dev_attr_evictions.attr,
	&dev_attr_nospace.attr,
	&dev_attr_notfound.attr,
	NULL,
};

static const struct attribute_group dynfont_stats_group = {
	.name = "stats",
	.attrs = dynfont_stats_attrs,
};

static int dynfont_glyph_miss(struct vc_data *vc, int ucs);

static int dynfont_cmp_index_key(const void *key, const void *elem)
{
	u32 ucs = *(const u32 *)key;
	u32 entry_ucs = get_unaligned_le32(&((const struct psf2_v1_entry *)elem)->ucs);

	if (ucs < entry_ucs)
		return -1;
	if (ucs > entry_ucs)
		return 1;
	return 0;
}

static const u8 *dynfont_lookup_glyph(const u8 *bitmaps,
				      unsigned int glyph_size,
				      const struct psf2_v1_entry *index,
				      u32 count, u32 ucs, u32 *glyph_out)
{
	const struct psf2_v1_entry *e;
	u32 glyph;

	if (!bitmaps || !index || !count)
		return NULL;

	e = bsearch(&ucs, index, count, sizeof(*index), dynfont_cmp_index_key);
	if (!e)
		return NULL;

	glyph = get_unaligned_le32(&e->glyph);
	if (glyph_out)
		*glyph_out = glyph;
	return bitmaps + (size_t)glyph * glyph_size;
}

static void dynfont_reset_slot_glyph(unsigned int vc_num)
{
	unsigned int i;

	for (i = 0; i < DYNFONT_MAX_SLOTS; i++)
		dynfont_slot_glyph[vc_num][i] = DYNFONT_GLYPH_NONE;
}

static int dynfont_init_vc(struct vc_data *vc)
{
	struct console_font init_font = {
		.width = dynfont_width,
		.height = dynfont_height,
		.charcount = DYNFONT_MAX_SLOTS,
		.data = dynfont_init_buf,
	};
	unsigned int u;
	int ret;

	WARN_CONSOLE_UNLOCKED();

	if (test_bit(vc->vc_num, dynfont_initialized_vcs))
		return 0;

	if (vc->vc_mode != KD_TEXT || !vc->vc_sw ||
	    !vc->vc_sw->con_font_set || !vc->vc_sw->con_font_set_glyph)
		return -EOPNOTSUPP;

	ret = vc->vc_sw->con_font_set(vc, &init_font, dynfont_height, 0);
	if (ret)
		return ret;

	ret = con_clear_unimap_locked(vc);
	if (ret)
		return ret;

	for (u = 0x20; u <= 0x7e; u++) {
		ret = con_set_unipair(vc, u, u, true);
		if (ret)
			return ret;
	}
	for (u = 0xa0; u <= 0xff; u++) {
		ret = con_set_unipair(vc, u, u, true);
		if (ret)
			return ret;
	}

	/* Bind U+FFFD to pinned slot 0x7f */
	ret = con_set_unipair(vc, 0xfffd, 0x7f, true);
	if (ret)
		return ret;

	dynfont_reset_slot_glyph(vc->vc_num);
	for (u = 0x20; u <= 0x7e; u++)
		dynfont_slot_glyph[vc->vc_num][u] = dynfont_init_glyph[u];
	for (u = 0xa0; u <= 0xff; u++)
		dynfont_slot_glyph[vc->vc_num][u] = dynfont_init_glyph[u];
	dynfont_slot_glyph[vc->vc_num][0x7f] = dynfont_init_glyph[0x7f];

	dynfont_cursor[vc->vc_num] = 256;
	set_bit(vc->vc_num, dynfont_initialized_vcs);
	clear_bit(vc->vc_num, dynfont_pending_vcs);
	vc->vc_glyph_miss = dynfont_glyph_miss;
	return 0;
}

static int dynfont_pick_slot(struct vc_data *vc)
{
	DECLARE_BITMAP(used, DYNFONT_MAX_SLOTS);
	unsigned int start = dynfont_cursor[vc->vc_num] % DYNFONT_MAX_SLOTS;
	unsigned int slot;

	vc_get_used_glyphs(vc, used, DYNFONT_MAX_SLOTS);

	/* Keep only slot 0, space (0x20), and slot 0x7f (U+FFFD) pinned */
	__set_bit(0, used);
	__set_bit(0x20, used);
	__set_bit(0x7f, used);

	slot = find_next_zero_bit(used, DYNFONT_MAX_SLOTS, start);
	if (slot >= DYNFONT_MAX_SLOTS)
		slot = find_next_zero_bit(used, start, 0);
	if (slot >= DYNFONT_MAX_SLOTS || test_bit(slot, used))
		return -ENOSPC;

	return slot;
}

static int dynfont_find_glyph_slot(struct vc_data *vc, u32 glyph_id)
{
	unsigned int slot;

	if (glyph_id == DYNFONT_GLYPH_NONE)
		return -ENOENT;

	for (slot = 0; slot < DYNFONT_MAX_SLOTS; slot++) {
		if (dynfont_slot_glyph[vc->vc_num][slot] == glyph_id)
			return slot;
	}
	return -ENOENT;
}

static int dynfont_glyph_miss(struct vc_data *vc, int ucs)
{
	const u8 *glyph;
	u32 glyph_id;
	int slot, ret;

	if (!dynfont_fw || ucs < 0 || ucs > DYNFONT_MAX_UCS) {
		atomic64_inc(&dynfont_stat_notfound);
		return -ENOENT;
	}

	if (!test_bit(vc->vc_num, dynfont_initialized_vcs)) {
		ret = dynfont_init_vc(vc);
		if (ret)
			return ret;
	}

	if (vc->vc_font.width != dynfont_width ||
	    vc->vc_font.height != dynfont_height)
		return -EINVAL;

	glyph = dynfont_lookup_glyph(dynfont_bitmaps, dynfont_glyph_size,
				     dynfont_index, dynfont_index_count,
				     (u32)ucs, &glyph_id);
	if (!glyph || (ucs != 0x20 && ucs != 0xa0 &&
		       !memchr_inv(glyph, 0, dynfont_glyph_size))) {
		atomic64_inc(&dynfont_stat_notfound);
		return -ENOENT;
	}

	/*
	 * Reuse an existing slot if this PSF2 glyph is already loaded on the VC
	 * (handles both non-BMP cache hits and BMP homoglyph aliases).
	 */
	slot = dynfont_find_glyph_slot(vc, glyph_id);
	if (slot >= 0) {
		if (ucs <= 0xffff) {
			ret = con_set_unipair(vc, (u16)ucs, (u16)slot, false);
			if (ret)
				return ret;
		}
		return slot;
	}

	slot = dynfont_pick_slot(vc);
	if (slot < 0) {
		if (slot == -ENOSPC)
			atomic64_inc(&dynfont_stat_nospace);
		return slot;
	}

	ret = con_font_set_glyph(vc, slot, glyph);
	if (ret)
		return ret;

	/*
	 * For BMP codepoints bind directly in consolemap; for non-BMP (> 0xffff)
	 * clear any previous BMP mapping on this slot using noncharacter U+FFFF.
	 */
	ret = con_set_unipair(vc, ucs <= 0xffff ? (u16)ucs : 0xffff,
			      (u16)slot, true);
	if (ret)
		return ret;

	if (dynfont_slot_glyph[vc->vc_num][slot] != DYNFONT_GLYPH_NONE)
		atomic64_inc(&dynfont_stat_evictions);
	dynfont_slot_glyph[vc->vc_num][slot] = glyph_id;
	atomic64_inc(&dynfont_stat_loaded);
	dynfont_cursor[vc->vc_num] = (slot + 1) % DYNFONT_MAX_SLOTS;
	return slot;
}

static void dynfont_init_workfn(struct work_struct *work)
{
	unsigned int i;

	console_lock();
	for_each_set_bit(i, dynfont_pending_vcs, MAX_NR_CONSOLES) {
		struct vc_data *vc = vc_cons[i].d;

		clear_bit(i, dynfont_pending_vcs);
		if (!vc)
			continue;
		dynfont_init_vc(vc);
	}
	console_unlock();
}

static DECLARE_WORK(dynfont_init_work, dynfont_init_workfn);

static int dynfont_vt_notify(struct notifier_block *nb, unsigned long action,
			     void *data)
{
	struct vt_notifier_param *param = data;
	struct vc_data *vc = param->vc;

	if (!vc || vc->vc_num >= MAX_NR_CONSOLES)
		return NOTIFY_OK;

	switch (action) {
	case VT_ALLOCATE:
		clear_bit(vc->vc_num, dynfont_initialized_vcs);
		vc->vc_glyph_miss = dynfont_glyph_miss;
		set_bit(vc->vc_num, dynfont_pending_vcs);
		schedule_work(&dynfont_init_work);
		break;
	case VT_DEALLOCATE:
		clear_bit(vc->vc_num, dynfont_pending_vcs);
		clear_bit(vc->vc_num, dynfont_initialized_vcs);
		dynfont_reset_slot_glyph(vc->vc_num);
		if (vc->vc_glyph_miss == dynfont_glyph_miss)
			vc->vc_glyph_miss = NULL;
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block dynfont_vt_nb = {
	.notifier_call = dynfont_vt_notify,
};

static void dynfont_restore_vc(struct vc_data *vc, bool restore_font)
{
	struct console_font def_font = { };

	WARN_CONSOLE_UNLOCKED();

	if (vc->vc_glyph_miss == dynfont_glyph_miss)
		vc->vc_glyph_miss = NULL;

	if (restore_font && test_bit(vc->vc_num, dynfont_initialized_vcs) &&
	    vc->vc_mode == KD_TEXT && vc->vc_sw) {
		if (vc->vc_sw->con_font_default)
			vc->vc_sw->con_font_default(vc, &def_font, NULL);
		con_set_default_unimap(vc);
	}

	clear_bit(vc->vc_num, dynfont_initialized_vcs);
	clear_bit(vc->vc_num, dynfont_pending_vcs);
	dynfont_reset_slot_glyph(vc->vc_num);
}

static void dynfont_unload_locked(bool restore_font)
{
	const struct firmware *old_fw;
	u8 *old_buf;
	int i;

	lockdep_assert_held(&dynfont_mutex);

	if (dynfont_notifier_registered) {
		unregister_vt_notifier(&dynfont_vt_nb);
		dynfont_notifier_registered = false;
	}
	cancel_work_sync(&dynfont_init_work);

	console_lock();
	for (i = 0; i < MAX_NR_CONSOLES; i++) {
		struct vc_data *vc = vc_cons[i].d;

		if (vc) {
			dynfont_restore_vc(vc, restore_font);
		} else {
			clear_bit(i, dynfont_initialized_vcs);
			clear_bit(i, dynfont_pending_vcs);
		}
	}
	old_buf = dynfont_init_buf;
	dynfont_init_buf = NULL;
	old_fw = dynfont_fw;
	dynfont_fw = NULL;
	dynfont_index = NULL;
	dynfont_index_count = 0;
	dynfont_bitmaps = NULL;
	dynfont_width = 0;
	dynfont_height = 0;
	dynfont_glyph_size = 0;
	console_unlock();

	kfree(old_buf);
	release_firmware(old_fw);
	dynfont_loaded_name[0] = '\0';
}

struct dynfont_parsed {
	const u8 *bitmaps;
	const struct psf2_v1_entry *index;
	u32 index_count;
	u32 num_glyphs;
	unsigned int width;
	unsigned int height;
	unsigned int glyph_size;
};

static int dynfont_parse_firmware(const struct firmware *fw,
				  struct dynfont_parsed *out)
{
	const struct psf2_v1_header *hdr;
	const struct psf2_v1_entry *index;
	u32 version, headersize, flags, length, charsize, width, height, count;
	size_t bitmap_bytes, index_bytes, index_off, expected;
	u32 i, prev_ucs = 0;

	if (fw->size < sizeof(*hdr))
		return -EINVAL;

	hdr = (const void *)fw->data;
	if (hdr->magic[0] != PSF2_MAGIC0 || hdr->magic[1] != PSF2_MAGIC1 ||
	    hdr->magic[2] != PSF2_MAGIC2 || hdr->magic[3] != PSF2_MAGIC3)
		return -EINVAL;

	version = le32_to_cpu(hdr->version);
	headersize = le32_to_cpu(hdr->headersize);
	flags = le32_to_cpu(hdr->flags);
	length = le32_to_cpu(hdr->length);
	charsize = le32_to_cpu(hdr->charsize);
	height = le32_to_cpu(hdr->height);
	width = le32_to_cpu(hdr->width);
	count = le32_to_cpu(hdr->index_count);

	if (version != PSF2_V1_VERSION ||
	    !(flags & PSF2_HAS_UNICODE_TABLE) ||
	    headersize < sizeof(*hdr) ||
	    !length || !count ||
	    !width || width > DYNFONT_MAX_WIDTH ||
	    !height || height > DYNFONT_MAX_HEIGHT ||
	    charsize != font_glyph_size(width, height))
		return -EINVAL;

	if (check_mul_overflow((size_t)length, (size_t)charsize, &bitmap_bytes) ||
	    check_add_overflow((size_t)headersize, bitmap_bytes, &index_off) ||
	    check_mul_overflow((size_t)count, sizeof(*index), &index_bytes) ||
	    check_add_overflow(index_off, index_bytes, &expected) ||
	    fw->size != expected)
		return -EINVAL;

	index = (const struct psf2_v1_entry *)(fw->data + index_off);
	for (i = 0; i < count; i++) {
		u32 ucs = get_unaligned_le32(&index[i].ucs);
		u32 glyph = get_unaligned_le32(&index[i].glyph);

		if (ucs > DYNFONT_MAX_UCS || glyph >= length)
			return -EINVAL;
		if (i && ucs <= prev_ucs)
			return -EINVAL;
		prev_ucs = ucs;
	}

	out->bitmaps = fw->data + headersize;
	out->index = index;
	out->index_count = count;
	out->num_glyphs = length;
	out->width = width;
	out->height = height;
	out->glyph_size = charsize;
	return 0;
}

static int dynfont_apply_firmware(const struct firmware *fw, const char *name)
{
	struct dynfont_parsed parsed;
	const u8 *g;
	u32 u;
	u8 *buf;
	int i, ret, attached = 0;

	if (!fw)
		return -ENOENT;

	ret = dynfont_parse_firmware(fw, &parsed);
	if (ret) {
		pr_err("invalid PSF2 v1 firmware '%s' (size %zu): %d\n",
		       name, fw->size, ret);
		release_firmware(fw);
		return ret;
	}

	buf = kzalloc(DYNFONT_MAX_SLOTS * parsed.glyph_size, GFP_KERNEL);
	if (!buf) {
		release_firmware(fw);
		return -ENOMEM;
	}

	guard(mutex)(&dynfont_mutex);

	if (dynfont_fw)
		dynfont_unload_locked(false);

	/* Populate initial 0x00..0xff glyphs and U+FFFD at slot 0x7f */
	for (u = 0; u < 256; u++) {
		u32 gid = DYNFONT_GLYPH_NONE;

		g = dynfont_lookup_glyph(parsed.bitmaps, parsed.glyph_size,
					 parsed.index, parsed.index_count, u,
					 &gid);
		if (g)
			memcpy(buf + u * parsed.glyph_size, g,
			       parsed.glyph_size);
		dynfont_init_glyph[u] = gid;
	}
	dynfont_init_glyph[0x7f] = DYNFONT_GLYPH_NONE;
	g = dynfont_lookup_glyph(parsed.bitmaps, parsed.glyph_size,
				 parsed.index, parsed.index_count, 0xfffd,
				 &dynfont_init_glyph[0x7f]);
	if (g)
		memcpy(buf + 0x7f * parsed.glyph_size, g, parsed.glyph_size);

	dynfont_fw = fw;
	dynfont_bitmaps = parsed.bitmaps;
	dynfont_index = parsed.index;
	dynfont_index_count = parsed.index_count;
	dynfont_width = parsed.width;
	dynfont_height = parsed.height;
	dynfont_glyph_size = parsed.glyph_size;
	dynfont_init_buf = buf;
	strscpy(dynfont_loaded_name, name, sizeof(dynfont_loaded_name));

	ret = register_vt_notifier(&dynfont_vt_nb);
	if (ret) {
		dynfont_unload_locked(false);
		return ret;
	}
	dynfont_notifier_registered = true;

	console_lock();
	for (i = 0; i < MAX_NR_CONSOLES; i++) {
		struct vc_data *vc = vc_cons[i].d;

		if (!vc)
			continue;
		if (!dynfont_init_vc(vc))
			attached++;
	}
	console_unlock();

	pr_info("loaded PSF2 v1 '%s' (%ux%u, %u glyphs, %u mappings), attached to %d VT(s)\n",
		dynfont_loaded_name, parsed.width, parsed.height,
		parsed.num_glyphs, parsed.index_count, attached);
	return 0;
}

static void dynfont_fw_cb(const struct firmware *fw, void *context)
{
	if (!fw) {
		pr_info("firmware '%s' not available yet; load via /sys/devices/platform/dynfont/firmware\n",
			fw_name);
		return;
	}

	dynfont_apply_firmware(fw, fw_name);
}

static ssize_t firmware_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	guard(mutex)(&dynfont_mutex);

	return sysfs_emit(buf, "%s\n",
			  dynfont_fw ? dynfont_loaded_name : "none");
}

static ssize_t firmware_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count)
{
	const struct firmware *fw;
	char name[sizeof(dynfont_loaded_name)];
	char *trimmed;
	int ret;

	if (count >= sizeof(name))
		return -EINVAL;

	memcpy(name, buf, count);
	name[count] = '\0';
	trimmed = strim(name);

	if (!trimmed[0] || !strcmp(trimmed, "none")) {
		guard(mutex)(&dynfont_mutex);
		dynfont_unload_locked(true);
		pr_info("unloaded firmware, restored default console fonts\n");
		return count;
	}

	ret = request_firmware(&fw, trimmed, dev);
	if (ret) {
		pr_err("failed to load firmware '%s': %d\n", trimmed, ret);
		return ret;
	}

	ret = dynfont_apply_firmware(fw, trimmed);
	if (ret)
		return ret;

	return count;
}
static DEVICE_ATTR_RW(firmware);

static int __init dynfont_init(void)
{
	int ret;

	dynfont_pdev = platform_device_register_simple("dynfont", -1, NULL, 0);
	if (IS_ERR(dynfont_pdev))
		return PTR_ERR(dynfont_pdev);

	ret = device_create_file(&dynfont_pdev->dev, &dev_attr_firmware);
	if (ret)
		goto err_pdev;

	ret = sysfs_create_group(&dynfont_pdev->dev.kobj, &dynfont_stats_group);
	if (ret)
		goto err_fw_attr;

	if (fw_name && fw_name[0]) {
		ret = request_firmware_nowait(THIS_MODULE, FW_ACTION_UEVENT,
					      fw_name, &dynfont_pdev->dev,
					      GFP_KERNEL, NULL, dynfont_fw_cb);
		if (ret)
			pr_warn("async firmware request for '%s' failed: %d\n",
				fw_name, ret);
	}

	return 0;

err_fw_attr:
	device_remove_file(&dynfont_pdev->dev, &dev_attr_firmware);
err_pdev:
	platform_device_unregister(dynfont_pdev);
	dynfont_pdev = NULL;
	return ret;
}

static void __exit dynfont_exit(void)
{
	sysfs_remove_group(&dynfont_pdev->dev.kobj, &dynfont_stats_group);
	device_remove_file(&dynfont_pdev->dev, &dev_attr_firmware);

	scoped_guard(mutex, &dynfont_mutex)
		dynfont_unload_locked(true);

	platform_device_unregister(dynfont_pdev);
	dynfont_pdev = NULL;
}

module_init(dynfont_init);
module_exit(dynfont_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Dynamic VT console font glyph loader");

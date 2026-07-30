// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 LibXZR <i@xzr.moe>.
 * Adapted for kernel 4.14 by cy122.
 * Optimized with batch single-write, re-entrancy guard, and pre-allocated creds.
 */

#define pr_fmt(fmt) "panic_logstore: " fmt

#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmsg_dump.h>
#include <linux/module.h>
#include <security.h>

/*
 * Path to the panic log file on a mounted persistent partition.
 * /cache is mounted early and survives reboot.
 */
#define LOG_FILE_PATH "/cache/last_panic.txt"
#define LOG_BUF_SIZE (128 * 1024)

extern struct selinux_state selinux_state;

static struct kmsg_dumper logstore_dumper;
static atomic_t logstore_active = ATOMIC_INIT(0);
static const struct cred *root_cred;
static char log_buf[LOG_BUF_SIZE];

void do_logstore(void)
{
	const struct cred *saved_cred;
	struct file *f;
	size_t len;
	int ret;
	int old_enforce;

	/* Re-entrancy guard: prevent nested panic loops */
	if (atomic_cmpxchg(&logstore_active, 0, 1) != 0)
		return;

	/* Bypass SELinux — we're in panic, better to write than to be denied */
	old_enforce = enforcing_enabled(&selinux_state);
	enforcing_set(&selinux_state, false);

	/* Use pre-allocated root_cred if available, fallback otherwise */
	if (root_cred) {
		saved_cred = override_creds(root_cred);
	} else {
		const struct cred *tmp_cred = prepare_kernel_cred(NULL);
		if (!tmp_cred) {
			pr_err("Unable to prepare kernel cred\n");
			goto restore_selinux;
		}
		saved_cred = override_creds(tmp_cred);
	}

	f = filp_open(LOG_FILE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(f)) {
		ret = PTR_ERR(f);
		pr_err("Unable to open log file, ret = %d\n", ret);
		goto revert_cred;
	}

	logstore_dumper.active = true;
	kmsg_dump_rewind(&logstore_dumper);
	if (kmsg_dump_get_buffer(&logstore_dumper, true, log_buf, sizeof(log_buf), &len)) {
		ret = kernel_write(f, log_buf, len, &f->f_pos);
		if (ret < 0)
			pr_err("Unable to write log file, ret = %d\n", ret);
	}
	logstore_dumper.active = false;

	ret = vfs_fsync(f, 0);
	if (ret)
		pr_err("Unable to sync log file, ret = %d\n", ret);
	else
		pr_info("Panic logstore is done.\n");

	filp_close(f, NULL);

revert_cred:
	revert_creds(saved_cred);
restore_selinux:
	enforcing_set(&selinux_state, old_enforce);
}

static int __init logstore_init(void)
{
	root_cred = prepare_kernel_cred(NULL);
	if (!root_cred)
		pr_err("Failed to pre-allocate root cred\n");
	return 0;
}
late_initcall(logstore_init);

static int logstore_trigger_store(
	const char *buf, const struct kernel_param *kp)
{
	do_logstore();
	return 0;
}

static struct kernel_param_ops logstore_trigger_ops = {
	.set = &logstore_trigger_store,
};

module_param_cb(trigger, &logstore_trigger_ops, NULL, 0644);

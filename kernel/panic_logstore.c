// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 LibXZR <i@xzr.moe>.
 * Adapted for kernel 4.14 by cy122.
 */

#define pr_fmt(fmt) "panic_logstore: " fmt

#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kmsg_dump.h>
#include <linux/module.h>
#include <security.h>

/*
 * Path to the panic log file on a mounted persistent partition.
 * /cache is mounted early and survives reboot.
 * Change to a device-specific path if needed.
 */
#define LOG_FILE_PATH "/cache/last_panic.txt"

extern struct selinux_state selinux_state;

/*
 * Static dumper for iterating kmsg buffer.
 * We don't register it as a normal kmsg dumper (via kmsg_dump_register);
 * instead we use its internal state (cur_idx/next_idx/cur_seq/next_seq)
 * to walk the buffer manually from do_logstore().
 */
static struct kmsg_dumper logstore_dumper;

void do_logstore(void)
{
	const struct cred *saved_cred, *root_cred;
	char buf[1024];
	struct file *f;
	size_t len;
	int ret;
	int old_enforce;

	/* Bypass SELinux — we're in panic, better to write than to be denied */
	old_enforce = enforcing_enabled(&selinux_state);
	enforcing_set(&selinux_state, false);

	root_cred = prepare_kernel_cred(NULL);
	if (!root_cred) {
		pr_err("Unable to prepare kernel cred\n");
		goto restore_selinux;
	}
	saved_cred = override_creds(root_cred);

	f = filp_open(LOG_FILE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(f)) {
		ret = PTR_ERR(f);
		pr_err("Unable to open log file, ret = %d\n", ret);
		goto revert_cred;
	}

	kmsg_dump_rewind(&logstore_dumper);
	while (kmsg_dump_get_line(&logstore_dumper, false, buf, sizeof(buf), &len)) {
		ret = kernel_write(f, buf, len, &f->f_pos);
		if (ret != (ssize_t)len) {
			pr_err("Unable to write log file, ret = %d\n", ret);
			goto close_file;
		}
	}

	ret = vfs_fsync(f, 0);
	if (ret)
		pr_err("Unable to sync log file, ret = %d\n", ret);
	else
		pr_info("Panic logstore is done.\n");

close_file:
	filp_close(f, NULL);
revert_cred:
	revert_creds(saved_cred);
	put_cred(root_cred);
restore_selinux:
	enforcing_set(&selinux_state, old_enforce);
}

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

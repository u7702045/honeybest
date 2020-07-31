/*
 * Security Hash Locking Module
 *
 * Copyright 2020 Moxa Inc.
 *
 * Author: Jimmy Chen <jimmy.chen@moxa.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/init.h>
#include <linux/kd.h>
#include <linux/kernel.h>
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/lsm_hooks.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <net/net_namespace.h>
#include <net/netlabel.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>	/* for network interface checks */
#include <net/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <net/af_unix.h>	/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/audit.h>
#include <linux/lsm_audit.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/syslog.h>
#include <linux/user_namespace.h>
#include <linux/export.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <net/xfrm.h>
#include <linux/xfrm.h>
#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/path.h>
#include <linux/string_helpers.h>
#include <linux/list.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <crypto/algapi.h>
#include "honeybest.h"
#include "creds.h"
#include "files.h"
#include "socket.h"
#include "tasks.h"
#include "inode.h"
#include "path.h"
#include "sb.h"
#include "kmod.h"
#include "notify.h"

#ifdef CONFIG_SECURITY_HONEYBEST
static int enabled = IS_ENABLED(CONFIG_SECURITY_HONEYBEST_ENABLED);
static int locking = 0;		// detect mode
static int interact = 0;	// interaction mode
static int level = 1;		// fine grain granularity
static unsigned long task_seq = 0;

extern hb_binprm_ll hb_binprm_list_head;
extern hb_file_ll hb_file_list_head;
extern hb_socket_ll hb_socket_list_head;
extern hb_task_ll hb_task_list_head;
extern hb_inode_ll hb_inode_list_head;
extern hb_path_ll hb_path_list_head;
extern hb_sb_ll hb_sb_list_head;
extern hb_kmod_ll hb_kmod_list_head;
extern hb_notify_ll hb_notify_list_head;

extern struct proc_dir_entry *hb_proc_file_entry;
extern struct proc_dir_entry *hb_proc_task_entry;
extern struct proc_dir_entry *hb_proc_socket_entry;
extern struct proc_dir_entry *hb_proc_binprm_entry;
extern struct proc_dir_entry *hb_proc_inode_entry;
extern struct proc_dir_entry *hb_proc_path_entry;
extern struct proc_dir_entry *hb_proc_sb_entry;
extern struct proc_dir_entry *hb_proc_kmod_entry;
extern struct proc_dir_entry *hb_proc_notify_entry;


/* attach to each trigger function so that we can trace all system activity */
typedef struct hb_track_t { 
	kuid_t uid;
	unsigned long tsid;	// task sequence id
	unsigned int prev_fid;	// previous track clue across function
	unsigned int curr_fid;	// current track clue across function
} hb_track_info;

MODULE_LICENSE("GPL");

#ifdef CONFIG_SYSCTL
static int zero;
static int one = 1;
static int two = 2;

static struct ctl_path honeybest_sysctl_path[] = {
	{ .procname = "kernel", },
	{ .procname = "honeybest", },
	{ }
};

static struct ctl_table honeybest_sysctl_table[] = {
	{
		.procname       = "enabled",
		.data           = &enabled,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &zero,
		.extra2         = &one,
	},
	{
		.procname       = "locking",
		.data           = &locking,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &zero,
		.extra2         = &one,
	},
	{
		.procname       = "interact",
		.data           = &interact,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &zero,
		.extra2         = &one,
	},
	{
		.procname       = "level",
		.data           = &level,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &one,
		.extra2         = &two,
	},
	{ }
};
#endif

int free_honeybest_tracker(const struct task_struct *task)
{
	int err = 0;
	hb_track_info *sec = NULL;

	if (task->cred->security != NULL) {
		sec = task->cred->security;
		kfree(sec);
	}
	return err;
}

int inject_honeybest_tracker(const struct task_struct *task, unsigned int fid)
{
	int err = 0;
	hb_track_info *sec = NULL;
	struct cred *cred = (struct cred *) task->cred;
       	kuid_t uid = task->cred->uid;

	if (task->cred->security == NULL) {
		sec = (hb_track_info *)kmalloc(sizeof(hb_track_info), GFP_KERNEL);
		if (sec != NULL) {
			sec->tsid = task_seq++;
			sec->curr_fid = fid;
			sec->uid = uid;
			cred->security = (hb_track_info *)sec;
		}
		else {
			//printk(KERN_WARNING "honeybest security malloc failure\n");
			err = -ENOMEM;
		}
	}

	if (task->cred->security != NULL) {
		sec = task->cred->security;
		if (sec->curr_fid != fid) {
			sec->prev_fid = sec->curr_fid;
			sec->curr_fid = fid;
		}
	       	//printk(KERN_DEBUG "%s, prev %u, curr %u\n", __FUNCTION__, sec->prev_fid, sec->curr_fid);
	}
	return err;
}

static int open_notify_proc(struct inode *inode, struct  file *file) {
	  return single_open(file, read_notify_record, NULL);
}

static const struct file_operations hb_proc_notify_fops = {
	.open  = open_notify_proc,
	.read  = seq_read,
	//.write  = write_notify_record,
	.llseek  = seq_lseek,
	.release = single_release,
};


static int open_file_proc(struct inode *inode, struct  file *file) {
	  return single_open(file, read_file_record, NULL);
}

static const struct file_operations hb_proc_file_fops = {
	.open  = open_file_proc,
	.read  = seq_read,
	.write  = write_file_record,
	.llseek  = seq_lseek,
	.release = single_release,
};

static int open_task_proc(struct inode *inode, struct  file *file) {
	  return single_open(file, read_task_record, NULL);
}

static const struct file_operations hb_proc_task_fops = {
	.open  = open_task_proc,
	.read  = seq_read,
	.write  = write_task_record,
	.llseek  = seq_lseek,
	.release = single_release,
};

static int open_socket_proc(struct inode *inode, struct  file *file) {
	  return single_open(file, read_socket_record, NULL);
}

static const struct file_operations hb_proc_socket_fops = {
	.open  = open_socket_proc,
	.read  = seq_read,
	.write  = write_socket_record,
	.llseek  = seq_lseek,
	.release = single_release,
};

static int open_binprm_proc(struct inode *inode, struct  file *file) {
	  return single_open(file, read_binprm_record, NULL);
}

static const struct file_operations hb_proc_binprm_fops = {
	.open  = open_binprm_proc,
	.read  = seq_read,
	.write  = write_binprm_record,
	.llseek  = seq_lseek,
	.release = single_release,
};

static int open_inode_proc(struct inode *inode, struct  file *file) {
	  return single_open(file, read_inode_record, NULL);
}

static const struct file_operations hb_proc_inode_fops = {
	.open  = open_inode_proc,
	.read  = seq_read,
	.write  = write_inode_record,
	.llseek  = seq_lseek,
	.release = single_release,
};

static int open_path_proc(struct inode *inode, struct  file *file) {
	  return single_open(file, read_path_record, NULL);
}

static const struct file_operations hb_proc_path_fops = {
	.open  = open_path_proc,
	.read  = seq_read,
	.write  = write_path_record,
	.llseek  = seq_lseek,
	.release = single_release,
};

static int open_sb_proc(struct inode *inode, struct  file *file) {
	  return single_open(file, read_sb_record, NULL);
}

static const struct file_operations hb_proc_sb_fops = {
	.open  = open_sb_proc,
	.read  = seq_read,
	.write  = write_sb_record,
	.llseek  = seq_lseek,
	.release = single_release,
};

static int open_kmod_proc(struct inode *inode, struct  file *file) {
	  return single_open(file, read_kmod_record, NULL);
}

static const struct file_operations hb_proc_kmod_fops = {
	.open  = open_kmod_proc,
	.read  = seq_read,
	.write  = write_kmod_record,
	.llseek  = seq_lseek,
	.release = single_release,
};

static void __init honeybest_init_sysctl(void)
{
       	struct proc_dir_entry *honeybest_dir = proc_mkdir("honeybest", NULL);

#ifdef CONFIG_SYSCTL
	if (!register_sysctl_paths(honeybest_sysctl_path, honeybest_sysctl_table))
		panic("HoneyBest: sysctl registration failed.\n");
#endif

	/* notification event linked list */
	INIT_LIST_HEAD(&hb_notify_list_head.list);

	/* binary execution tracing */
	INIT_LIST_HEAD(&hb_binprm_list_head.list);

	/* file rwx tracing */
	INIT_LIST_HEAD(&hb_file_list_head.list);

	/* socket tracing */
	INIT_LIST_HEAD(&hb_socket_list_head.list);

	/* task tracing */
	INIT_LIST_HEAD(&hb_task_list_head.list);

	/* inode tracing */
	INIT_LIST_HEAD(&hb_inode_list_head.list);

	/* path tracing */
	INIT_LIST_HEAD(&hb_path_list_head.list);

	/* super block tracing */
	INIT_LIST_HEAD(&hb_sb_list_head.list);

	/* kernel modules tracing */
	INIT_LIST_HEAD(&hb_kmod_list_head.list);

	/* prepare notify proc entry */
	hb_proc_notify_entry = proc_create("notify", 0666, honeybest_dir, &hb_proc_notify_fops);
	if (!hb_proc_notify_entry) {
		printk(KERN_INFO "Error creating honeybest notify entry");
	}

	/* prepare file proc entry */
	hb_proc_file_entry = proc_create("files", 0666, honeybest_dir, &hb_proc_file_fops);
	if (!hb_proc_file_entry) {
		printk(KERN_INFO "Error creating honeybest file proc entry");
	}

	/* prepare task proc entry */
	hb_proc_task_entry = proc_create("tasks", 0666, honeybest_dir, &hb_proc_task_fops);
	if (!hb_proc_task_entry) {
		printk(KERN_INFO "Error creating honeybest task proc entry");
	}

	/* prepare socket proc entry */
	hb_proc_socket_entry = proc_create("socket", 0666, honeybest_dir, &hb_proc_socket_fops);
	if (!hb_proc_socket_entry) {
		printk(KERN_INFO "Error creating honeybest socket proc entry");
	}

	/* prepare binprm proc entry */
	hb_proc_binprm_entry = proc_create("binprm", 0666, honeybest_dir, &hb_proc_binprm_fops);
	if (!hb_proc_binprm_entry) {
		printk(KERN_INFO "Error creating honeybest binprm proc entry");
	}

	/* prepare inode proc entry */
	hb_proc_inode_entry = proc_create("inode", 0666, honeybest_dir, &hb_proc_inode_fops);
	if (!hb_proc_inode_entry) {
		printk(KERN_INFO "Error creating honeybest inode proc entry");
	}

	/* prepare path proc entry */
	hb_proc_path_entry = proc_create("path", 0666, honeybest_dir, &hb_proc_path_fops);
	if (!hb_proc_path_entry) {
		printk(KERN_INFO "Error creating honeybest path proc entry");
	}

	/* prepare sb proc entry */
	hb_proc_sb_entry = proc_create("sb", 0666, honeybest_dir, &hb_proc_sb_fops);
	if (!hb_proc_sb_entry) {
		printk(KERN_INFO "Error creating honeybest sb proc entry");
	}

	/* prepare kmod proc entry */
	hb_proc_kmod_entry = proc_create("kmod", 0666, honeybest_dir, &hb_proc_kmod_fops);
	if (!hb_proc_kmod_entry) {
		printk(KERN_INFO "Error creating honeybest kmod proc entry");
	}

}

static int honeybest_binder_set_context_mgr(struct task_struct *mgr)
{
	return 0;
}

static int honeybest_binder_transaction(struct task_struct *from,
                                      struct task_struct *to)
{
	return 0;
}

static int honeybest_binder_transfer_binder(struct task_struct *from,
                                          struct task_struct *to)
{
	return 0;
}

static int honeybest_binder_transfer_file(struct task_struct *from,
                                        struct task_struct *to,
                                        struct file *file)
{
	return 0;
}

static int honeybest_ptrace_access_check(struct task_struct *child,
                                     unsigned int mode)
{
	int err = 0;

	if (!enabled)
		err = -EOPNOTSUPP;

	return err;
}

static int honeybest_ptrace_traceme(struct task_struct *parent)
{
	int err = 0;

	if (!enabled)
		err = -EOPNOTSUPP;

	return err;
}

static int honeybest_capget(struct task_struct *target, kernel_cap_t *effective,
                          kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	return 0;
}

static int honeybest_capset(struct cred *new, const struct cred *old,
                          const kernel_cap_t *effective,
                          const kernel_cap_t *inheritable,
                          const kernel_cap_t *permitted)
{
	return 0;
}

static int honeybest_capable(const struct cred *cred, struct user_namespace *ns,
                           int cap, int audit)
{
	return 0;
}

static int honeybest_quotactl(int cmds, int type, int id, struct super_block *sb)
{
	return 0;
}

static int honeybest_quota_on(struct dentry *dentry)
{
	return 0;
}

static int honeybest_syslog(int type)
{
	return 0;
}

static int honeybest_vm_enough_memory(struct mm_struct *mm, long pages)
{
	return 0;
}

static int honeybest_bprm_set_creds(struct linux_binprm *bprm)
{
	int err = 0;
       	const struct task_struct *task = current;
	char digest[SHA1_HONEYBEST_DIGEST_SIZE];
	hb_binprm_ll *record = NULL;
	char *pathname;

	if (!enabled)
		return err;

	pathname = kstrdup_quotable_file(bprm->file, GFP_KERNEL);

	if (allow_file_whitelist(pathname)) {
		return err;
	}

	// logic of xattr need to validate?
	memset(digest, '\0', SHA1_HONEYBEST_DIGEST_SIZE);
	lookup_binprm_digest(bprm->file, digest);

	record = search_binprm_record(HL_BPRM_SET_CREDS, task->cred->uid.val, pathname, digest);

	if (record) {
	       	printk(KERN_INFO "Found set creds record func=%u, hash=[%s]\n", record->fid, record->digest);
	}
	else {

		if (locking == 0) 
			err = add_binprm_record(HL_BPRM_SET_CREDS, task->cred->uid.val , pathname, digest, interact);

		if (locking == 1) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}

	return err;
}


static int honeybest_bprm_secureexec(struct linux_binprm *bprm)
{
	int err = 0;

	if (!enabled)
		return err;

	return err;
}

/* Derived from fs/exec.c:flush_old_files. */
static inline void flush_unauthorized_files(const struct cred *cred,
                                            struct files_struct *files)
{
	return ;
}

static void honeybest_bprm_committing_creds(struct linux_binprm *bprm)
{
	return ;
}

static void honeybest_bprm_committed_creds(struct linux_binprm *bprm)
{
}

static int honeybest_sb_alloc_security(struct super_block *sb)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;

	return err;
}

static void honeybest_sb_free_security(struct super_block *sb)
{
       	const struct task_struct *task = current;
	int err = 0;

	if (!enabled)
		return;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return;
}
	
static int honeybest_sb_copy_data(char *orig, char *copy)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_SB_COPY_DATA))
	       	err = -ENOMEM;

	return err;
}

static int honeybest_sb_remount(struct super_block *sb, void *data)
{
	int err = 0;
	struct security_mnt_opts opts;
	char **mount_options;
	int *flags;
	int i = 0;
	char *na = "N/A";
	hb_sb_ll *record = NULL;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;

	security_init_mnt_opts(&opts);
	mount_options = opts.mnt_opts;
	flags = opts.mnt_opts_flags;
	for (i = 0; i < opts.num_mnt_opts; i++) {
		record = search_sb_record(HL_SB_REMOUNT, task->cred->uid.val, sb->s_id, (char *)sb->s_type->name, na, na, 0);

		if (record) {
			printk(KERN_INFO "Found sb remount record func=%u, uid %u, s_id=%s, type name=%s\n", record->fid, record->uid, record->s_id, record->name);
		}
		else {
			if (locking == 0) 
				err = add_sb_record(HL_SB_REMOUNT, task->cred->uid.val, sb->s_id, (char *)sb->s_type->name, na, na, 0, interact);

			if (locking == 1)
				err = -EOPNOTSUPP;
		}
	}
	return err;
}

static int honeybest_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_SB_KERN_MOUNT))
	       	err = -ENOMEM;

	// less info compare to sb_mount

	return err;
}

static int honeybest_sb_statfs(struct dentry *dentry)
{
	int err = 0;
       	const struct task_struct *task = current;
       	struct super_block *sb = dentry->d_sb;
	char *na = "N/A";
	hb_sb_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_SB_STATFS))
	       	err = -ENOMEM;

	record = search_sb_record(HL_SB_STATFS, task->cred->uid.val, sb->s_id, (char *)sb->s_type->name, na, na, 0);

	if (record) {
		printk(KERN_INFO "Found sb statfs record func=%u, uid %u, s_id=%s, type name=%s\n", record->fid, record->uid, record->s_id, record->name);
	}
	else {
		if (locking == 0) 
			err = add_sb_record(HL_SB_STATFS, task->cred->uid.val, sb->s_id, (char *)sb->s_type->name, na, na, 0, interact);

		if (locking == 1)
			err = -EOPNOTSUPP;
	}
	return err;
}

static int honeybest_mount(const char *dev_name,
                         const struct path *path,
                         const char *type,
                         unsigned long flags,
                         void *data)
{
	int err = 0;
       	const struct task_struct *task = current;
	char *na = "N/A";
	hb_sb_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_SB_MOUNT))
	       	err = -ENOMEM;

	record = search_sb_record(HL_SB_MOUNT, task->cred->uid.val, na, (char *)na, (char *)dev_name, (char *)type, flags);

	if (record) {
		printk(KERN_INFO "Found sb mount record func=%u, uid %u, dev_name=%s, type name=%s, flags=%d\n", record->fid, record->uid, record->dev_name, record->type, record->flags);
	}
	else {
		if (locking == 0) 
			err = add_sb_record(HL_SB_MOUNT, task->cred->uid.val, na, na, (char *)dev_name, (char *)type, flags, interact);

		if (locking == 1)
			err = -EOPNOTSUPP;
	}

	return err;
}

static int honeybest_umount(struct vfsmount *mnt, int flags)
{
	int err = 0;
       	const struct task_struct *task = current;
       	struct super_block *sb = mnt->mnt_sb;
	char *na = "N/A";
	hb_sb_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_SB_UMOUNT))
	       	err = -ENOMEM;

	record = search_sb_record(HL_SB_UMOUNT, task->cred->uid.val, sb->s_id, (char *)sb->s_type->name, na, na, flags);

	if (record) {
		printk(KERN_INFO "Found sb umount record func=%u, uid %u, dev_name=%s, type name=%s, flags=%d\n", record->fid, record->uid, record->dev_name, record->type, record->flags);
	}
	else {
		if (locking == 0) 
			err = add_sb_record(HL_SB_UMOUNT, task->cred->uid.val, sb->s_id, (char *)sb->s_type->name, na, na, flags, interact);

		if (locking == 1)
			err = -EOPNOTSUPP;
	}

	return err;
}

static int honeybest_inode_alloc_security(struct inode *inode)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;

	return err;
}

static void honeybest_inode_free_security(struct inode *inode)
{
       	const struct task_struct *task = current;
	int err = 0;

	if (!enabled)
		return;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return;
}

static int honeybest_dentry_init_security(struct dentry *dentry, int mode,
                                        const struct qstr *name, void **ctx,
                                        u32 *ctxlen)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_DENTRY_INIT_SEC))
	       	err = -ENOMEM;

	return err;
}


static int honeybest_path_unlink(const struct path *dir, struct dentry *dentry)
{

	int err = 0;
       	const struct task_struct *task = current;
	struct path source = { dir->mnt, dentry };
	char *source_pathname = NULL;
       	char *target_pathname = "N/A";
	char *source_buff = NULL;
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_PATH_UNLINK))
	       	err = -ENOMEM;

	/* extract full path */
	source_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	source_pathname = d_absolute_path(&source, source_buff, PATH_MAX);

	if (source_buff == NULL) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!source_pathname) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	if (allow_file_whitelist(source_pathname)) {
		goto out1;
	}

	record = search_path_record(HL_PATH_UNLINK, task->cred->uid.val, 0, source_pathname, target_pathname, 0, 0, 0);

	if (record) {
	       	printk(KERN_INFO "Found path unlink record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->source_pathname, record->target_pathname);
	}
	else {
		if (locking == 0) 
			err = add_path_record(HL_PATH_UNLINK, task->cred->uid.val, 0, source_pathname, target_pathname, 0, 0, 0, interact);

		if (locking == 1)
			err = -EOPNOTSUPP;
	}

out1:
	kfree(source_buff);
out:
	return err;
}


static int honeybest_path_mkdir(const struct path *dir, struct dentry *dentry,
			       umode_t mode)
{

	int err = 0;
       	const struct task_struct *task = current;
	struct path source = { dir->mnt, dentry };
	char *source_pathname = NULL;
       	char *target_pathname = "N/A";
	char *source_buff = NULL;
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_PATH_MKDIR))
	       	err = -ENOMEM;

	/* extract full path */
	source_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	source_pathname = d_absolute_path(&source, source_buff, PATH_MAX);

	if (!source_pathname) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!source_pathname) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	if (allow_file_whitelist(source_pathname)) {
		goto out1;
	}

	record = search_path_record(HL_PATH_MKDIR, task->cred->uid.val, mode, source_pathname, target_pathname, 0, 0, 0);

	if (record) {
	       	printk(KERN_INFO "Found path mkdir record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->source_pathname, record->target_pathname);
	}
	else {
		if (locking == 0) 
			err = add_path_record(HL_PATH_MKDIR, task->cred->uid.val, mode, source_pathname, target_pathname, 0, 0, 0, interact);

		if (locking == 1)
			err = -EOPNOTSUPP;
	}

out1:
	kfree(source_buff);
out:
	return err;
}

static int honeybest_path_rmdir(const struct path *dir, struct dentry *dentry)
{

	int err = 0;
       	const struct task_struct *task = current;
	struct path source = { dir->mnt, dentry };
	char *source_pathname = NULL;
       	char *target_pathname = "N/A";
	char *source_buff = NULL;
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_PATH_RMDIR))
	       	err = -ENOMEM;

	/* extract full path */
	source_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	source_pathname = d_absolute_path(&source, source_buff, PATH_MAX);

	if (!source_buff) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!source_pathname) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	record = search_path_record(HL_PATH_RMDIR, task->cred->uid.val, 0, source_pathname, target_pathname, 0, 0, 0);

	if (record) {
	       	printk(KERN_INFO "Found path rmdir record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->source_pathname, record->target_pathname);
	}
	else {
		if (locking == 0) 
			err = add_path_record(HL_PATH_RMDIR, task->cred->uid.val, 0, source_pathname, target_pathname, 0, 0, 0, interact);

		if (locking == 1)
			err = -EOPNOTSUPP;
	}

out1:
	kfree(source_buff);
out:
	return err;
}

static int honeybest_path_mknod(const struct path *dir, struct dentry *dentry,
			       umode_t mode, unsigned int dev)
{

	int err = 0;
       	const struct task_struct *task = current;
	struct path source = { dir->mnt, dentry };
	char *source_pathname = NULL;
       	char *target_pathname = "N/A";
	char *source_buff = NULL;
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_PATH_MKNOD))
	       	err = -ENOMEM;

	/* extract full path */
	source_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	source_pathname = d_absolute_path(&source, source_buff, PATH_MAX);

	if (!source_buff) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!source_pathname) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	if (allow_file_whitelist(source_pathname)) {
		goto out1;
	}

	record = search_path_record(HL_PATH_MKNOD, task->cred->uid.val, mode, source_pathname, target_pathname, 0, 0, dev);

	if (record) {
	       	printk(KERN_INFO "Found path mknod record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->source_pathname, record->target_pathname);
	}
	else {
		if (locking == 0) 
			err = add_path_record(HL_PATH_MKNOD, task->cred->uid.val, mode, source_pathname, target_pathname, 0, 0, dev, interact);

		if (locking == 1)
			err = -EOPNOTSUPP;
	}

out1:
	kfree(source_buff);
out:
	return err;
}

static int honeybest_path_truncate(const struct path *path)
{
	int err = 0;
       	const struct task_struct *task = current;
	char *source_pathname = NULL;
       	char *target_pathname = "N/A";
	char *source_buff = NULL;
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_PATH_TRUNCATE))
	       	err = -ENOMEM;

	/* extract full path */
	source_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	source_pathname = d_absolute_path(path, source_buff, PATH_MAX);

	if (source_buff == NULL) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!source_pathname) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	if (allow_file_whitelist(source_pathname)) {
		goto out1;
	}

	record = search_path_record(HL_PATH_TRUNCATE, task->cred->uid.val, 0, source_pathname, target_pathname, 0, 0, 0);

	if (record) {
	       	printk(KERN_INFO "Found path truncate record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->source_pathname, record->target_pathname);
	}
	else {
		if (locking == 0) 
			err = add_path_record(HL_PATH_TRUNCATE, task->cred->uid.val, 0, source_pathname, target_pathname, 0, 0, 0, interact);

		if (locking == 1)
			err = -EOPNOTSUPP;
	}

out1:
	kfree(source_buff);
out:
	return err;
}

static int honeybest_path_symlink(const struct path *dir, struct dentry *dentry,
				 const char *old_name)
{

	int err = 0;
       	const struct task_struct *task = current;
	struct path target = { dir->mnt, dentry };
	char *source_pathname = (char *)old_name;
       	char *target_pathname = NULL;
	char *target_buff = NULL;
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_PATH_SYMLINK))
	       	err = -ENOMEM;

	/* extract full path */
	target_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	target_pathname = d_absolute_path(&target, target_buff, PATH_MAX);

	if (target_buff == NULL) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!target_pathname) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	record = search_path_record(HL_PATH_SYMLINK, task->cred->uid.val, 0, source_pathname, target_pathname, 0, 0, 0);

	if (record) {
	       	printk(KERN_INFO "Found path symlink record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->source_pathname, record->target_pathname);
	}
	else {
		if (locking == 0) 
			err = add_path_record(HL_PATH_SYMLINK, task->cred->uid.val, 0, source_pathname, target_pathname, 0, 0, 0, interact);

		if (locking == 1)
			err = -EOPNOTSUPP;
	}

out1:
	kfree(target_buff);
out:
	return err;
}


static int honeybest_path_link(struct dentry *old_dentry, const struct path *new_dir,
			      struct dentry *new_dentry)
{
	int err = 0;
       	const struct task_struct *task = current;
	struct path source = { new_dir->mnt, new_dentry };
	struct path target = { new_dir->mnt, old_dentry };
	char *source_pathname = NULL;
       	char *target_pathname = NULL;
	char *source_buff = NULL;
	char *target_buff = NULL;
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_PATH_LINK))
	       	err = -ENOMEM;

	/* extract full path */
	source_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	target_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	source_pathname = d_absolute_path(&source, source_buff, PATH_MAX);
	target_pathname = d_absolute_path(&target, target_buff, PATH_MAX);

	if (source_buff == NULL) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (target_buff == NULL) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	if (!source_pathname) {
		err = -EOPNOTSUPP;
		goto out2;
	}

	if (!target_pathname) {
		err = -EOPNOTSUPP;
		goto out2;
	}

	if (allow_file_whitelist(source_pathname)) {
		goto out2;
	}

	record = search_path_record(HL_PATH_LINK, task->cred->uid.val, 0, source_pathname, target_pathname, 0, 0, 0);

	if (record) {
	       	printk(KERN_INFO "Found path link record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->source_pathname, record->target_pathname);
	}
	else {
		if (locking == 0) 
			err = add_path_record(HL_PATH_LINK, task->cred->uid.val, 0, source_pathname, target_pathname, 0, 0, 0, interact);

		if (locking == 1)
			err = -EOPNOTSUPP;
	}
out2:
	kfree(target_buff);
out1:
	kfree(source_buff);
out:
	return err;
}

static int honeybest_path_rename(const struct path *old_dir, struct dentry *old_dentry,
				const struct path *new_dir, struct dentry *new_dentry)
{
	int err = 0;
       	const struct task_struct *task = current;
	struct path target = { new_dir->mnt, new_dentry };
	struct path source = { old_dir->mnt, old_dentry };
	char *source_pathname = NULL;
       	char *target_pathname = NULL;
	char *source_buff = NULL;
	char *target_buff = NULL;
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_PATH_RENAME))
	       	err = -ENOMEM;

	/* extract full path */
	source_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	target_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	source_pathname = d_absolute_path(&source, source_buff, PATH_MAX);
	target_pathname = d_absolute_path(&target, target_buff, PATH_MAX);

	if (source_buff == NULL) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (target_buff == NULL) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	if (!source_pathname) {
		err = -EOPNOTSUPP;
		goto out2;
	}

	if (!target_pathname) {
		err = -EOPNOTSUPP;
		goto out2;
	}

	record = search_path_record(HL_PATH_RENAME, task->cred->uid.val, 0, source_pathname, target_pathname, 0, 0, 0);

	if (record) {
	       	printk(KERN_INFO "Found path rename record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->source_pathname, record->target_pathname);
	}
	else {
		if (locking == 0) 
			err = add_path_record(HL_PATH_RENAME, task->cred->uid.val, 0, source_pathname, target_pathname, 0, 0, 0, interact);

		if (locking == 1)
			err = -EOPNOTSUPP;
	}

out2:
	kfree(target_buff);
out1:
	kfree(source_buff);
out:
	return err;
}

static int honeybest_path_chmod(const struct path *path, umode_t mode)
{
	int err = 0;
       	const struct task_struct *task = current;
	char *source_pathname = NULL;
       	char *target_pathname = "N/A";
	char *source_buff = NULL;
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_PATH_CHMOD))
	       	err = -ENOMEM;

	/* extract full path */
	source_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	source_pathname = d_absolute_path(path, source_buff, PATH_MAX);

	if (source_buff == NULL) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!source_pathname) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	record = search_path_record(HL_PATH_CHMOD, task->cred->uid.val, mode, source_pathname, target_pathname, 0, 0, 0);

	if (record) {
	       	printk(KERN_INFO "Found path chmod record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->source_pathname, record->target_pathname);
	}
	else {
		if (locking == 0) 
			err = add_path_record(HL_PATH_CHMOD, task->cred->uid.val, mode, source_pathname, target_pathname, 0, 0, 0, interact);

		if (locking == 1)
			err = -EOPNOTSUPP;
	}

out1:
	kfree(source_buff);
out:
	return err;
}

static int honeybest_path_chown(const struct path *path, kuid_t uid, kgid_t gid)
{
	int err = 0;
       	const struct task_struct *task = current;
	char *source_pathname = NULL;
       	char *target_pathname = "N/A";
	char *source_buff = NULL;
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_PATH_CHOWN))
	       	err = -ENOMEM;

	/* extract full path */
	source_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	source_pathname = d_absolute_path(path, source_buff, PATH_MAX);

	if (source_buff == NULL) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!source_pathname) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	record = search_path_record(HL_PATH_CHOWN, task->cred->uid.val, 0, source_pathname, target_pathname, uid.val, gid.val, 0);

	if (record) {
	       	printk(KERN_INFO "Found path chmod record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->source_pathname, record->target_pathname);
	}
	else {
		if (locking == 0) 
			err = add_path_record(HL_PATH_CHOWN, task->cred->uid.val, 0, source_pathname, target_pathname, uid.val, gid.val, 0, interact);

		if (locking == 1)
			err = -EOPNOTSUPP;
	}

out1:
	kfree(source_buff);
out:
	return err;
}

static int honeybest_inode_init_security(struct inode *inode, struct inode *dir,
                                       const struct qstr *qstr,
                                       const char **name,
                                       void **value, size_t *len)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_INODE_INIT_SEC))
	       	err = -ENOMEM;

	return -EOPNOTSUPP;
}

static int honeybest_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_INODE_CREATE))
	       	err = -ENOMEM;

        return err;
}

static int honeybest_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_INODE_LINK))
	       	err = -ENOMEM;

        return err;
}

static int honeybest_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_INODE_UNLINK))
	       	err = -ENOMEM;

        return err;
}

static int honeybest_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_INODE_SYMLINK))
	       	err = -ENOMEM;

        return err;
}

static int honeybest_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mask)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_INODE_MKDIR))
	       	err = -ENOMEM;

        return err;
}

static int honeybest_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;

        return err;
}

static int honeybest_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;

        return err;
}

static int honeybest_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
                                struct inode *new_inode, struct dentry *new_dentry)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;

        return err;
}

static int honeybest_inode_readlink(struct dentry *dentry)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;

        return err;
}

static int honeybest_inode_follow_link(struct dentry *dentry, struct inode *inode,
                                     bool rcu)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;

        return err;
}

static int honeybest_inode_permission(struct inode *inode, int mask)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;

        return err;
}

static int honeybest_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;

        return err;
}

static int honeybest_inode_getattr(const struct path *path)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;

        return err;
}

static int honeybest_inode_setxattr(struct dentry *dentry, const char *name,
                                  const void *value, size_t size, int flags)
{
	int err = 0;
       	const struct task_struct *task = current;
	const struct qstr *d_name = &dentry->d_name;
	const unsigned char *dname = d_name->name;
	hb_inode_ll *record;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_INODE_SETXATTR))
	       	err = -ENOMEM;

	record = search_inode_record(HL_INODE_SETXATTR, task->cred->uid.val, (char *)name, (char *)dname, 0);

	if (record) {
		printk(KERN_INFO "Found inode setxattr name %s, dname %s\n", name, dname);
	}
	else {

		if (locking == 0) 
			err = add_inode_record(HL_INODE_SETXATTR, task->cred->uid.val, (char *)name, (char *)dname, 0, interact);

		if (locking == 1) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}

        return err;
}

static void honeybest_inode_post_setxattr(struct dentry *dentry, const char *name,
                                        const void *value, size_t size,
                                        int flags)
{
	return ;
}

static int honeybest_inode_getxattr(struct dentry *dentry, const char *name)
{
	int err = 0;
       	const struct task_struct *task = current;
	const struct qstr *d_name = &dentry->d_name;
	const unsigned char *dname = d_name->name;
	hb_inode_ll *record;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_INODE_GETXATTR))
	       	err = -ENOMEM;

	record = search_inode_record(HL_INODE_GETXATTR, task->cred->uid.val, (char *)name, (char *)dname, 0);

	if (record) {
		printk(KERN_INFO "Found inode getxattr name %s, dname %s\n", name, dname);
	}
	else {

		if (locking == 0) 
			err = add_inode_record(HL_INODE_GETXATTR, task->cred->uid.val, (char *)name, (char *)dname, 0, interact);

		if (locking == 1) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}

        return err;
}
static int honeybest_inode_listxattr(struct dentry *dentry)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;

        return err;
}

static int honeybest_inode_removexattr(struct dentry *dentry, const char *name)
{
	int err = 0;
       	const struct task_struct *task = current;
	const struct qstr *d_name = &dentry->d_name;
	const unsigned char *dname = d_name->name;
	hb_inode_ll *record;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, HL_INODE_REMOVEXATTR))
	       	err = -ENOMEM;

	record = search_inode_record(HL_INODE_REMOVEXATTR, task->cred->uid.val, (char *)name, (char *)dname, 0);

	if (record) {
		printk(KERN_INFO "Found inode removexattr name %s, dname %s\n", name, dname);
	}
	else {

		if (locking == 0) 
			err = add_inode_record(HL_INODE_REMOVEXATTR, task->cred->uid.val, (char *)name, (char *)dname, 0, interact);

		if (locking == 1) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}

        return err;
}


static int honeybest_inode_getsecurity(struct inode *inode, const char *name, void **buffer, bool alloc)
{
	return -EOPNOTSUPP;
}

static int honeybest_inode_setsecurity(struct inode *inode, const char *name,
                                     const void *value, size_t size, int flags)
{
	return -EOPNOTSUPP;
}

static int honeybest_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
	return 0;
}

static void honeybest_inode_getsecid(struct inode *inode, u32 *secid)
{
	*secid = 0;
}



static int honeybest_file_permission(struct file *file, int mask)
{
	return 0;
}

static int honeybest_file_alloc_security(struct file *file)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;

	return err;
}

static void honeybest_file_free_security(struct file *file)
{
       	const struct task_struct *task = current;
	int err = 0;

	if (!enabled)
		return;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;

	return;
}

static int honeybest_file_ioctl(struct file *file, unsigned int cmd,
                              unsigned long arg)
{
	return 0;
}

static int honeybest_mmap_addr(unsigned long addr)
{
	return 0;
}

static int honeybest_mmap_file(struct file *file, unsigned long reqprot,
                             unsigned long prot, unsigned long flags)
{
	return 0;
}

static int honeybest_file_mprotect(struct vm_area_struct *vma,
                                 unsigned long reqprot,
                                 unsigned long prot)
{
	return 0;
}

static int honeybest_file_lock(struct file *file, unsigned int cmd)
{
	return 0;
}

static int honeybest_file_fcntl(struct file *file, unsigned int cmd,
                              unsigned long arg)
{
	return 0;
}

static void honeybest_file_set_fowner(struct file *file)
{
}

static int honeybest_file_send_sigiotask(struct task_struct *tsk,
                                       struct fown_struct *fown, int signum)
{
	return 0;
}

static int honeybest_file_receive(struct file *file)
{
	return 0;
}

static int honeybest_file_open(struct file *file, const struct cred *cred)
{
	int err = 0;
       	const struct task_struct *task = current;
	hb_file_ll *record = NULL;
	char *pathname = NULL;

	if (!enabled) {
		return err;
	}

	if (inject_honeybest_tracker(task, HL_FILE_OPEN))
	       	err = -ENOMEM;

	pathname = kstrdup_quotable_file(file, GFP_KERNEL);

	if (allow_file_whitelist(pathname)) {
		return err;
	}

	record = search_file_record(HL_FILE_OPEN, task->cred->uid.val, pathname);

	if (record) {
	       	printk(KERN_INFO "Found file open record func=%u, path=[%s]\n", record->fid, record->pathname);
	}
	else {

		if (locking == 0) 
			err = add_file_record(HL_FILE_OPEN, task->cred->uid.val , pathname, interact);

		if (locking == 1) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}

	if (pathname)
		kfree(pathname);

        return err;

}

static int honeybest_task_create(unsigned long clone_flags)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled) {
		return err;
	}

	if (inject_honeybest_tracker(task, 0))
		err = -ENOMEM;

        return err;
}

static int honeybest_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;

        return err;
}

static void honeybest_cred_free(struct cred *cred)
{
       	const struct task_struct *task = current;
	int err = 0;

	if (!enabled)
		return;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;

	return;
}


static int honeybest_cred_prepare(struct cred *new, const struct cred *old,
                                gfp_t gfp)
{
        return 0;
}

static void honeybest_cred_transfer(struct cred *new, const struct cred *old)
{
}

static int honeybest_kernel_act_as(struct cred *new, u32 secid)
{
	return 0;
}

static int honeybest_kernel_create_files_as(struct cred *new, struct inode *inode)
{
	int err = 0;

	if (!enabled) {
		return err;
	}

        return err;
}

static int honeybest_kernel_module_request(char *kmod_name)
{
	int err = 0;
       	const struct task_struct *task = current;
	hb_kmod_ll *record = NULL;

	if (!enabled) {
		return err;
	}

	if (inject_honeybest_tracker(task, HL_KMOD_REQ))
	       	err = -ENOMEM;

	printk(KERN_ERR "--------->%s, %s\n", __FUNCTION__, kmod_name);

	record = search_kmod_record(HL_KMOD_REQ, task->cred->uid.val, kmod_name);

	if (record) {
		printk(KERN_INFO "Found kmod record func=%u, uid %u, name=%s\n", record->fid, record->uid, record->name);
	}
	else {
		if (locking == 0) 
			err = add_kmod_record(HL_KMOD_REQ, task->cred->uid.val, kmod_name, interact);

		if (locking == 1)
			err = -EOPNOTSUPP;
	}

        return err;
}

static int honeybest_kernel_read_file(struct file *file, enum kernel_read_file_id id)
{
	return 0;
}

static int honeybest_task_setpgid(struct task_struct *p, pid_t pgid)
{
        return 0;
}

static int honeybest_task_getpgid(struct task_struct *p)
{
        return 0;
}

static int honeybest_task_getsid(struct task_struct *p)
{
        return 0;
}

static void honeybest_task_getsecid(struct task_struct *p, u32 *secid)
{
	*secid = 0;
}

static int honeybest_task_setnice(struct task_struct *p, int nice)
{
        return 0;
}

static int honeybest_task_setioprio(struct task_struct *p, int ioprio)
{
        return 0;
}

static int honeybest_task_getioprio(struct task_struct *p)
{
        return 0;
}

static int honeybest_task_setrlimit(struct task_struct *p, unsigned int resource,
                struct rlimit *new_rlim)
{
        return 0;
}

static int honeybest_task_setscheduler(struct task_struct *p)
{
        return 0;
}

static int honeybest_task_getscheduler(struct task_struct *p)
{
        return 0;
}

static int honeybest_task_movememory(struct task_struct *p)
{
        return 0;
}

static int honeybest_task_kill(struct task_struct *p, struct siginfo *info,
                                int sig, u32 secid)
{
	int err = 0;
       	const struct task_struct *task = current;
	hb_task_ll *record;

	if (!enabled) {
		return err;
	}

	if (inject_honeybest_tracker(task, HL_TASK_SIGNAL))
	       	err = -ENOMEM;

	record = search_task_record(HL_TASK_SIGNAL, task->cred->uid.val, info, sig, secid);

	if (record) {
		printk(KERN_INFO "Found task struct sig %d, secid %d, signo %d, errno %d\n", record->sig, record->secid, record->si_signo, record->si_errno);
	}
	else {

		if (locking == 0) 
			err = add_task_record(HL_TASK_SIGNAL, task->cred->uid.val, info->si_signo\
					, info->si_errno, sig, secid, interact);

		if (locking == 1) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}


        return err;

}

static int honeybest_task_wait(struct task_struct *p)
{
        return 0;
}

static void honeybest_task_to_inode(struct task_struct *p,
                                  struct inode *inode)
{

	if (!enabled)
	       	return;
}

static int honeybest_socket_create(int family, int type,
                                 int protocol, int kern)
{
	int err = 0;
       	const struct task_struct *task = current;
	hb_socket_ll *record;

	if (!enabled)
	       	return err;

	if (inject_honeybest_tracker(task, HL_SOCKET_CREATE))
		err = -ENOMEM;

	record = search_socket_record(HL_SOCKET_CREATE, task->cred->uid.val, family, type, protocol, kern, 0, 0 , 0, NULL, NULL, 0);

	if (record) {
	       	printk(KERN_INFO "Found socket create record func=%u, family %d, type %d, protocol %d, kern %d\n", record->fid, family, type, protocol, kern);
	}
	else {

		if (locking == 0) 
			err = add_socket_record(HL_SOCKET_CREATE, task->cred->uid.val, family, \
					type, protocol, kern, 0, 0, 0, 0, NULL, NULL, 0, interact);

		if (locking == 1)
			err = -EOPNOTSUPP;
	}

	return err;
}

static int honeybest_socket_post_create(struct socket *sock, int family,
                                      int type, int protocol, int kern)
{
	return 0;
}

static int honeybest_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
       	const struct task_struct *task = current;
	hb_socket_ll *record;
	int err = 0;

	if (!enabled)
	       	return err;

	if (inject_honeybest_tracker(task, HL_SOCKET_BIND))
		err = -ENOMEM;

	record = search_socket_record(HL_SOCKET_BIND, task->cred->uid.val, 0, 0, 0, 0, 0, 0 , 0, sock, address, addrlen);

	if (record) {
	       	printk(KERN_INFO "Found socket bind record func=%u, port=[%d]\n", record->fid, record->port);
	}
	else {

		if (locking == 0) 
			err = add_socket_record(HL_SOCKET_BIND, task->cred->uid.val, 0, 0, 0, 0, \
					0, 0, 0, 0, sock, address, addrlen, interact);

		if (locking == 1) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}

	return err;
}

static int honeybest_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
       	const struct task_struct *task = current;
	hb_socket_ll *record;
	int err = 0;

	if (!enabled)
	       	return err;

	if (inject_honeybest_tracker(task, HL_SOCKET_CONNECT))
		err = -ENOMEM;

	record = search_socket_record(HL_SOCKET_CONNECT, task->cred->uid.val, 0, 0, 0, 0, 0, 0, 0, sock, address, addrlen);

	if (record) {
	       	printk(KERN_INFO "Found socket bind record func=%u, port=[%d]\n", record->fid, record->port);
	}
	else {

		if (locking == 0) 
			err = add_socket_record(HL_SOCKET_CONNECT, task->cred->uid.val, 0, 0, 0, 0, 0, \
					0, 0, 0, sock, address, addrlen, interact);

		if (locking == 1) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}

	return err;
}

static int honeybest_socket_listen(struct socket *sock, int backlog)
{
	int err = 0;

	if (!enabled)
	       	return err;

	return err;
}

static int honeybest_socket_accept(struct socket *sock, struct socket *newsock)
{
	int err = 0;

	if (!enabled)
	       	return err;

	return err;
}

static int honeybest_socket_sendmsg(struct socket *sock, struct msghdr *msg,
                                  int size)
{
	return 0;
}

static int honeybest_socket_recvmsg(struct socket *sock, struct msghdr *msg,
                                  int size, int flags)
{
	return 0;
}

static int honeybest_socket_getsockname(struct socket *sock)
{
	return 0;
}

static int honeybest_socket_getpeername(struct socket *sock)
{
	return 0;
}

static int honeybest_socket_setsockopt(struct socket *sock, int level, int optname)
{
       	const struct task_struct *task = current;
	hb_socket_ll *record;
	int err = 0;

	if (!enabled)
	       	return err;

	if (inject_honeybest_tracker(task, HL_SOCKET_SETSOCKOPT))
		err = -ENOMEM;

	record = search_socket_record(HL_SOCKET_SETSOCKOPT, task->cred->uid.val, 0, 0, 0, 0, 0, level, optname, NULL, NULL, 0);

	if (record) {
	       	printk(KERN_INFO "Found socket setsockopt record func=%u, level=%d, optname=%d\n", record->fid, level, optname);
	}
	else {

		if (locking == 0) 
			err = add_socket_record(HL_SOCKET_SETSOCKOPT, task->cred->uid.val, 0, 0, 0, 0, \
					0, 0, level, optname, NULL, NULL, 0, interact);

		if (locking == 1)
			err = -EOPNOTSUPP;
	}

	return err;
}


static int honeybest_socket_getsockopt(struct socket *sock, int level,
                                     int optname)
{
	return 0;
}

static int honeybest_socket_shutdown(struct socket *sock, int how)
{
	return 0;
}

static int honeybest_socket_unix_stream_connect(struct sock *sock,
                                              struct sock *other,
                                              struct sock *newsk)
{
	return 0;
}

static int honeybest_socket_unix_may_send(struct socket *sock,
                                        struct socket *other)
{
	return 0;
}

static int honeybest_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static int honeybest_socket_getpeersec_stream(struct socket *sock, char __user *optval,
                                            int __user *optlen, unsigned len)
{
	return 0;
}

static int honeybest_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *secid)
{
	return 0;
}

static int honeybest_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return err;
}

static void honeybest_sk_free_security(struct sock *sk)
{
       	const struct task_struct *task = current;
	int err = 0;

	if (!enabled)
		return;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return;
}

static void honeybest_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
}

static void honeybest_sk_getsecid(struct sock *sk, u32 *secid)
{
}

static void honeybest_sock_graft(struct sock *sk, struct socket *parent)
{
}

static int honeybest_inet_conn_request(struct sock *sk, struct sk_buff *skb,
                                     struct request_sock *req)
{
	return 0;
}

static void honeybest_inet_csk_clone(struct sock *newsk,
                                   const struct request_sock *req)
{
}

static void honeybest_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
}

static int honeybest_secmark_relabel_packet(u32 sid)
{
	return 0;
}

static void honeybest_secmark_refcount_inc(void)
{
}

static void honeybest_secmark_refcount_dec(void)
{
}

static void honeybest_req_classify_flow(const struct request_sock *req,
                                      struct flowi *fl)
{
}

static int honeybest_tun_dev_alloc_security(void **security)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return err;
}

static void honeybest_tun_dev_free_security(void *security)
{
	if (security != NULL)
	       	kfree(security);
}

static int honeybest_tun_dev_create(void)
{
	return 0;
}

static int honeybest_tun_dev_attach_queue(void *security)
{
	return 0;
}

static int honeybest_tun_dev_attach(struct sock *sk, void *security)
{
	return 0;
}

static int honeybest_tun_dev_open(void *security)
{
	return 0;
}

#ifdef CONFIG_SECURITY_NETWORK_XFRM
static void honeybest_xfrm_free(struct xfrm_sec_ctx *ctx)
{
        if (!ctx)
                return;

        kfree(ctx);
}

int honeybest_xfrm_policy_alloc(struct xfrm_sec_ctx **ctxp,
                              struct xfrm_user_sec_ctx *uctx,
                              gfp_t gfp)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return err;
}

int honeybest_xfrm_policy_clone(struct xfrm_sec_ctx *old_ctx,
                              struct xfrm_sec_ctx **new_ctxp)
{
	return 0;
}

void honeybest_xfrm_policy_free(struct xfrm_sec_ctx *ctx)
{
        honeybest_xfrm_free(ctx);
}

int honeybest_xfrm_policy_delete(struct xfrm_sec_ctx *ctx)
{
        return 0;
}

int honeybest_xfrm_state_alloc(struct xfrm_state *x,
                             struct xfrm_user_sec_ctx *uctx)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return err;
}

int honeybest_xfrm_state_alloc_acquire(struct xfrm_state *x,
                                     struct xfrm_sec_ctx *polsec, u32 secid)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return err;
}

void honeybest_xfrm_state_free(struct xfrm_state *x)
{
        honeybest_xfrm_free(x->security);
}

int honeybest_xfrm_state_delete(struct xfrm_state *x)
{
	return 0;
}

int honeybest_xfrm_policy_lookup(struct xfrm_sec_ctx *ctx, u32 fl_secid, u8 dir)
{
	return 0;
}

int honeybest_xfrm_state_pol_flow_match(struct xfrm_state *x,
                                      struct xfrm_policy *xp,
                                      const struct flowi *fl)
{
	return 0;
}

int honeybest_xfrm_decode_session(struct sk_buff *skb, u32 *sid, int ckall)
{
	return 0;
}

#endif

static int honeybest_netlink_send(struct sock *sk, struct sk_buff *skb)
{
        return 0;
}

static int honeybest_msg_msg_alloc_security(struct msg_msg *msg)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return err;
}

static void honeybest_msg_msg_free_security(struct msg_msg *msg)
{
       	const struct task_struct *task = current;
	int err = 0;

	if (!enabled)
		return;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return;
}


static int honeybest_msg_queue_alloc_security(struct msg_queue *msq)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return err;
}

static void honeybest_msg_queue_free_security(struct msg_queue *msq)
{
       	const struct task_struct *task = current;
	int err = 0;

	if (!enabled)
		return;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return;
}

static int honeybest_msg_queue_associate(struct msg_queue *msq, int msqflg)
{
        return 0;
}

static int honeybest_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
        return 0;
}

static int honeybest_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg, int msqflg)
{
	return 0;
}

static int honeybest_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
                                    struct task_struct *target,
                                    long type, int mode)
{
	return 0;
}

static int honeybest_shm_alloc_security(struct shmid_kernel *shp)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return err;
}

static void honeybest_shm_free_security(struct shmid_kernel *shp)
{
       	const struct task_struct *task = current;
	int err = 0;

	if (!enabled)
		return;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return;
}

static int honeybest_shm_associate(struct shmid_kernel *shp, int shmflg)
{
	return 0;
}

static int honeybest_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
	return 0;
}

static int honeybest_shm_shmat(struct shmid_kernel *shp,
                             char __user *shmaddr, int shmflg)
{
	return 0;
}

static int honeybest_sem_alloc_security(struct sem_array *sma)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return err;
}

static void honeybest_sem_free_security(struct sem_array *sma)
{
       	const struct task_struct *task = current;
	int err = 0;

	if (!enabled)
		return;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return;
}

static int honeybest_sem_associate(struct sem_array *sma, int semflg)
{
	return 0;
}

static int honeybest_sem_semctl(struct sem_array *sma, int cmd)
{
	return 0;
}

static int honeybest_sem_semop(struct sem_array *sma,
                             struct sembuf *sops, unsigned nsops, int alter)
{
        return 0;
}

static int honeybest_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
        return 0;
}

static void honeybest_ipc_getsecid(struct kern_ipc_perm *ipcp, u32 *secid)
{
	*secid = 0;
}

static void honeybest_d_instantiate(struct dentry *dentry, struct inode *inode)
{
	return;
}

static int honeybest_getprocattr(struct task_struct *p,
                               char *name, char **value)
{
	return -EINVAL;
}

static int honeybest_setprocattr(struct task_struct *p,
                               char *name, void *value, size_t size)
{
	return -EINVAL;
}


static int honeybest_ismaclabel(const char *name)
{
	return 0;
}

static int honeybest_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
	return -EOPNOTSUPP;
}

static int honeybest_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
	return -EOPNOTSUPP;
}

static void honeybest_release_secctx(char *secdata, u32 seclen)
{
}

static void honeybest_inode_invalidate_secctx(struct inode *inode)
{
}

static int honeybest_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
{
	return 0;
}

static int honeybest_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
	return 0;
}

static int honeybest_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
	return 0;
}

#ifdef CONFIG_KEYS
static int honeybest_key_alloc(struct key *k, const struct cred *cred,
                             unsigned long flags)
{
	int err = 0;
       	const struct task_struct *task = current;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return err;
}

static void honeybest_key_free(struct key *k)
{
       	const struct task_struct *task = current;
	int err = 0;

	if (!enabled)
		return;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return;
}

static int honeybest_key_permission(key_ref_t key_ref,
                                  const struct cred *cred,
                                  unsigned perm)
{
	return 0;
}

static int honeybest_key_getsecurity(struct key *key, char **_buffer)
{
	*_buffer = NULL;
	return 0;
}

#endif /* CONFIG_KEYS */

static int honeybest_sb_show_options(struct seq_file *m, struct super_block *sb)
{
	return 0;
}

static int honeybest_set_mnt_opts(struct super_block *sb,
                                struct security_mnt_opts *opts,
                                unsigned long kern_flags,
                                unsigned long *set_kern_flags)
{
	return 0;
}


static int honeybest_sb_clone_mnt_opts(const struct super_block *oldsb,
                                        struct super_block *newsb)
{
	return 0;
}

#ifdef CONFIG_AUDIT
static int honeybest_audit_rule_init(u32 field, u32 op, char *rulestr, void **lsmrule)
{

	return 0;
}

static int honeybest_audit_rule_known(struct audit_krule *krule)
{
	return 0;
}

static int honeybest_audit_rule_match(u32 secid, u32 field, u32 op, void *lsmrule,
				struct audit_context *actx)
{
	return 0;
}

static void honeybest_audit_rule_free(void *lsmrule)
{
       	const struct task_struct *task = current;
	int err = 0;

	if (!enabled)
		return;

	if (inject_honeybest_tracker(task, 0))
	       	err = -ENOMEM;
	return;
}
#endif /* CONFIG_AUDIT */



static int honeybest_parse_opts_str(char *options,
				  struct security_mnt_opts *opts)
{
	return 0;
} 

static struct security_hook_list honeybest_hooks[] = {
        LSM_HOOK_INIT(binder_set_context_mgr, honeybest_binder_set_context_mgr),
        LSM_HOOK_INIT(binder_transaction, honeybest_binder_transaction),
        LSM_HOOK_INIT(binder_transfer_binder, honeybest_binder_transfer_binder),
        LSM_HOOK_INIT(binder_transfer_file, honeybest_binder_transfer_file),

        LSM_HOOK_INIT(ptrace_access_check, honeybest_ptrace_access_check),
        LSM_HOOK_INIT(ptrace_traceme, honeybest_ptrace_traceme),
        LSM_HOOK_INIT(capget, honeybest_capget),
        LSM_HOOK_INIT(capset, honeybest_capset),
        LSM_HOOK_INIT(capable, honeybest_capable),
        LSM_HOOK_INIT(quotactl, honeybest_quotactl),
        LSM_HOOK_INIT(quota_on, honeybest_quota_on),
        LSM_HOOK_INIT(syslog, honeybest_syslog),
        LSM_HOOK_INIT(vm_enough_memory, honeybest_vm_enough_memory),

        LSM_HOOK_INIT(netlink_send, honeybest_netlink_send),

        LSM_HOOK_INIT(bprm_set_creds, honeybest_bprm_set_creds),
        LSM_HOOK_INIT(bprm_committing_creds, honeybest_bprm_committing_creds),
        LSM_HOOK_INIT(bprm_committed_creds, honeybest_bprm_committed_creds),
        LSM_HOOK_INIT(bprm_secureexec, honeybest_bprm_secureexec),

        LSM_HOOK_INIT(sb_alloc_security, honeybest_sb_alloc_security),
        LSM_HOOK_INIT(sb_free_security, honeybest_sb_free_security),
        LSM_HOOK_INIT(sb_copy_data, honeybest_sb_copy_data),
        LSM_HOOK_INIT(sb_remount, honeybest_sb_remount),
        LSM_HOOK_INIT(sb_kern_mount, honeybest_sb_kern_mount),
        LSM_HOOK_INIT(sb_show_options, honeybest_sb_show_options),
        LSM_HOOK_INIT(sb_statfs, honeybest_sb_statfs),
        LSM_HOOK_INIT(sb_mount, honeybest_mount),
        LSM_HOOK_INIT(sb_umount, honeybest_umount),
        LSM_HOOK_INIT(sb_set_mnt_opts, honeybest_set_mnt_opts),
        LSM_HOOK_INIT(sb_clone_mnt_opts, honeybest_sb_clone_mnt_opts),
        LSM_HOOK_INIT(sb_parse_opts_str, honeybest_parse_opts_str),

        LSM_HOOK_INIT(dentry_init_security, honeybest_dentry_init_security),

#ifdef CONFIG_SECURITY_PATH
	LSM_HOOK_INIT(path_link, honeybest_path_link),
	LSM_HOOK_INIT(path_unlink, honeybest_path_unlink),
	LSM_HOOK_INIT(path_symlink, honeybest_path_symlink),
	LSM_HOOK_INIT(path_mkdir, honeybest_path_mkdir),
	LSM_HOOK_INIT(path_rmdir, honeybest_path_rmdir),
	LSM_HOOK_INIT(path_mknod, honeybest_path_mknod),
	LSM_HOOK_INIT(path_rename, honeybest_path_rename),
	LSM_HOOK_INIT(path_chmod, honeybest_path_chmod),
	LSM_HOOK_INIT(path_chown, honeybest_path_chown),
	LSM_HOOK_INIT(path_truncate, honeybest_path_truncate),
#endif

        LSM_HOOK_INIT(inode_alloc_security, honeybest_inode_alloc_security),
        LSM_HOOK_INIT(inode_free_security, honeybest_inode_free_security),
        LSM_HOOK_INIT(inode_init_security, honeybest_inode_init_security),
        LSM_HOOK_INIT(inode_create, honeybest_inode_create),
        LSM_HOOK_INIT(inode_link, honeybest_inode_link),
        LSM_HOOK_INIT(inode_unlink, honeybest_inode_unlink),
        LSM_HOOK_INIT(inode_symlink, honeybest_inode_symlink),
        LSM_HOOK_INIT(inode_mkdir, honeybest_inode_mkdir),
        LSM_HOOK_INIT(inode_rmdir, honeybest_inode_rmdir),
        LSM_HOOK_INIT(inode_mknod, honeybest_inode_mknod),
        LSM_HOOK_INIT(inode_rename, honeybest_inode_rename),
        LSM_HOOK_INIT(inode_readlink, honeybest_inode_readlink),
        LSM_HOOK_INIT(inode_follow_link, honeybest_inode_follow_link),
        LSM_HOOK_INIT(inode_permission, honeybest_inode_permission),
        LSM_HOOK_INIT(inode_setattr, honeybest_inode_setattr),
        LSM_HOOK_INIT(inode_getattr, honeybest_inode_getattr),
        LSM_HOOK_INIT(inode_setxattr, honeybest_inode_setxattr),
        LSM_HOOK_INIT(inode_post_setxattr, honeybest_inode_post_setxattr),
        LSM_HOOK_INIT(inode_getxattr, honeybest_inode_getxattr),
        LSM_HOOK_INIT(inode_listxattr, honeybest_inode_listxattr),
        LSM_HOOK_INIT(inode_removexattr, honeybest_inode_removexattr),
        LSM_HOOK_INIT(inode_getsecurity, honeybest_inode_getsecurity),
        LSM_HOOK_INIT(inode_setsecurity, honeybest_inode_setsecurity),
        LSM_HOOK_INIT(inode_listsecurity, honeybest_inode_listsecurity),
        LSM_HOOK_INIT(inode_getsecid, honeybest_inode_getsecid),

        LSM_HOOK_INIT(file_permission, honeybest_file_permission),
        LSM_HOOK_INIT(file_alloc_security, honeybest_file_alloc_security),
        LSM_HOOK_INIT(file_free_security, honeybest_file_free_security),
        LSM_HOOK_INIT(file_ioctl, honeybest_file_ioctl),
        LSM_HOOK_INIT(mmap_file, honeybest_mmap_file),
        LSM_HOOK_INIT(mmap_addr, honeybest_mmap_addr),
        LSM_HOOK_INIT(file_mprotect, honeybest_file_mprotect),
        LSM_HOOK_INIT(file_lock, honeybest_file_lock),
        LSM_HOOK_INIT(file_fcntl, honeybest_file_fcntl),
        LSM_HOOK_INIT(file_set_fowner, honeybest_file_set_fowner),
        LSM_HOOK_INIT(file_send_sigiotask, honeybest_file_send_sigiotask),
        LSM_HOOK_INIT(file_receive, honeybest_file_receive),
        LSM_HOOK_INIT(file_open, honeybest_file_open),

        LSM_HOOK_INIT(task_create, honeybest_task_create),
        LSM_HOOK_INIT(cred_alloc_blank, honeybest_cred_alloc_blank),
        LSM_HOOK_INIT(cred_free, honeybest_cred_free),
        LSM_HOOK_INIT(cred_prepare, honeybest_cred_prepare),
        LSM_HOOK_INIT(cred_transfer, honeybest_cred_transfer),
        LSM_HOOK_INIT(kernel_act_as, honeybest_kernel_act_as),
        LSM_HOOK_INIT(kernel_create_files_as, honeybest_kernel_create_files_as),
        LSM_HOOK_INIT(kernel_module_request, honeybest_kernel_module_request),
        LSM_HOOK_INIT(kernel_read_file, honeybest_kernel_read_file),
        LSM_HOOK_INIT(task_setpgid, honeybest_task_setpgid),
        LSM_HOOK_INIT(task_getpgid, honeybest_task_getpgid),
        LSM_HOOK_INIT(task_getsid, honeybest_task_getsid),
        LSM_HOOK_INIT(task_getsecid, honeybest_task_getsecid),
        LSM_HOOK_INIT(task_setnice, honeybest_task_setnice),
        LSM_HOOK_INIT(task_setioprio, honeybest_task_setioprio),
        LSM_HOOK_INIT(task_getioprio, honeybest_task_getioprio),
        LSM_HOOK_INIT(task_setrlimit, honeybest_task_setrlimit),
        LSM_HOOK_INIT(task_setscheduler, honeybest_task_setscheduler),
        LSM_HOOK_INIT(task_getscheduler, honeybest_task_getscheduler),
        LSM_HOOK_INIT(task_movememory, honeybest_task_movememory),
        LSM_HOOK_INIT(task_kill, honeybest_task_kill),
        LSM_HOOK_INIT(task_wait, honeybest_task_wait),
        LSM_HOOK_INIT(task_to_inode, honeybest_task_to_inode),

        LSM_HOOK_INIT(ipc_permission, honeybest_ipc_permission),
        LSM_HOOK_INIT(ipc_getsecid, honeybest_ipc_getsecid),

        LSM_HOOK_INIT(msg_msg_alloc_security, honeybest_msg_msg_alloc_security),
        LSM_HOOK_INIT(msg_msg_free_security, honeybest_msg_msg_free_security),

        LSM_HOOK_INIT(msg_queue_alloc_security,
                        honeybest_msg_queue_alloc_security),
        LSM_HOOK_INIT(msg_queue_free_security, honeybest_msg_queue_free_security),
        LSM_HOOK_INIT(msg_queue_associate, honeybest_msg_queue_associate),
        LSM_HOOK_INIT(msg_queue_msgctl, honeybest_msg_queue_msgctl),
        LSM_HOOK_INIT(msg_queue_msgsnd, honeybest_msg_queue_msgsnd),
        LSM_HOOK_INIT(msg_queue_msgrcv, honeybest_msg_queue_msgrcv),

        LSM_HOOK_INIT(shm_alloc_security, honeybest_shm_alloc_security),
        LSM_HOOK_INIT(shm_free_security, honeybest_shm_free_security),
        LSM_HOOK_INIT(shm_associate, honeybest_shm_associate),
        LSM_HOOK_INIT(shm_shmctl, honeybest_shm_shmctl),
        LSM_HOOK_INIT(shm_shmat, honeybest_shm_shmat),

        LSM_HOOK_INIT(sem_alloc_security, honeybest_sem_alloc_security),
        LSM_HOOK_INIT(sem_free_security, honeybest_sem_free_security),
        LSM_HOOK_INIT(sem_associate, honeybest_sem_associate),
        LSM_HOOK_INIT(sem_semctl, honeybest_sem_semctl),
        LSM_HOOK_INIT(sem_semop, honeybest_sem_semop),

        LSM_HOOK_INIT(d_instantiate, honeybest_d_instantiate),

        LSM_HOOK_INIT(getprocattr, honeybest_getprocattr),
        LSM_HOOK_INIT(setprocattr, honeybest_setprocattr),

        LSM_HOOK_INIT(ismaclabel, honeybest_ismaclabel),
        LSM_HOOK_INIT(secid_to_secctx, honeybest_secid_to_secctx),
        LSM_HOOK_INIT(secctx_to_secid, honeybest_secctx_to_secid),
        LSM_HOOK_INIT(release_secctx, honeybest_release_secctx),
        LSM_HOOK_INIT(inode_invalidate_secctx, honeybest_inode_invalidate_secctx),
	LSM_HOOK_INIT(inode_notifysecctx, honeybest_inode_notifysecctx),
        LSM_HOOK_INIT(inode_setsecctx, honeybest_inode_setsecctx),
        LSM_HOOK_INIT(inode_getsecctx, honeybest_inode_getsecctx),

        LSM_HOOK_INIT(unix_stream_connect, honeybest_socket_unix_stream_connect),
        LSM_HOOK_INIT(unix_may_send, honeybest_socket_unix_may_send),

        LSM_HOOK_INIT(socket_create, honeybest_socket_create),
        LSM_HOOK_INIT(socket_post_create, honeybest_socket_post_create),
        LSM_HOOK_INIT(socket_bind, honeybest_socket_bind),
        LSM_HOOK_INIT(socket_connect, honeybest_socket_connect),
        LSM_HOOK_INIT(socket_listen, honeybest_socket_listen),
        LSM_HOOK_INIT(socket_accept, honeybest_socket_accept),
        LSM_HOOK_INIT(socket_sendmsg, honeybest_socket_sendmsg),
        LSM_HOOK_INIT(socket_recvmsg, honeybest_socket_recvmsg),
        LSM_HOOK_INIT(socket_getsockname, honeybest_socket_getsockname),
        LSM_HOOK_INIT(socket_getpeername, honeybest_socket_getpeername),
        LSM_HOOK_INIT(socket_getsockopt, honeybest_socket_getsockopt),
        LSM_HOOK_INIT(socket_setsockopt, honeybest_socket_setsockopt),
        LSM_HOOK_INIT(socket_shutdown, honeybest_socket_shutdown),
        LSM_HOOK_INIT(socket_sock_rcv_skb, honeybest_socket_sock_rcv_skb),
        LSM_HOOK_INIT(socket_getpeersec_stream, honeybest_socket_getpeersec_stream),
        LSM_HOOK_INIT(socket_getpeersec_dgram, honeybest_socket_getpeersec_dgram),
        LSM_HOOK_INIT(sk_alloc_security, honeybest_sk_alloc_security),
        LSM_HOOK_INIT(sk_free_security, honeybest_sk_free_security),
        LSM_HOOK_INIT(sk_clone_security, honeybest_sk_clone_security),
        LSM_HOOK_INIT(sk_getsecid, honeybest_sk_getsecid),
        LSM_HOOK_INIT(sock_graft, honeybest_sock_graft),
        LSM_HOOK_INIT(inet_conn_request, honeybest_inet_conn_request),
        LSM_HOOK_INIT(inet_csk_clone, honeybest_inet_csk_clone),
        LSM_HOOK_INIT(inet_conn_established, honeybest_inet_conn_established),
        LSM_HOOK_INIT(secmark_relabel_packet, honeybest_secmark_relabel_packet),
        LSM_HOOK_INIT(secmark_refcount_inc, honeybest_secmark_refcount_inc),
        LSM_HOOK_INIT(secmark_refcount_dec, honeybest_secmark_refcount_dec),
        LSM_HOOK_INIT(req_classify_flow, honeybest_req_classify_flow),
        LSM_HOOK_INIT(tun_dev_alloc_security, honeybest_tun_dev_alloc_security),
        LSM_HOOK_INIT(tun_dev_free_security, honeybest_tun_dev_free_security),
        LSM_HOOK_INIT(tun_dev_create, honeybest_tun_dev_create),
        LSM_HOOK_INIT(tun_dev_attach_queue, honeybest_tun_dev_attach_queue),
        LSM_HOOK_INIT(tun_dev_attach, honeybest_tun_dev_attach),
        LSM_HOOK_INIT(tun_dev_open, honeybest_tun_dev_open),

#ifdef CONFIG_SECURITY_NETWORK_XFRM
        LSM_HOOK_INIT(xfrm_policy_alloc_security, honeybest_xfrm_policy_alloc),
        LSM_HOOK_INIT(xfrm_policy_clone_security, honeybest_xfrm_policy_clone),
        LSM_HOOK_INIT(xfrm_policy_free_security, honeybest_xfrm_policy_free),
        LSM_HOOK_INIT(xfrm_policy_delete_security, honeybest_xfrm_policy_delete),
        LSM_HOOK_INIT(xfrm_state_alloc, honeybest_xfrm_state_alloc),
        LSM_HOOK_INIT(xfrm_state_alloc_acquire,
                        honeybest_xfrm_state_alloc_acquire),
        LSM_HOOK_INIT(xfrm_state_free_security, honeybest_xfrm_state_free),
        LSM_HOOK_INIT(xfrm_state_delete_security, honeybest_xfrm_state_delete),
        LSM_HOOK_INIT(xfrm_policy_lookup, honeybest_xfrm_policy_lookup),
        LSM_HOOK_INIT(xfrm_state_pol_flow_match,
                        honeybest_xfrm_state_pol_flow_match),
        LSM_HOOK_INIT(xfrm_decode_session, honeybest_xfrm_decode_session),
#endif

#ifdef CONFIG_KEYS
        LSM_HOOK_INIT(key_alloc, honeybest_key_alloc),
        LSM_HOOK_INIT(key_free, honeybest_key_free),
        LSM_HOOK_INIT(key_permission, honeybest_key_permission),
        LSM_HOOK_INIT(key_getsecurity, honeybest_key_getsecurity),
#endif

#ifdef CONFIG_AUDIT
        LSM_HOOK_INIT(audit_rule_init, honeybest_audit_rule_init),
        LSM_HOOK_INIT(audit_rule_known, honeybest_audit_rule_known),
        LSM_HOOK_INIT(audit_rule_match, honeybest_audit_rule_match),
        LSM_HOOK_INIT(audit_rule_free, honeybest_audit_rule_free),
#endif
};

void __init honeybest_add_hooks(void)
{
	printk(KERN_INFO "ready to honeybest (currently %sabled)\n", enabled ? "en" : "dis");
	security_add_hooks(honeybest_hooks, ARRAY_SIZE(honeybest_hooks));
	honeybest_init_sysctl();
}

/* Should not be mutable after boot, so not listed in sysfs (perm == 0). */
module_param(enabled, int, 0);
module_param(locking, int, 0);
MODULE_PARM_DESC(enabled, "HoneyBest module/firmware loading (default: true)");

#endif /* CONFIG_SECURITY_HONEYBEST */

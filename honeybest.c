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
#include <linux/version.h>
#include "honeybest.h"
#include "creds.h"
#include "files.h"
#include "socket.h"
#include "tasks.h"
#include "inode.h"
#include "path.h"
#include "sb.h"
#include "kmod.h"
#include "ptrace.h"
#include "notify.h"

/**
 * @brief honeybest.c is the entry point of honeybest LSM. Main job
 * 1. Initializing all external linked list use by
 * 	creds
 * 	files
 * 	tasks
 * 	sockets
 * 	inodes
 * 	kmod (kernel modules)
 * 	paths
 * 	sb (super block)
 * 	notify
 * 2. Initialize various of hooks
 * 3. Initialize userspace variable options including enabled/locking/interact/level
 * 4. Inject tracking ticket
 * 5. Operate insert/search activities
 * 6. Initialize /proc/honeybest* & /proc/sys/kernel/honeybest* interface
 */

#ifdef CONFIG_SECURITY_HONEYBEST
static int enabled = IS_ENABLED(CONFIG_SECURITY_HONEYBEST_ENABLED);
static int locking = 0;		// detect mode
static int bl = 0;		// white list vs black list
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
extern hb_ptrace_ll hb_ptrace_list_head;
extern hb_notify_ll hb_notify_list_head;

extern struct proc_dir_entry *hb_proc_file_entry;
extern struct proc_dir_entry *hb_proc_task_entry;
extern struct proc_dir_entry *hb_proc_socket_entry;
extern struct proc_dir_entry *hb_proc_binprm_entry;
extern struct proc_dir_entry *hb_proc_inode_entry;
extern struct proc_dir_entry *hb_proc_path_entry;
extern struct proc_dir_entry *hb_proc_sb_entry;
extern struct proc_dir_entry *hb_proc_kmod_entry;
extern struct proc_dir_entry *hb_proc_ptrace_entry;
extern struct proc_dir_entry *hb_proc_notify_entry;


typedef struct hb_track_t { 
	kuid_t uid;		/**< current task uid */
	unsigned long tsid;	/**< task sequence id */
	unsigned int prev_fid;	/**< previous track clue across function */
	unsigned int curr_fid;	/**< current track clue across function */
} hb_track_info;

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
		.procname       = "enabled",	/**< enabled = 1 turn on honeybest LSM */
		.data           = &enabled,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &zero,
		.extra2         = &one,
	},
	{
		.procname       = "locking",	/**< locking = 1 turn on honeybest LSM lock down activities update */
		.data           = &locking,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &zero,
		.extra2         = &one,
	},
	{
		.procname       = "interact",	/**< interact = 1 update activities to /proc/honeybest/notify */
		.data           = &interact,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &zero,
		.extra2         = &one,
	},
	{
		.procname       = "level",	/**< currently support 0 & 1 honeybest LSM granularity level */
		.data           = &level,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &one,
		.extra2         = &two,
	},
	{
		.procname       = "bl",	/**< bl = 0, item in record is allow; bl = 1, item in record is not allow */
		.data           = &bl,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &zero,
		.extra2         = &one,
	},
	{ }
};
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,4,0)
/**
 * Migrate from kernel 4.9.189 string_helpers.c
 * kstrdup_quotable / kstrdup_quotable_file use to extract
 * struct file to full pathname.
 */
char *kstrdup_quotable(const char *src, gfp_t gfp)
{
	size_t slen, dlen;
	char *dst;
	const int flags = ESCAPE_HEX;
	const char esc[] = "\f\n\r\t\v\a\e\\\"";

	if (!src)
		return NULL;
	slen = strlen(src);

	dlen = string_escape_mem(src, slen, NULL, 0, flags, esc);
	dst = kmalloc(dlen + 1, gfp);
	if (!dst)
		return NULL;

	WARN_ON(string_escape_mem(src, slen, dst, dlen, flags, esc) != dlen);
	dst[dlen] = '\0';

	return dst;
}

char *kstrdup_quotable_file(struct file *file, gfp_t gfp)
{
	char *temp, *pathname;

	if (!file)
		return kstrdup("<unknown>", gfp);

	/* We add 11 spaces for ' (deleted)' to be appended */
	temp = kmalloc(PATH_MAX + 11, GFP_KERNEL);
	if (!temp)
		return kstrdup("<no_memory>", gfp);

	pathname = file_path(file, temp, PATH_MAX + 11);
	if (IS_ERR(pathname))
		pathname = kstrdup("<too_long>", gfp);
	else
		pathname = kstrdup_quotable(pathname, gfp);

	kfree(temp);
	return pathname;
}
#endif

/**
 * Free track memory from current task cred_cxt(cred) pointer
 * reference track memory allocation inject_honeybest_tracker()
 * 
 */
int free_honeybest_tracker(struct cred *cred)
{
	int err = 0;
	hb_track_info *sec = cred_cxt(cred);

	if (sec) {
		;//printk(KERN_ERR "free %lu\n", sec->tsid);
	       	kfree(sec);
		sec = NULL;
	}

	return err;
}

/**
 * Attach to each trigger function so that we can track previous system activity
 * reference to memory free_honeybest_tracker.
 * 
 * @param[in] fid reference to honeybest.h to track who is the caller
 * @param[in] task reference to struct cred
 */
int inject_honeybest_tracker(struct cred *cred, unsigned int fid)
{
	int err = 0;
	hb_track_info *sec = NULL;
       	kuid_t uid;
       
	if (!cred)
		return -ENOMEM;

	uid = cred->uid;
	sec = cred_cxt(cred);
	       	
	if (sec)
	{
		if (sec->curr_fid != fid) {
			sec->prev_fid = sec->curr_fid;
			sec->curr_fid = fid;
			;//printk(KERN_ERR "%s(%d) alloc %lu\n", __FUNCTION__, __LINE__, sec->tsid);
		}
		return err;
	}
	else {
		sec = (hb_track_info *)kmalloc(sizeof(hb_track_info), GFP_KERNEL);
		if (sec) {
			sec->tsid = task_seq++;
			sec->prev_fid = fid;
			sec->curr_fid = fid;
			sec->uid = uid;
			cred_cxt(cred) = (hb_track_info *)sec;
			//printk(KERN_ERR "%s(%d) alloc %lu\n", __FUNCTION__, __LINE__, sec->tsid);
		}
		else 
			err = -ENOMEM;
	}

	return err;
}

/**
 * open_notify_proc provide read OP for user to acces all activities
 * while /proc/sys/kernel/interact < 1
 */
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

/**
 * open_file_proc provide read OP for user to acces current file activities
 */
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

/**
 * open_task_proc provide read OP for user to acces current signal activities
 */
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

/**
 * open_socket_proc provide read OP for user to acces current 
 * bind/listen/accept socket activities
 */
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

/**
 * open_binprm_proc provide read OP for user to acces current 
 * execution activities
 */
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

/**
 * open_inode_proc provide read OP for user to acces current 
 * inode create/delete activities
 */
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

/**
 * open_path_proc provide read OP for user to acces current 
 * symlink/delete/create/softlink file activities
 */
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

/**
 * open_sb_proc provide read OP for user to acces current 
 * superblock mount/umount activities
 */
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

/**
 * open_kmod_proc provide read OP for user to acces current 
 * kernel insmod/rmmod activities
 */
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

/**
 * open_ptrace_proc provide read OP for user to acces current 
 * kernel insmod/rmmod activities
 */
static int open_ptrace_proc(struct inode *inode, struct  file *file) {
	  return single_open(file, read_ptrace_record, NULL);
}

static const struct file_operations hb_proc_ptrace_fops = {
	.open  = open_ptrace_proc,
	.read  = seq_read,
	.write  = write_ptrace_record,
	.llseek  = seq_lseek,
	.release = single_release,
};

static void __init honeybest_init_sysctl(void)
{
       	struct proc_dir_entry *honeybest_dir = proc_mkdir("honeybest", NULL);
	struct cred *cred = (struct cred *) current->real_cred;

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

	/* ptrace op tracing */
	INIT_LIST_HEAD(&hb_ptrace_list_head.list);

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

	/* prepare ptrace proc entry */
	hb_proc_ptrace_entry = proc_create("ptrace", 0666, honeybest_dir, &hb_proc_ptrace_fops);
	if (!hb_proc_ptrace_entry) {
		printk(KERN_INFO "Error creating honeybest ptrace proc entry");
	}

	inject_honeybest_tracker(cred, HB_INITIALIZE);
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
	struct cred *cred = (struct cred *) current->real_cred;
       	struct task_struct *parent_task = current;
       	struct task_struct *child_task = child;
	struct mm_struct *parent_mm = current->mm;
	struct mm_struct *child_mm = child->mm;
       	char *parent_binprm = NULL;
       	char *child_binprm = NULL;
       	char *parent_taskname = NULL;
       	char *child_taskname = NULL;
	hb_ptrace_ll *record = NULL;
	char uid[UID_STR_SIZE];

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_PTRACE_ACCESS_CHECK))
	       	err = -ENOMEM;

	task_lock(parent_task);
	if (parent_mm) {
		down_read(&parent_mm->mmap_sem);
		if (parent_mm->exe_file) {
			parent_taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (parent_taskname) {
				parent_binprm = d_path(&parent_mm->exe_file->f_path, parent_taskname, PATH_MAX);
				//printk(KERN_ERR "binprm %s, file %s\n", binprm, filename);
			}
			else
			       	goto out;
		}
		up_read(&parent_mm->mmap_sem);
	}
	task_unlock(parent_task);

	if (!parent_binprm)
		goto out1;

	task_lock(child_task);
	if (child_mm) {
		down_read(&child_mm->mmap_sem);
		if (child_mm->exe_file) {
			child_taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (child_taskname) {
				child_binprm = d_path(&child_mm->exe_file->f_path, child_taskname, PATH_MAX);
				//printk(KERN_ERR "binprm %s, file %s\n", binprm, filename);
			}
			else
				goto out1;
		}
		up_read(&child_mm->mmap_sem);
	}
	task_unlock(child_task);

	if (!child_binprm)
		goto out2;

//	printk(KERN_ERR "%s,%d -->%s, %s, %d\n", __FUNCTION__, __LINE__, parent_binprm, child_binprm, mode);

	record = search_ptrace_record(HB_PTRACE_ACCESS_CHECK, current->cred->uid.val, parent_binprm, child_binprm, mode);

	if (record) {
	       	;//printk(KERN_INFO "Found ptrace record func=%u, parent=[%s]\n", record->fid, record->parent);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_ptrace_record(HB_PTRACE_ACCESS_CHECK, uid, 'A', parent_binprm, child_binprm, mode, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_ptrace_record(HB_PTRACE_ACCESS_CHECK, uid, 'R', parent_binprm, child_binprm, mode, interact);

		if ((locking == 1) && (bl == 0)) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}

out2:
	kfree(child_taskname);
out1:
	kfree(parent_taskname);
out:
	return err;
}

static int honeybest_ptrace_traceme(struct task_struct *parent)
{
	int err = 0;
       	
	if (!enabled)
		return err;

	return err;
}

static int honeybest_capget(struct task_struct *target, kernel_cap_t *effective,
                          kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	int err = 0;

	if (!enabled)
		return err;
#if 0
	kernel_cap_t dest, a, b;
	struct cred *cred = NULL;
	char *pathname,*p;
	struct mm_struct *mm = target->mm;
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (pathname) {
				p = d_path(&mm->exe_file->f_path, pathname, PATH_MAX);
			}
		}
		up_read(&mm->mmap_sem);
	}

	cap_clear(dest);
	rcu_read_lock();
	cred = (struct cred *) current->real_cred;

	a = *effective;
	b = *permitted;
	CAP_BOP_ALL(dest, a, b, |);
	//printk(KERN_ERR "target %s, uid=%u, effec=%u, inherit=%u, permit=%u, dest=%u\n", p, cred->uid.val, (u32)effective->cap, (u32)inheritable->cap, (u32)permitted->cap, (u32)dest.cap); rcu_read_unlock();
#endif

	return err;
}

static int honeybest_capset(struct cred *new, const struct cred *old,
                          const kernel_cap_t *effective,
                          const kernel_cap_t *inheritable,
                          const kernel_cap_t *permitted)
{
	int err = 0;
	kernel_cap_t dest, a, b;
       	struct task_struct *task = current;
	char *pathname = NULL;
	char *p = NULL;
	struct mm_struct *mm = current->mm;

	if (!enabled)
		return err;

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (pathname) {
				p = d_path(&mm->exe_file->f_path, pathname, PATH_MAX);
			}
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	cap_clear(dest);
	rcu_read_lock();

	a = *effective;
	b = *permitted;
	CAP_BOP_ALL(dest, a, b, |);
	//printk(KERN_ERR "program %s, old uid=%u, new uid=%u, effec=%u, inherit=%u, permit=%u, dest=%u\n", p, old->uid.val, new->uid.val, (u32)effective->cap, (u32)inheritable->cap, (u32)permitted->cap, (u32)dest.cap); rcu_read_unlock();
	kfree(pathname);

	return err;
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

/**
 * This function use to tracking all binary had been executed.
 * Tracking info: absolute path / sha1 digest / user id 
 */
static int honeybest_bprm_set_creds(struct linux_binprm *bprm)
{
	int err = 0;
	struct cred *cred = (struct cred *) current->real_cred;
	char digest[SHA1_HONEYBEST_DIGEST_SIZE];
	hb_binprm_ll *record = NULL;
	char *pathname;
	char uid[UID_STR_SIZE];

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_BPRM_SET_CREDS))
	       	err = -ENOMEM;

	pathname = kstrdup_quotable_file(bprm->file, GFP_KERNEL);

	if (!pathname) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if(allow_file_whitelist(pathname)) {
		goto out1;
	}

	// logic of xattr need to validate?
	memset(digest, '\0', SHA1_HONEYBEST_DIGEST_SIZE);
	lookup_binprm_digest(bprm->file, digest);

	record = search_binprm_record(HB_BPRM_SET_CREDS, current->cred->uid.val, pathname, digest);

	if (record) {
	       	;//printk(KERN_INFO "Found set creds record func=%u, hash=[%s]\n", record->fid, record->digest);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_binprm_record(HB_BPRM_SET_CREDS, uid, 'A', pathname, digest, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_binprm_record(HB_BPRM_SET_CREDS, uid, 'R', pathname, digest, interact);

		if ((locking == 1) && (bl == 0)) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}
out1:
	kfree(pathname);
out:
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

	if (!enabled)
		return err;

	return err;
}

static void honeybest_sb_free_security(struct super_block *sb)
{

	if (!enabled)
		return;
	return;
}
	
static int honeybest_sb_copy_data(char *orig, char *copy)
{
	int err = 0;

	if (!enabled)
		return err;

	return err;
}

/**
 * This function use to tracking remount activity.
 * Tracking info: superblock id / disk format 
 */
static int honeybest_sb_remount(struct super_block *sb, void *data)
{
	int err = 0;
	struct security_mnt_opts opts;
	char **mount_options;
	int *flags;
	int i = 0;
	char *na = "N/A";
	char uid[UID_STR_SIZE];
	hb_sb_ll *record = NULL;
	struct cred *cred = (struct cred *) current->real_cred;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_SB_MOUNT))
	       	err = -ENOMEM;

	if (!sb)
		return err;

	security_init_mnt_opts(&opts);
	mount_options = opts.mnt_opts;
	flags = opts.mnt_opts_flags;
	for (i = 0; i < opts.num_mnt_opts; i++) {
		record = search_sb_record(HB_SB_REMOUNT, current->cred->uid.val, sb->s_id, (char *)sb->s_type->name, na, na, 0);

		if (record) {
			;//printk(KERN_INFO "Found sb remount record func=%u, uid %u, s_id=%s, type name=%s\n", record->fid, record->uid, record->s_id, record->name);
			if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
				err = -EOPNOTSUPP;
		}
		else {
			sprintf(uid, "%u", current->cred->uid.val);

			if ((locking == 0) && (bl == 0)) 
				err = add_sb_record(HB_SB_REMOUNT, uid, 'A', sb->s_id, (char *)sb->s_type->name, na, na, 0, interact);

			if ((locking == 0) && (bl == 1)) 
				err = add_sb_record(HB_SB_REMOUNT, uid, 'R', sb->s_id, (char *)sb->s_type->name, na, na, 0, interact);

			if ((locking == 1) && (bl == 0))
				err = -EOPNOTSUPP;
		}
	}
	return err;
}

static int honeybest_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
	int err = 0;

	if (!enabled)
		return err;

	// less info compare to sb_mount

	return err;
}

/**
 * This function use to tracking disk stat activity.
 * Trigger by command df/mount while view disk information
 * Tracking info: superblock id / disk format 
 */
static int honeybest_sb_statfs(struct dentry *dentry)
{
	int err = 0;
	struct cred *cred = (struct cred *) current->real_cred;
       	struct super_block *sb = dentry->d_sb;
	char *na = "N/A";
	char uid[UID_STR_SIZE];
	hb_sb_ll *record = NULL;

	if (!enabled)
		return err;

	if (!sb)
		return err;

	if (inject_honeybest_tracker(cred, HB_SB_STATFS))
	       	err = -ENOMEM;

	record = search_sb_record(HB_SB_STATFS, current->cred->uid.val, sb->s_id, (char *)sb->s_type->name, na, na, 0);

	if (record) {
		;//printk(KERN_INFO "Found sb statfs record func=%u, uid %u, s_id=%s, type name=%s\n", record->fid, record->uid, record->s_id, record->name);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_sb_record(HB_SB_STATFS, uid, 'A', sb->s_id, (char *)sb->s_type->name, na, na, 0, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_sb_record(HB_SB_STATFS, uid, 'R', sb->s_id, (char *)sb->s_type->name, na, na, 0, interact);

		if ((locking == 1) && (bl == 0))
			err = -EOPNOTSUPP;
	}
	return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
int honeybest_sb_pivotroot(const struct path *old_path, const struct path *new_path)
#else
int honeybest_sb_pivotroot(struct path *old_path, struct path *new_path)
#endif
{
	int err = 0;
	char *old_pathname = NULL;
	char *new_pathname = NULL;
	char *old_buff = NULL;
	char *new_buff = NULL;

	if (!enabled)
		return err;

	old_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	new_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);

	old_pathname = d_absolute_path(old_path, old_buff, PATH_MAX);
	new_pathname = d_absolute_path(new_path, new_buff, PATH_MAX);

	printk(KERN_ERR "old_path %s\n", old_pathname);
	printk(KERN_ERR "new_path %s\n", new_pathname);

	kfree(old_buff);
	kfree(new_buff);

	return err;
}

/**
 * This function use to tracking mount activity.
 * Trigger after success allocate disk
 * Tracking info: device name / disk format 
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
static int honeybest_mount(const char *dev_name,
                         const struct path *path,
                         const char *type,
                         unsigned long flags,
                         void *data)
#else
static int honeybest_mount(const char *dev_name, struct path *path,
                         const char *type, unsigned long flags, void *data)
#endif
{
	int err = 0;
	struct cred *cred = (struct cred *) current->real_cred;
	char *na = "N/A";
	char uid[UID_STR_SIZE];
	hb_sb_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_SB_MOUNT))
	       	err = -ENOMEM;

	record = search_sb_record(HB_SB_MOUNT, current->cred->uid.val, na, (char *)na, (char *)dev_name, (char *)type, flags);

	if (record) {
		;//printk(KERN_INFO "Found sb mount record func=%u, uid %u, dev_name=%s, type name=%s, flags=%d\n", record->fid, record->uid, record->dev_name, record->type, record->flags);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_sb_record(HB_SB_MOUNT, uid, 'A', na, na, (char *)dev_name, (char *)type, flags, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_sb_record(HB_SB_MOUNT, uid, 'R', na, na, (char *)dev_name, (char *)type, flags, interact);

		if ((locking == 1) && (bl == 0))
			err = -EOPNOTSUPP;
	}

	return err;
}

/**
 * This function use to tracking umount activity.
 * Trigger after success deallocate disk
 * Tracking info: superblock id / disk format 
 */
static int honeybest_umount(struct vfsmount *mnt, int flags)
{
	int err = 0;
	struct cred *cred = (struct cred *) current->real_cred;
       	struct super_block *sb = mnt->mnt_sb;
	char *na = "N/A";
	char uid[UID_STR_SIZE];
	hb_sb_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_SB_UMOUNT))
	       	err = -ENOMEM;

	if (!sb)
		return err;

	record = search_sb_record(HB_SB_UMOUNT, current->cred->uid.val, sb->s_id, (char *)sb->s_type->name, na, na, flags);

	if (record) {
		;//printk(KERN_INFO "Found sb umount record func=%u, uid %u, dev_name=%s, type name=%s, flags=%d\n", record->fid, record->uid, record->dev_name, record->type, record->flags);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_sb_record(HB_SB_UMOUNT, uid, 'A', sb->s_id, (char *)sb->s_type->name, na, na, flags, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_sb_record(HB_SB_UMOUNT, uid, 'R', sb->s_id, (char *)sb->s_type->name, na, na, flags, interact);

		if ((locking == 1) && (bl == 0))
			err = -EOPNOTSUPP;
	}

	return err;
}

static int honeybest_inode_alloc_security(struct inode *inode)
{
	int err = 0;

	if (!enabled)
		return err;

	return err;
}

static void honeybest_inode_free_security(struct inode *inode)
{

	if (!enabled)
		return;
	return;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
static int honeybest_dentry_init_security(struct dentry *dentry, int mode,
                                        const struct qstr *name, void **ctx,
                                        u32 *ctxlen)
{
	int err = 0;

	if (!enabled)
		return err;

	return err;
}

/**
 * This function use to tracking remove file activity.
 * Trigger during remove file
 * Tracking info: user id / source file
 */
static int honeybest_path_unlink(const struct path *dir, struct dentry *dentry)
#else
static int honeybest_path_unlink(struct path *dir, struct dentry *dentry)
#endif
{

	int err = 0;
       	struct task_struct *task = current;
	struct cred *cred = (struct cred *) current->real_cred;
	struct mm_struct *mm = current->mm;
       	char *binprm = NULL;
       	char *taskname = NULL;
	struct path source = { dir->mnt, dentry };
	char *s_path = NULL;
       	char *t_path = "N/A";
	char *s_buff = NULL;
	char tuid[UID_STR_SIZE];
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_PATH_UNLINK))
	       	err = -ENOMEM;

	/* extract full path */
	s_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	s_path = d_absolute_path(&source, s_buff, PATH_MAX);

	if (s_buff == NULL) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!s_path) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	if (allow_file_whitelist(s_path)) {
		goto out1;
	}

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
				//printk(KERN_ERR "binprm %s, file %s\n", binprm, filename);
			}
			else
				goto out1;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out2;

	record = search_path_record(HB_PATH_UNLINK, current->cred->uid.val, 0, s_path, t_path, 0, 0, 0, binprm);

	if (record) {
	       	;//printk(KERN_INFO "Found path unlink record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->s_path, record->t_path);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(tuid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_path_record(HB_PATH_UNLINK, tuid, 'A', 0, s_path, t_path, 0, 0, 0, binprm, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_path_record(HB_PATH_UNLINK, tuid, 'R', 0, s_path, t_path, 0, 0, 0, binprm, interact);

		if ((locking == 1) && (bl == 0))
			err = -EOPNOTSUPP;
	}
out2:
	kfree(taskname);
out1:
	kfree(s_buff);
out:
	return err;
}

/**
 * This function use to tracking create directory activity.
 * Trigger during create directory
 * Tracking info: user id / directory mode / directory
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
static int honeybest_path_mkdir(const struct path *dir, struct dentry *dentry,
			       umode_t mode)
#else
static int honeybest_path_mkdir(struct path *dir, struct dentry *dentry,
			       umode_t mode)
#endif
{

	int err = 0;
       	struct task_struct *task = current;
	struct cred *cred = (struct cred *) current->real_cred;
	struct mm_struct *mm = current->mm;
       	char *binprm = NULL;
       	char *taskname = NULL;
	struct path source = { dir->mnt, dentry };
	char *s_path = NULL;
       	char *t_path = "N/A";
	char *s_buff = NULL;
	char tuid[UID_STR_SIZE];
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_PATH_MKDIR))
	       	err = -ENOMEM;

	/* extract full path */
	s_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	s_path = d_absolute_path(&source, s_buff, PATH_MAX);

	if (!s_buff) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!s_path) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	if (allow_file_whitelist(s_path)) {
		goto out1;
	}

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
				//printk(KERN_ERR "binprm %s, file %s\n", binprm, filename);
			}
			else
				goto out1;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out2;

	record = search_path_record(HB_PATH_MKDIR, current->cred->uid.val, mode, s_path, t_path, 0, 0, 0, binprm);

	if (record) {
	       	;//printk(KERN_INFO "Found path mkdir record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->s_path, record->t_path);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(tuid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_path_record(HB_PATH_MKDIR, tuid, 'A', mode, s_path, t_path, 0, 0, 0, binprm, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_path_record(HB_PATH_MKDIR, tuid, 'R', mode, s_path, t_path, 0, 0, 0, binprm, interact);

		if ((locking == 1) && (bl == 0))
			err = -EOPNOTSUPP;
	}
out2:
	kfree(taskname);
out1:
	kfree(s_buff);
out:
	return err;
}

/**
 * This function use to tracking remove directory activity.
 * Trigger during remove directory
 * Tracking info: user id / directory name
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
static int honeybest_path_rmdir(const struct path *dir, struct dentry *dentry)
#else
static int honeybest_path_rmdir(struct path *dir, struct dentry *dentry)
#endif
{

	int err = 0;
       	struct task_struct *task = current;
	struct cred *cred = (struct cred *) current->real_cred;
	struct mm_struct *mm = current->mm;
       	char *binprm = NULL;
       	char *taskname = NULL;
	struct path source = { dir->mnt, dentry };
	char *s_path = NULL;
       	char *t_path = "N/A";
	char *s_buff = NULL;
	char tuid[UID_STR_SIZE];
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_PATH_RMDIR))
	       	err = -ENOMEM;

	/* extract full path */
	s_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	s_path = d_absolute_path(&source, s_buff, PATH_MAX);

	if (!s_buff) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!s_path) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
				//printk(KERN_ERR "binprm %s, file %s\n", binprm, filename);
			}
			else
				goto out1;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out2;

	record = search_path_record(HB_PATH_RMDIR, current->cred->uid.val, 0, s_path, t_path, 0, 0, 0, binprm);

	if (record) {
	       	;//printk(KERN_INFO "Found path rmdir record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->s_path, record->t_path);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(tuid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_path_record(HB_PATH_RMDIR, tuid, 'A', 0, s_path, t_path, 0, 0, 0, binprm, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_path_record(HB_PATH_RMDIR, tuid, 'R', 0, s_path, t_path, 0, 0, 0, binprm, interact);

		if ((locking == 1) && (bl == 0))
			err = -EOPNOTSUPP;
	}
out2:
	kfree(taskname);
out1:
	kfree(s_buff);
out:
	return err;
}

/**
 * This function use to tracking create device node activity.
 * Trigger during create device node
 * Tracking info: user id / mode / device node name
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
static int honeybest_path_mknod(const struct path *dir, struct dentry *dentry,
			       umode_t mode, unsigned int dev)
#else
static int honeybest_path_mknod(struct path *dir, struct dentry *dentry,
			       umode_t mode, unsigned int dev)
#endif
{

	int err = 0;
       	struct task_struct *task = current;
	struct cred *cred = (struct cred *) current->real_cred;
	struct mm_struct *mm = current->mm;
       	char *binprm = NULL;
       	char *taskname = NULL;
	struct path source = { dir->mnt, dentry };
	char *s_path = NULL;
       	char *t_path = "N/A";
	char *s_buff = NULL;
	char tuid[UID_STR_SIZE];
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_PATH_MKNOD))
	       	err = -ENOMEM;

	/* extract full path */
	s_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	s_path = d_absolute_path(&source, s_buff, PATH_MAX);

	if (!s_buff) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!s_path) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	if (allow_file_whitelist(s_path)) {
		goto out1;
	}

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
				//printk(KERN_ERR "binprm %s, file %s\n", binprm, filename);
			}
			else
				goto out1;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out2;

	record = search_path_record(HB_PATH_MKNOD, current->cred->uid.val, mode, s_path, t_path, 0, 0, dev, binprm);

	if (record) {
	       	;//printk(KERN_INFO "Found path mknod record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->s_path, record->t_path);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(tuid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_path_record(HB_PATH_MKNOD, tuid, 'A', mode, s_path, t_path, 0, 0, dev, binprm, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_path_record(HB_PATH_MKNOD, tuid, 'R', mode, s_path, t_path, 0, 0, dev, binprm, interact);

		if ((locking == 1) && (bl == 0))
			err = -EOPNOTSUPP;
	}
out2:
	kfree(taskname);
out1:
	kfree(s_buff);
out:
	return err;
}

/**
 * This function use to tracking resize file activity.
 * Trigger during resize file
 * Tracking info: user id / file name
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
static int honeybest_path_truncate(const struct path *path)
#else
static int honeybest_path_truncate(struct path *path)
#endif
{
	int err = 0;
       	struct task_struct *task = current;
	struct cred *cred = (struct cred *) current->real_cred;
	struct mm_struct *mm = current->mm;
       	char *binprm = NULL;
       	char *taskname = NULL;
	char *s_path = NULL;
       	char *t_path = "N/A";
	char *s_buff = NULL;
	char tuid[UID_STR_SIZE];
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_PATH_TRUNCATE))
	       	err = -ENOMEM;

	/* extract full path */
	s_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	s_path = d_absolute_path(path, s_buff, PATH_MAX);

	if (s_buff == NULL) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!s_path) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	if (allow_file_whitelist(s_path)) {
		goto out1;
	}

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
				//printk(KERN_ERR "binprm %s, file %s\n", binprm, filename);
			}
			else
				goto out1;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out2;

	record = search_path_record(HB_PATH_TRUNCATE, current->cred->uid.val, 0, s_path, t_path, 0, 0, 0, binprm);

	if (record) {
	       	;//printk(KERN_INFO "Found path truncate record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->s_path, record->t_path);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(tuid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_path_record(HB_PATH_TRUNCATE, tuid, 'A', 0, s_path, t_path, 0, 0, 0, binprm, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_path_record(HB_PATH_TRUNCATE, tuid, 'R', 0, s_path, t_path, 0, 0, 0, binprm, interact);

		if ((locking == 1) && (bl == 0))
			err = -EOPNOTSUPP;
	}
out2:
	kfree(taskname);
out1:
	kfree(s_buff);
out:
	return err;
}

/**
 * This function use to tracking symbolic file activity.
 * Trigger during create symbolic file
 * Tracking info: user id / source filename / target filename
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
static int honeybest_path_symlink(const struct path *dir, struct dentry *dentry,
				 const char *old_name)
#else
static int honeybest_path_symlink(struct path *dir, struct dentry *dentry,
				 const char *old_name)
#endif
{

	int err = 0;
       	struct task_struct *task = current;
	struct cred *cred = (struct cred *) current->real_cred;
	struct mm_struct *mm = current->mm;
       	char *binprm = NULL;
       	char *taskname = NULL;
	struct path target = { dir->mnt, dentry };
	char *s_path = (char *)old_name;
       	char *t_path = NULL;
	char *t_buff = NULL;
	char tuid[UID_STR_SIZE];
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_PATH_SYMLINK))
	       	err = -ENOMEM;

	/* extract full path */
	t_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	t_path = d_absolute_path(&target, t_buff, PATH_MAX);

	if (t_buff == NULL) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!t_path) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
				//printk(KERN_ERR "binprm %s, file %s\n", binprm, filename);
			}
			else
				goto out1;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out2;

	record = search_path_record(HB_PATH_SYMLINK, current->cred->uid.val, 0, s_path, t_path, 0, 0, 0, binprm);

	if (record) {
	       	;//printk(KERN_INFO "Found path symlink record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->s_path, record->t_path);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(tuid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_path_record(HB_PATH_SYMLINK, tuid, 'A', 0, s_path, t_path, 0, 0, 0, binprm, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_path_record(HB_PATH_SYMLINK, tuid, 'R', 0, s_path, t_path, 0, 0, 0, binprm, interact);

		if ((locking == 1) && (bl == 0))
			err = -EOPNOTSUPP;
	}
out2:
	kfree(taskname);
out1:
	kfree(t_buff);
out:
	return err;
}

/**
 * This function use to tracking hard link file activity.
 * Trigger during create hard symbolic link
 * Tracking info: user id / source filename / target filename
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
static int honeybest_path_link(struct dentry *old_dentry, const struct path *new_dir,
			      struct dentry *new_dentry)
#else

static int honeybest_path_link(struct dentry *old_dentry, struct path *new_dir,
			      struct dentry *new_dentry)
#endif
{
	int err = 0;
       	struct task_struct *task = current;
	struct cred *cred = (struct cred *) current->real_cred;
	struct mm_struct *mm = current->mm;
       	char *binprm = NULL;
       	char *taskname = NULL;
	struct path source = { new_dir->mnt, new_dentry };
	struct path target = { new_dir->mnt, old_dentry };
	char *s_path = NULL;
       	char *t_path = NULL;
	char *s_buff = NULL;
	char *t_buff = NULL;
	char tuid[UID_STR_SIZE];
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_PATH_LINK))
	       	err = -ENOMEM;

	/* extract full path */
	s_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	s_path = d_absolute_path(&source, s_buff, PATH_MAX);

	if (!s_buff) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!s_path) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	t_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	t_path = d_absolute_path(&target, t_buff, PATH_MAX);

	if (!t_buff) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	if (!t_path) {
		err = -EOPNOTSUPP;
		goto out2;
	}

	if (allow_file_whitelist(s_path)) {
		goto out2;
	}

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
				//printk(KERN_ERR "binprm %s, file %s\n", binprm, filename);
			}
			else
				goto out2;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out3;

	record = search_path_record(HB_PATH_LINK, current->cred->uid.val, 0, s_path, t_path, 0, 0, 0, binprm);

	if (record) {
	       	;//printk(KERN_INFO "Found path link record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->s_path, record->t_path);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(tuid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_path_record(HB_PATH_LINK, tuid, 'A', 0, s_path, t_path, 0, 0, 0, binprm, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_path_record(HB_PATH_LINK, tuid, 'R', 0, s_path, t_path, 0, 0, 0, binprm, interact);

		if ((locking == 1) && (bl == 0))
			err = -EOPNOTSUPP;
	}
out3:
	kfree(taskname);
out2:
	kfree(t_buff);
out1:
	kfree(s_buff);
out:
	return err;
}

/**
 * This function use to tracking rename file activity.
 * Trigger during rename
 * Tracking info: user id / source filename / target filename
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
static int honeybest_path_rename(const struct path *old_dir, struct dentry *old_dentry,
				const struct path *new_dir, struct dentry *new_dentry)
#else
static int honeybest_path_rename(struct path *old_dir, struct dentry *old_dentry,
				struct path *new_dir, struct dentry *new_dentry)
#endif
{
	int err = 0;
       	struct task_struct *task = current;
	struct cred *cred = (struct cred *) current->real_cred;
	struct mm_struct *mm = current->mm;
       	char *binprm = NULL;
       	char *taskname = NULL;
	struct path target = { new_dir->mnt, new_dentry };
	struct path source = { old_dir->mnt, old_dentry };
	char *s_path = NULL;
       	char *t_path = NULL;
	char *s_buff = NULL;
	char *t_buff = NULL;
	char tuid[UID_STR_SIZE];
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_PATH_RENAME))
	       	err = -ENOMEM;

	/* extract full path */
	s_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	s_path = d_absolute_path(&source, s_buff, PATH_MAX);

	if (!s_buff) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!s_path) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	t_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	t_path = d_absolute_path(&target, t_buff, PATH_MAX);

	if (!t_buff) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	if (!t_path) {
		err = -EOPNOTSUPP;
		goto out2;
	}

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
				//printk(KERN_ERR "binprm %s, file %s\n", binprm, filename);
			}
			else
				goto out2;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out3;

	record = search_path_record(HB_PATH_RENAME, current->cred->uid.val, 0, s_path, t_path, 0, 0, 0, binprm);

	if (record) {
	       	;//printk(KERN_INFO "Found path rename record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->s_path, record->t_path);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(tuid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_path_record(HB_PATH_RENAME, tuid, 'A', 0, s_path, t_path, 0, 0, 0, binprm, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_path_record(HB_PATH_RENAME, tuid, 'R', 0, s_path, t_path, 0, 0, 0, binprm, interact);

		if ((locking == 1) && (bl == 0))
			err = -EOPNOTSUPP;
	}
out3:
	kfree(taskname);
out2:
	kfree(t_buff);
out1:
	kfree(s_buff);
out:
	return err;
}

/**
 * This function use to tracking change file mode activity.
 * Trigger during file mode change
 * Tracking info: user id / mode / source filename / target filename
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
static int honeybest_path_chmod(const struct path *path, umode_t mode)
#else
static int honeybest_path_chmod(struct path *path, umode_t mode)
#endif
{
	int err = 0;
       	struct task_struct *task = current;
	struct cred *cred = (struct cred *) current->real_cred;
	struct mm_struct *mm = current->mm;
       	char *binprm = NULL;
       	char *taskname = NULL;
	char *s_path = NULL;
       	char *t_path = "N/A";
	char *s_buff = NULL;
	char tuid[UID_STR_SIZE];
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_PATH_CHMOD))
	       	err = -ENOMEM;

	/* extract full path */
	s_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	s_path = d_absolute_path(path, s_buff, PATH_MAX);

	if (s_buff == NULL) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!s_path) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
				//printk(KERN_ERR "binprm %s, file %s\n", binprm, filename);
			}
			else
			       	goto out1;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out2;

	record = search_path_record(HB_PATH_CHMOD, current->cred->uid.val, mode, s_path, t_path, 0, 0, 0, binprm);

	if (record) {
	       	;//printk(KERN_INFO "Found path chmod record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->s_path, record->t_path);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(tuid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_path_record(HB_PATH_CHMOD, tuid, 'A', mode, s_path, t_path, 0, 0, 0, binprm, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_path_record(HB_PATH_CHMOD, tuid, 'R', mode, s_path, t_path, 0, 0, 0, binprm, interact);

		if ((locking == 1) && (bl == 0))
			err = -EOPNOTSUPP;
	}
out2:
	kfree(taskname);
out1:
	kfree(s_buff);
out:
	return err;
}

/**
 * This function use to tracking change owner activity.
 * Trigger during file owner change
 * Tracking info: user id / source filename / uid / gid
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
int honeybest_path_chown(const struct path *path, kuid_t uid, kgid_t gid)
#else
static int honeybest_path_chown(struct path *path, kuid_t uid, kgid_t gid)
#endif
{
	int err = 0;
       	struct task_struct *task = current;
	struct cred *cred = (struct cred *) current->real_cred;
	struct mm_struct *mm = current->mm;
       	char *binprm = NULL;
       	char *taskname = NULL;
	char *s_path = NULL;
       	char *t_path = "N/A";
	char *s_buff = NULL;
	char tuid[UID_STR_SIZE];
	hb_path_ll *record = NULL;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_PATH_CHOWN))
	       	err = -ENOMEM;

	/* extract full path */
	s_buff = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	s_path = d_absolute_path(path, s_buff, PATH_MAX);

	if (s_buff == NULL) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!s_path) {
		err = -EOPNOTSUPP;
		goto out1;
	}

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
				//printk(KERN_ERR "binprm %s, file %s\n", binprm, filename);
			}
			else
				goto out1;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out2;

	record = search_path_record(HB_PATH_CHOWN, current->cred->uid.val, 0, s_path, t_path, uid.val, gid.val, 0, binprm);

	if (record) {
	       	;//printk(KERN_INFO "Found path chmod record func=%u, uid %u, source=%s, target=%s\n", record->fid, record->uid, record->s_path, record->t_path);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(tuid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_path_record(HB_PATH_CHOWN, tuid, 'A', 0, s_path, t_path, uid.val, gid.val, 0, binprm, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_path_record(HB_PATH_CHOWN, tuid, 'R', 0, s_path, t_path, uid.val, gid.val, 0, binprm, interact);

		if ((locking == 1) && (bl == 0))
			err = -EOPNOTSUPP;
	}
out2:
	kfree(taskname);
out1:
	kfree(s_buff);
out:
	return err;
}

static int honeybest_inode_init_security(struct inode *inode, struct inode *dir,
                                       const struct qstr *qstr,
                                       const char **name,
                                       void **value, size_t *len)
{
	int err = 0;

	if (!enabled)
		return err;

	return -EOPNOTSUPP;
}

static int honeybest_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err = 0;

	if (!enabled)
		return err;

        return err;
}

static int honeybest_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	int err = 0;

	if (!enabled)
		return err;

        return err;
}

static int honeybest_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	int err = 0;

	if (!enabled)
		return err;

        return err;
}

static int honeybest_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
	int err = 0;

	if (!enabled)
		return err;

        return err;
}

static int honeybest_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mask)
{
	int err = 0;

	if (!enabled)
		return err;

        return err;
}

static int honeybest_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	int err = 0;

	if (!enabled)
		return err;

        return err;
}

static int honeybest_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	int err = 0;

	if (!enabled)
		return err;

        return err;
}

static int honeybest_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
                                struct inode *new_inode, struct dentry *new_dentry)
{
	int err = 0;

	if (!enabled)
		return err;

        return err;
}

static int honeybest_inode_readlink(struct dentry *dentry)
{
	int err = 0;

	if (!enabled)
		return err;

        return err;
}

static int honeybest_inode_follow_link(struct dentry *dentry, struct inode *inode,
                                     bool rcu)
{
	int err = 0;

	if (!enabled)
		return err;

        return err;
}

static int honeybest_inode_permission(struct inode *inode, int mask)
{
	int err = 0;

	if (!enabled)
		return err;

        return err;
}

static int honeybest_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
	int err = 0;

	if (!enabled)
		return err;

        return err;
}

static int honeybest_inode_getattr(const struct path *path)
{
	int err = 0;

	if (!enabled)
		return err;

        return err;
}

/**
 * This function use to tracking add extend attribute activity.
 * Trigger during add file extend attribute
 * Tracking info: user id / xattr key / xattr value
 */
static int honeybest_inode_setxattr(struct dentry *dentry, const char *name,
                                  const void *value, size_t size, int flags)
{
	int err = 0;
	struct cred *cred = (struct cred *) current->real_cred;
	char *pathname = NULL;
       	char *binprm = NULL;
	char uid[UID_STR_SIZE];
	hb_inode_ll *record;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_INODE_SETXATTR))
	       	err = -ENOMEM;

	pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
	binprm = dentry_path_raw(dentry, pathname, PATH_MAX);

	if (!pathname)
		goto out;

	if (!binprm)
		goto out1;

	record = search_inode_record(HB_INODE_SETXATTR, current->cred->uid.val, (char *)name, binprm);

	if (record) {
		;//printk(KERN_INFO "Found inode setxattr name %s, dname %s\n", name, dname);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_inode_record(HB_INODE_SETXATTR, uid, 'A', (char *)name, binprm, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_inode_record(HB_INODE_SETXATTR, uid, 'R', (char *)name, binprm, interact);

		if ((locking == 1) && (bl == 0)) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}

out1:
	kfree(pathname);
out:
        return err;
}

static void honeybest_inode_post_setxattr(struct dentry *dentry, const char *name,
                                        const void *value, size_t size,
                                        int flags)
{
	return ;
}

/**
 * This function use to tracking read extend attribute activity.
 * Trigger during read file extend attribute
 * Tracking info: user id / xattr key / xattr value
 */
static int honeybest_inode_getxattr(struct dentry *dentry, const char *name)
{
	int err = 0;
	struct cred *cred = (struct cred *) current->real_cred;
	char *pathname = NULL;
       	char *binprm = NULL;
	char uid[UID_STR_SIZE];
	hb_inode_ll *record;

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_INODE_GETXATTR))
	       	err = -ENOMEM;

	pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
	binprm = dentry_path_raw(dentry, pathname, PATH_MAX);

	if (!pathname)
		goto out;

	if (!binprm)
		goto out1;

	record = search_inode_record(HB_INODE_GETXATTR, current->cred->uid.val, (char *)name, binprm);

	if (record) {
		;//printk(KERN_ERR "Found inode getxattr name %s, dname %s\n", name, binprm);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0))
			err = add_inode_record(HB_INODE_GETXATTR, uid, 'A', (char *)name, binprm, interact);

		if ((locking == 0) && (bl == 1))
			err = add_inode_record(HB_INODE_GETXATTR, uid, 'R', (char *)name, binprm, interact);

		if ((locking == 1) && (bl == 0)) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}

out1:
	kfree(pathname);
out:
        return err;
}

static int honeybest_inode_listxattr(struct dentry *dentry)
{
	int err = 0;
	struct cred *cred = (struct cred *) current->real_cred;
	char *name = "N/A";
	char *pathname = NULL;
       	char *binprm = NULL;
	hb_inode_ll *record;
	char uid[UID_STR_SIZE];

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_INODE_LISTXATTR))
	       	err = -ENOMEM;

	pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
	binprm = dentry_path_raw(dentry, pathname, PATH_MAX);

	if (!pathname)
		goto out;

	if (!binprm)
		goto out1;

	record = search_inode_record(HB_INODE_LISTXATTR, current->cred->uid.val, (char *)name, binprm);

	if (record) {
		;//printk(KERN_INFO "Found inode setxattr name %s, dname %s\n", name, dname);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_inode_record(HB_INODE_LISTXATTR, uid, 'A', (char *)name, binprm, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_inode_record(HB_INODE_LISTXATTR, uid, 'R', (char *)name, binprm, interact);

		if ((locking == 1) && (bl == 0)) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}

out1:
	kfree(pathname);
out:
        return err;
}

/**
 * This function use to tracking remove extend attribute activity.
 * Trigger during remove file extend attribute
 * Tracking info: user id / xattr key / xattr value
 */
static int honeybest_inode_removexattr(struct dentry *dentry, const char *name)
{
	int err = 0;
	struct cred *cred = (struct cred *) current->real_cred;
	char *pathname = NULL;
       	char *binprm = NULL;
	hb_inode_ll *record;
	char uid[UID_STR_SIZE];

	if (!enabled)
		return err;

	if (inject_honeybest_tracker(cred, HB_INODE_REMOVEXATTR))
	       	err = -ENOMEM;

	pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
	binprm = dentry_path_raw(dentry, pathname, PATH_MAX);

	if (!pathname)
		goto out;

	if (!binprm)
		goto out1;

	record = search_inode_record(HB_INODE_REMOVEXATTR, current->cred->uid.val, (char *)name, binprm);

	if (record) {
		;//printk(KERN_INFO "Found inode removexattr name %s, dname %s\n", name, dname);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_inode_record(HB_INODE_REMOVEXATTR, uid, 'A', (char *)name, binprm, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_inode_record(HB_INODE_REMOVEXATTR, uid, 'R', (char *)name, binprm, interact);

		if ((locking == 1) && (bl == 0)) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}
out1:
	kfree(pathname);
out:
        return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
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


#endif

static int honeybest_file_permission(struct file *file, int mask)
{
	return 0;
}

static int honeybest_file_alloc_security(struct file *file)
{
	int err = 0;

	if (!enabled)
		return err;

	return err;
}

static void honeybest_file_free_security(struct file *file)
{

	if (!enabled)
		return;

	return;
}

static int honeybest_file_ioctl(struct file *file, unsigned int cmd,
                              unsigned long arg)
{
	int err = 0;
       	struct task_struct *task = current;
	struct cred *cred = (struct cred *) current->real_cred;
	hb_file_ll *record = NULL;
	struct mm_struct *mm = current->mm;
	char *filename = NULL;
       	char *binprm = NULL;
	char uid[UID_STR_SIZE];
       	char *taskname = NULL;

	if (!enabled) {
		return err;
	}

	if (inject_honeybest_tracker(cred, HB_FILE_IOCTL))
	       	err = -ENOMEM;

	filename = kstrdup_quotable_file(file, GFP_KERNEL);

	if (!filename)
		goto out;

	if (allow_file_whitelist(filename)) {
		goto out1;
	}

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
				//printk(KERN_ERR "binprm %s, file %s\n", binprm, filename);
			}
			else
				goto out1;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out2;

	record = search_file_record(HB_FILE_IOCTL, current->cred->uid.val, filename, binprm, cmd);

	if (record) {
	       	;//printk(KERN_INFO "Found file open record func=%u, path=[%s]\n", record->fid, record->filename);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0))
			err = add_file_record(HB_FILE_IOCTL, uid, 'A', filename, binprm, cmd, interact);

		if ((locking == 0) && (bl == 1))
			err = add_file_record(HB_FILE_IOCTL, uid, 'R', filename, binprm, cmd, interact);

		if ((locking == 1) && (bl == 0)) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}
out2:
	kfree(taskname);
out1:
	kfree(filename);
out:
        return err;

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
	int err = 0;
       	struct task_struct *task = current;
	struct cred *cred = (struct cred *) current->real_cred;
	hb_file_ll *record = NULL;
	struct mm_struct *mm = current->mm;
	char *filename = NULL;
       	char *binprm = NULL;
	char uid[UID_STR_SIZE];
       	char *taskname = NULL;

	if (!enabled) {
		return err;
	}

	if (inject_honeybest_tracker(cred, HB_FILE_RECEIVE))
	       	err = -ENOMEM;

	filename = kstrdup_quotable_file(file, GFP_KERNEL);

	if (!filename)
		goto out;

	if (allow_file_whitelist(filename)) {
		goto out1;
	}

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
				//printk(KERN_ERR "binprm %s, file %s\n", binprm, filename);
			}
			else
				goto out1;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out2;

	record = search_file_record(HB_FILE_RECEIVE, current->cred->uid.val, filename, binprm, 0);

	if (record) {
	       	;//printk(KERN_INFO "Found file open record func=%u, path=[%s]\n", record->fid, record->filename);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0))
			err = add_file_record(HB_FILE_RECEIVE, uid, 'A', filename, binprm, 0, interact);

		if ((locking == 0) && (bl == 1))
			err = add_file_record(HB_FILE_RECEIVE, uid, 'R', filename, binprm, 0, interact);

		if ((locking == 1) && (bl == 0)) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}
out2:
	kfree(taskname);
out1:
	kfree(filename);
out:
        return err;

}

/**
 * This function use to tracking open file activity.
 * Trigger during open file
 * Tracking info: user id / filename / digest? (future)
 */
static int honeybest_file_open(struct file *file, const struct cred *cred)
{
	int err = 0;
       	struct task_struct *task = current;
	hb_file_ll *record = NULL;
	struct cred *file_cred = (struct cred *)cred;
	struct mm_struct *mm = current->mm;
	char *filename = NULL;
       	char *binprm = NULL;
	char uid[UID_STR_SIZE];
       	char *taskname = NULL;

	if (!enabled) {
		return err;
	}

	if (inject_honeybest_tracker(file_cred, HB_FILE_OPEN))
	       	err = -ENOMEM;

	filename = kstrdup_quotable_file(file, GFP_KERNEL);

	if (!filename)
		goto out;

	if (allow_file_whitelist(filename)) {
		goto out1;
	}

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
				//printk(KERN_ERR "binprm %s, file %s\n", binprm, filename);
			}
			else
				goto out1;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out2;

	record = search_file_record(HB_FILE_OPEN, current->cred->uid.val, filename, binprm, 0);

	if (record) {
	       	;//printk(KERN_INFO "Found file open record func=%u, path=[%s]\n", record->fid, record->filename);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0))
			err = add_file_record(HB_FILE_OPEN, uid, 'A', filename, binprm, 0, interact);

		if ((locking == 0) && (bl == 1))
			err = add_file_record(HB_FILE_OPEN, uid, 'R', filename, binprm, 0, interact);

		if ((locking == 1) && (bl == 0)) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}
out2:
	kfree(taskname);
out1:
	kfree(filename);
out:
        return err;

}

static int honeybest_task_create(unsigned long clone_flags)
{
	int err = 0;

	if (!enabled) {
		return err;
	}

        return err;
}

static int honeybest_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	int err = 0;

	if (!enabled) {
		return err;
	}

	if (inject_honeybest_tracker(cred, HB_CRED_ALLOC_BLANK))
	       	err = -ENOMEM;

        return err;
}

static void honeybest_cred_free(struct cred *cred)
{
	int err = 0;

	if (!enabled)
		return;

	if (free_honeybest_tracker(cred))
	       	err = -ENOMEM;

	return;
}


static int honeybest_cred_prepare(struct cred *new, const struct cred *old,
                                gfp_t gfp)
{
	int err = 0;
	hb_track_info *old_sec = NULL;
	hb_track_info *new_sec = NULL;

	if (!enabled)
		return err;

	old_sec = old->security;
	if (old_sec) {
		new_sec = kmemdup(old_sec, sizeof(hb_track_info), gfp);
		if (new_sec) {
			new->security = (hb_track_info *)new_sec;
		}
		else
			err = -ENOMEM;
	}

        return err;
}

static void honeybest_cred_transfer(struct cred *new, const struct cred *old)
{
	hb_track_info *sec = old->security;

	if (!enabled)
		return;

	if (sec) {
		sec->tsid = task_seq;
		new->security = (hb_track_info *)sec;
	}
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

/**
 * This function use to tracking kernel load driver activity.
 * Trigger during insmod/rmmod
 * Tracking info: user id / driver register name
 */
static int honeybest_kernel_module_from_file(struct file *file)
{
	int err = 0;
	hb_kmod_ll *record = NULL;
	struct cred *cred = (struct cred *) current->real_cred;
	char *filename = NULL;
	char *na = "N/A";
	char uid[UID_STR_SIZE];
	char digest[SHA1_HONEYBEST_DIGEST_SIZE];

	if (!enabled) {
		return err;
	}

	if (inject_honeybest_tracker(cred, HB_KMOD_LOAD_FROM_FILE))
	       	err = -ENOMEM;

	filename = kstrdup_quotable_file(file, GFP_KERNEL);

	if (!filename)
		goto out;

	if (allow_file_whitelist(filename)) {
		goto out1;
	}

	memset(digest, '\0', SHA1_HONEYBEST_DIGEST_SIZE);
	lookup_binprm_digest(file, digest);

	record = search_kmod_record(HB_KMOD_LOAD_FROM_FILE, current->cred->uid.val, na, filename, digest);

	if (record) {
	       	;//printk(KERN_INFO "Found file open record func=%u, path=[%s]\n", record->fid, record->filename);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0))
			err = add_kmod_record(HB_KMOD_LOAD_FROM_FILE, uid, 'A', na, filename, digest, interact);

		if ((locking == 0) && (bl == 1))
			err = add_kmod_record(HB_KMOD_LOAD_FROM_FILE, uid, 'R', na, filename, digest, interact);

		if ((locking == 1) && (bl == 0)) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}
out1:
	kfree(filename);
out:
        return err;

}

/**
 * This function use to tracking kernel load driver activity.
 * Trigger during insmod/rmmod
 * Tracking info: user id / driver register name
 */
static int honeybest_kernel_module_request(char *kmod_name)
{
	int err = 0;
	struct cred *cred = (struct cred *) current->real_cred;
	char uid[UID_STR_SIZE];
	char *na = "N/A";
	hb_kmod_ll *record = NULL;

	if (!enabled) {
		return err;
	}

	if (inject_honeybest_tracker(cred, HB_KMOD_REQ))
	       	err = -ENOMEM;

	record = search_kmod_record(HB_KMOD_REQ, current->cred->uid.val, kmod_name, na, na);

	if (record) {
		;//printk(KERN_INFO "Found kmod record func=%u, uid %u, name=%s\n", record->fid, record->uid, record->name);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_kmod_record(HB_KMOD_REQ, uid, 'A', kmod_name, na, na, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_kmod_record(HB_KMOD_REQ, uid, 'R', kmod_name, na, na, interact);

		if ((locking == 1) && (bl == 0))
			err = -EOPNOTSUPP;
	}

        return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
static int honeybest_kernel_read_file(struct file *file, enum kernel_read_file_id id)
{
	return 0;
}
#endif

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

/**
 * This function use to tracking between process signal activity.
 * Trigger during kill [NUMBER]
 * Tracking info: user id / signal number / signal err / securityID
 */
static int honeybest_task_kill(struct task_struct *p, struct siginfo *info,
                                int sig, u32 secid)
{
	int err = 0;
       	struct task_struct *task = current;
	struct cred *cred = (struct cred *) current->real_cred;
	struct mm_struct *mm = current->mm;
       	char *binprm = NULL;
       	char *taskname = NULL;
	char uid[UID_STR_SIZE];
	hb_task_ll *record;

	if (!enabled) {
		return err;
	}

	if (inject_honeybest_tracker(cred, HB_TASK_SIGNAL))
	       	err = -ENOMEM;

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
				//printk(KERN_ERR "binprm %s, file %s\n", binprm, filename);
			}
			else
				goto out;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out1;

	record = search_task_record(HB_TASK_SIGNAL, current->cred->uid.val, info, sig, secid, binprm);

	if (record) {
		;//printk(KERN_INFO "Found task struct sig %d, secid %d, signo %d, errno %d\n", record->sig, record->secid, record->si_signo, record->si_errno);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) {
			if (info == NULL)
				err = add_task_record(HB_TASK_SIGNAL, uid, 'A', 0, 0, sig, secid, binprm, interact);
			else
				err = add_task_record(HB_TASK_SIGNAL, uid, 'R', info->si_signo\
						, info->si_errno, sig, secid, binprm, interact);
		}

		if ((locking == 0) && (bl == 1)) {
			if (info == NULL)
				err = add_task_record(HB_TASK_SIGNAL, uid, 'A', 0, 0, sig, secid, binprm, interact);
			else
				err = add_task_record(HB_TASK_SIGNAL, uid, 'R', info->si_signo\
						, info->si_errno, sig, secid, binprm, interact);
		}

		if ((locking == 1) && (bl == 0)) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}

out1:
	kfree(taskname);
out:
        return err;

}

static int honeybest_task_wait(struct task_struct *p)
{
        return 0;
}

static void honeybest_task_to_inode(struct task_struct *p,
                                  struct inode *inode)
{
#if 0
	struct dentry *dentry;
	struct mm_struct *mm = p->mm;
	char *pathname = NULL;
       	char *binprm = NULL;
	char *taskpath = NULL;
	char *taskbuff = NULL;
#endif

	if (!enabled)
		return;

#if 0
	/* inode */
	dentry = d_find_alias(inode);
	if (!dentry)
		goto out;

	pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
	binprm = dentry_path_raw(dentry, pathname, PATH_MAX);

	if(!binprm) {
		goto out1;
	}

	/* task */
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskbuff = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskbuff) {
				taskpath = d_path(&mm->exe_file->f_path, taskbuff, PATH_MAX);
				printk(KERN_ERR "%s --> pid %d, tgid %d, inode %s, pathname %s\n", __FUNCTION__, p->pid, p->tgid, binprm, taskpath);
				kfree(taskbuff);
			}
		}
		up_read(&mm->mmap_sem);
	}
out1:
	kfree(pathname);
out:
#endif
	return;
}

/**
 * This function use to tracking socket activity.
 * Trigger during bind/listen/create/connect
 * Tracking info: user id / inet family / udp_tcp / protocol / warning msg
 */
static int honeybest_socket_create(int family, int type,
                                 int protocol, int kern)
{
	int err = 0;
       	struct task_struct *task = current;
	struct cred *cred = (struct cred *)task->cred;
	struct mm_struct *mm = current->mm;
	char *taskname = NULL;
	char *binprm = NULL;
	char uid[UID_STR_SIZE];
	hb_socket_ll *record;

	if (!enabled)
	       	return err;

	if (inject_honeybest_tracker(cred, HB_SOCKET_CREATE))
		err = -ENOMEM;

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
			}
			else
				goto out;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out1;

	record = search_socket_record(HB_SOCKET_CREATE, current->cred->uid.val, family, type, protocol, 0, 0, 0, binprm);

	if (record) {
	       	;//printk(KERN_INFO "Found socket create record func=%u, family %d, type %d, protocol %d, kern %d\n", record->fid, family, type, protocol, kern);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_socket_record(HB_SOCKET_CREATE, uid, 'A', family, type, protocol, 0, 0, 0, binprm, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_socket_record(HB_SOCKET_CREATE, uid, 'R', family, type, protocol, 0, 0, 0, binprm, interact);

		if ((locking == 1) && (bl == 0)) 
			err = -EOPNOTSUPP;
	}

out1:
	kfree(taskname);
out:
	return err;
}

static int honeybest_socket_post_create(struct socket *sock, int family,
                                      int type, int protocol, int kern)
{
	return 0;
}

/**
 * This function use to tracking socket activity.
 * Trigger during bind
 * Tracking info: user id / interface / address / address length
 */
static int honeybest_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
       	struct task_struct *task = current;
	struct cred *cred = (struct cred *)task->cred;
	struct mm_struct *mm = current->mm;
	char *taskname = NULL;
	char *binprm = NULL;
	char uid[UID_STR_SIZE];
	hb_socket_ll *record;
	int port = 0;
	int err = 0;

	if (!enabled)
	       	return err;

	if (inject_honeybest_tracker(cred, HB_SOCKET_BIND))
		err = -ENOMEM;

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
			}
			else
				goto out;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out1;

	port = lookup_source_port(sock, address, addrlen);

	record = search_socket_record(HB_SOCKET_BIND, current->cred->uid.val, 0, 0, 0, port, 0, 0, binprm);

	if (record) {
	       	;//printk(KERN_INFO "Found socket bind record func=%u, port=[%d]\n", record->fid, record->port);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_socket_record(HB_SOCKET_BIND, uid, 'A', 0, 0, 0, \
					port, 0, 0, binprm, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_socket_record(HB_SOCKET_BIND, uid, 'R', 0, 0, 0, \
					port, 0, 0, binprm, interact);

		if ((locking == 1) && (bl == 0)) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}
out1:
	kfree(taskname);
out:
	return err;
}

/**
 * This function use to tracking socket activity.
 * Trigger during connect
 * Tracking info: user id / interface / address / address length
 */
static int honeybest_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
       	struct task_struct *task = current;
	struct cred *cred = (struct cred *)task->cred;
	struct mm_struct *mm = current->mm;
	char *taskname = NULL;
	char *binprm = NULL;
	char uid[UID_STR_SIZE];
	hb_socket_ll *record;
	int port = 0;
	int err = 0;

	if (!enabled)
	       	return err;

	if (inject_honeybest_tracker(cred, HB_SOCKET_CONNECT))
		err = -ENOMEM;

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
			}
			else
				goto out;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out1;

	port = lookup_source_port(sock, address, addrlen);

	record = search_socket_record(HB_SOCKET_CONNECT, current->cred->uid.val, 0, 0, 0, port, 0, 0, binprm);

	if (record) {
	       	;//printk(KERN_INFO "Found socket bind record func=%u, port=[%d]\n", record->fid, record->port);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_socket_record(HB_SOCKET_CONNECT, uid, 'A', 0, 0, 0, port, 0, 0, binprm, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_socket_record(HB_SOCKET_CONNECT, uid, 'R', 0, 0, 0, port, 0, 0, binprm, interact);

		if ((locking == 1) && (bl == 0)) {
			/* detect mode */
			err = -EOPNOTSUPP;
		}
	}
out1:
	kfree(taskname);
out:
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

/**
 * This function use to tracking socket activity.
 * Trigger during set socket attribute
 * Tracking info: user id / level / options
 */
static int honeybest_socket_setsockopt(struct socket *sock, int level, int optname)
{
       	struct task_struct *task = current;
	struct cred *cred = (struct cred *)task->cred;
	struct mm_struct *mm = current->mm;
	char *taskname = NULL;
	char *binprm = NULL;
	char uid[UID_STR_SIZE];
	hb_socket_ll *record;
	int err = 0;

	if (!enabled)
	       	return err;

	if (inject_honeybest_tracker(cred, HB_SOCKET_SETSOCKOPT))
		err = -ENOMEM;

	task_lock(task);
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			taskname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (taskname) {
				binprm = d_path(&mm->exe_file->f_path, taskname, PATH_MAX);
			}
			else
				goto out;
		}
		up_read(&mm->mmap_sem);
	}
	task_unlock(task);

	if (!binprm)
		goto out1;

	record = search_socket_record(HB_SOCKET_SETSOCKOPT, current->cred->uid.val, 0, 0, 0, 0, level, optname, binprm);

	if (record) {
	       	;//printk(KERN_INFO "Found socket setsockopt record func=%u, level=%d, optname=%d\n", record->fid, level, optname);
		if ((bl == 1) && (record->act_allow == 'R') && (locking == 1))
			err = -EOPNOTSUPP;
	}
	else {
		sprintf(uid, "%u", current->cred->uid.val);

		if ((locking == 0) && (bl == 0)) 
			err = add_socket_record(HB_SOCKET_SETSOCKOPT, uid, 'A', 0, 0, 0, 0, level, optname, binprm, interact);

		if ((locking == 0) && (bl == 1)) 
			err = add_socket_record(HB_SOCKET_SETSOCKOPT, uid, 'R', 0, 0, 0, 0, level, optname, binprm, interact);

		if ((locking == 1) && (bl == 0)) 
			err = -EOPNOTSUPP;
	}
out1:
	kfree(taskname);
out:
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

	if (!enabled)
		return err;

	return err;
}

static void honeybest_sk_free_security(struct sock *sk)
{
	if (!enabled)
		return;
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

	if (!enabled)
	       	return err;
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

	if (!enabled)
	       	return err;
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

	if (!enabled)
	       	return err;
	return err;
}

int honeybest_xfrm_state_alloc_acquire(struct xfrm_state *x,
                                     struct xfrm_sec_ctx *polsec, u32 secid)
{
	int err = 0;

	if (!enabled)
	       	return err;

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

	if (!enabled)
	       	return err;

	return err;
}

static void honeybest_msg_msg_free_security(struct msg_msg *msg)
{

	if (!enabled)
		return;
	return;
}


static int honeybest_msg_queue_alloc_security(struct msg_queue *msq)
{
	int err = 0;

	if (!enabled)
		return err;

	return err;
}

static void honeybest_msg_queue_free_security(struct msg_queue *msq)
{

	if (!enabled)
		return;
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

	if (!enabled)
		return err;

	return err;
}

static void honeybest_shm_free_security(struct shmid_kernel *shp)
{

	if (!enabled)
		return;
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

	if (!enabled)
		return err;

	return err;
}

static void honeybest_sem_free_security(struct sem_array *sma)
{
	if (!enabled)
		return;
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
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
#endif

#ifdef CONFIG_KEYS
static int honeybest_key_alloc(struct key *k, const struct cred *cred,
                             unsigned long flags)
{
	int err = 0;

	if (!enabled)
		return err;

	return err;
}

static void honeybest_key_free(struct key *k)
{
	if (!enabled)
		return;
	return;
}

static int honeybest_key_permission(key_ref_t key_ref,
                                  const struct cred *cred,
                                  unsigned perm)
{
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
static int honeybest_key_getsecurity(struct key *key, char **_buffer)
{
	*_buffer = NULL;
	return 0;
}
#endif

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
	if (!enabled)
		return;
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
        LSM_HOOK_INIT(sb_pivotroot, honeybest_sb_pivotroot),
        LSM_HOOK_INIT(sb_remount, honeybest_sb_remount),
        LSM_HOOK_INIT(sb_kern_mount, honeybest_sb_kern_mount),
        LSM_HOOK_INIT(sb_show_options, honeybest_sb_show_options),
        LSM_HOOK_INIT(sb_statfs, honeybest_sb_statfs),
        LSM_HOOK_INIT(sb_mount, honeybest_mount),
        LSM_HOOK_INIT(sb_umount, honeybest_umount),
        LSM_HOOK_INIT(sb_set_mnt_opts, honeybest_set_mnt_opts),
        LSM_HOOK_INIT(sb_clone_mnt_opts, honeybest_sb_clone_mnt_opts),
        LSM_HOOK_INIT(sb_parse_opts_str, honeybest_parse_opts_str),

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
        LSM_HOOK_INIT(dentry_init_security, honeybest_dentry_init_security),
#endif

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
        LSM_HOOK_INIT(inode_getsecurity, honeybest_inode_getsecurity),
        LSM_HOOK_INIT(inode_setsecurity, honeybest_inode_setsecurity),
        LSM_HOOK_INIT(inode_listsecurity, honeybest_inode_listsecurity),
        LSM_HOOK_INIT(inode_getsecid, honeybest_inode_getsecid),
#endif

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
        LSM_HOOK_INIT(kernel_module_from_file, honeybest_kernel_module_from_file),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
        LSM_HOOK_INIT(kernel_read_file, honeybest_kernel_read_file),
#endif
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
        LSM_HOOK_INIT(release_secctx, honeybest_release_secctx),
        LSM_HOOK_INIT(inode_invalidate_secctx, honeybest_inode_invalidate_secctx),
	LSM_HOOK_INIT(inode_notifysecctx, honeybest_inode_notifysecctx),
        LSM_HOOK_INIT(inode_setsecctx, honeybest_inode_setsecctx),
        LSM_HOOK_INIT(inode_getsecctx, honeybest_inode_getsecctx),
#endif

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
        LSM_HOOK_INIT(key_getsecurity, honeybest_key_getsecurity),
#endif
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
MODULE_LICENSE("GPL");

#endif /* CONFIG_SECURITY_HONEYBEST */

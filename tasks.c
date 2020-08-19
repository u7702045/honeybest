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
#include "tasks.h"
#include "notify.h"
#include "regex.h"
#include "honeybest.h"

struct proc_dir_entry *hb_proc_task_entry;
hb_task_ll hb_task_list_head;
hb_task_ll *search_task_record(unsigned int fid, uid_t uid, struct siginfo *info, int sig, u32 secid, char *binprm)
{
	hb_task_ll *tmp = NULL;
	struct list_head *pos = NULL;

	list_for_each(pos, &hb_task_list_head.list) {
		tmp = list_entry(pos, hb_task_ll, list);
		if ((tmp->fid == HB_TASK_SIGNAL) && (uid == tmp->uid) && (tmp->sig == sig) && !compare_regex(tmp->binprm, strlen(tmp->binprm), binprm, strlen(binprm))) {
			/* we find the record */
			//printk(KERN_INFO "Found task open record !!!!\n");
			return tmp;
		}
	}

	return NULL;
}

int add_task_record(unsigned int fid, uid_t uid, int sig, int si_signo, int si_errno, u32 secid, char *binprm, int interact)
{
	int err = 0;
	hb_task_ll *tmp = NULL;

	tmp = (hb_task_ll *)kmalloc(sizeof(hb_task_ll), GFP_KERNEL);
	if (tmp) {
		memset(tmp, 0, sizeof(hb_task_ll));
		tmp->fid = fid;
		tmp->uid = uid;
	       	tmp->binprm = kmalloc(strlen(binprm)+1, GFP_KERNEL);
		if (tmp->binprm == NULL) {
			err = -EOPNOTSUPP;
			goto out;
		}
		strcpy(tmp->binprm, binprm);
		switch (fid) {
			case HB_TASK_SIGNAL:
				tmp->sig = sig;
				tmp->si_signo = si_signo;
				tmp->si_errno = si_errno;
				tmp->secid = secid;
				break;
			default:
				break;
		}
		if ((err == 0) && (interact == 0))
		       	list_add_tail(&(tmp->list), &(hb_task_list_head.list));

		if ((err == 0) && (interact == 1))
			add_notify_record(fid, tmp);
	}
	else
		err = -EOPNOTSUPP;
out:
	return err;
}

int read_task_record(struct seq_file *m, void *v)
{
	hb_task_ll *tmp = NULL;
	struct list_head *pos = NULL;
	unsigned long total = 0;

	seq_printf(m, "NO\tFUNC\tUID\tSIGNAL\tSIGNO\tERRNO\tSECID\tBINPRM\n");
	list_for_each(pos, &hb_task_list_head.list) {
		tmp = list_entry(pos, hb_task_ll, list);
		seq_printf(m, "%lu\t%u\t%u\t%d\t%d\t%d\t%u\t%s\n", total++, tmp->fid, tmp->uid, tmp->sig, tmp->si_signo, tmp->si_errno, tmp->secid, tmp->binprm);
	}

	return 0;
}

ssize_t write_task_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
	char *acts_buff = NULL;
	char *delim = "\n";
	char *token, *cur;
	hb_task_ll *tmp = NULL;
	struct list_head *pos = NULL;
	struct list_head *q = NULL;

	if(*ppos > 0 || count > TOTAL_ACT_SIZE) {
		printk(KERN_WARNING "Write size is too big!\n");
		count = 0;
		goto out;
	}

	acts_buff = (char *)kmalloc(TOTAL_ACT_SIZE, GFP_KERNEL);
	if (acts_buff == NULL) {
		count = 0;
		goto out1;
	}
	memset(acts_buff, '\0', TOTAL_ACT_SIZE);

	if (count <= 0) {
		goto out1;
	}

	if(copy_from_user(acts_buff, buffer, count))
		goto out1;

	/* clean all acts_buff */
	list_for_each_safe(pos, q, &hb_task_list_head.list) {
		tmp = list_entry(pos, hb_task_ll, list);
		kfree(tmp->binprm);
		list_del(pos);
		kfree(tmp);
		tmp = NULL;
	}

       	cur = acts_buff;
	/* add acts_buff */
	while((token = strsep(&cur, delim)) && (strlen(token)>1)) {
		uid_t uid = 0;
		unsigned int fid = 0;
		int sig = 0;
		int si_signo = 0;
		int si_errno = 0;
		u32 secid = 0;
		char *binprm = NULL;

		binprm = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
		if (binprm == NULL) {
			printk(KERN_ERR "binprm is null !\n");
			continue;
		}

		sscanf(token, "%u %u %d %d %d %u %s", &fid, &uid, &sig, &si_signo, &si_errno, &secid, binprm);
		if (add_task_record(HB_TASK_SIGNAL, uid, sig, si_signo, si_errno, secid, binprm, 0) != 0) {
			printk(KERN_WARNING "Failure to add task record %u, %d, %s\n", uid, sig, binprm);
		}
	}

out1:
	kfree(acts_buff);
out:
	return count;
}

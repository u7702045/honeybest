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
#include "ptrace.h"
#include "regex.h"
#include "notify.h"
#include "honeybest.h"

struct proc_dir_entry *hb_proc_ptrace_entry;
hb_ptrace_ll hb_ptrace_list_head;
hb_ptrace_ll *search_ptrace_record(unsigned int fid, uid_t uid, char *parent, char *child, unsigned int mode)
{
	hb_ptrace_ll *tmp = NULL;
	struct list_head *pos = NULL;

	list_for_each(pos, &hb_ptrace_list_head.list) {
		bool do_compare_uid = false;
		unsigned long list_uid = 0;

		tmp = list_entry(pos, hb_ptrace_ll, list);

		if (tmp->uid[0] == '*')
			do_compare_uid = true;
		else {
			if ((kstrtoul(tmp->uid, 10, &list_uid) == 0) && (list_uid < UINT_MAX))
				do_compare_uid = (uid == list_uid) ;
		}

		if ((tmp->fid == HB_PTRACE_ACCESS_CHECK) && do_compare_uid && !compare_regex(tmp->parent, strlen(tmp->parent), parent, strlen(parent)) && !compare_regex(tmp->child, strlen(tmp->child), child, strlen(child)) && (tmp->mode == mode)) {
			/* we find the record */
			//printk(KERN_INFO "Found ptrace access record !!!!\n");
			return tmp;
		}
	}

	return NULL;
}

int add_ptrace_record(unsigned int fid, char *uid, char act_allow, char *parent, char *child, unsigned int mode, int interact)
{
	int err = 0;
	hb_ptrace_ll *tmp = NULL;
       	int parent_len = strlen(parent);
       	int child_len = strlen(child);

	tmp = (hb_ptrace_ll *)kmalloc(sizeof(hb_ptrace_ll), GFP_KERNEL);
	if (tmp) {
		memset(tmp, 0, sizeof(hb_ptrace_ll));
		tmp->fid = fid;
		strncpy(tmp->uid, uid, UID_STR_SIZE-1);
		tmp->act_allow = act_allow;
		switch (fid) {
			case HB_PTRACE_ACCESS_CHECK:
				tmp->mode = mode;
				tmp->parent = kmalloc(parent_len+1, GFP_KERNEL);
				if (tmp->parent == NULL)
					err = -EOPNOTSUPP;
				else
					strcpy(tmp->parent, parent);

				tmp->child = kmalloc(child_len+1, GFP_KERNEL);
				if (tmp->child == NULL) {
					err = -EOPNOTSUPP;
					kfree(tmp->parent);
				}
				else
					strcpy(tmp->child, child);
			       	break;
			default:
				break;
		}
		if ((err == 0) && (interact == 0))
		       	list_add_tail(&(tmp->list), &(hb_ptrace_list_head.list));

		if ((err == 0) && (interact == 1))
			add_notify_record(fid, tmp);
	}
	else
		err = -EOPNOTSUPP;

	if(err != 0)
		kfree(tmp);

	return err;
}

int read_ptrace_record(struct seq_file *m, void *v)
{
	hb_ptrace_ll *tmp = NULL;
	struct list_head *pos = NULL;
	unsigned long total = 0;

	seq_printf(m, "NO\tFUNC\tUID\tACTION\tPARENT BINPRM\t\t\t\tCHILD BINPRM\t\t\t\tMODE\n");
	list_for_each(pos, &hb_ptrace_list_head.list) {
		tmp = list_entry(pos, hb_ptrace_ll, list);
		seq_printf(m, "%lu\t%u\t%s\t%c\t%s\t\t\t\t%s\t\t\t\t%u\n", total++, tmp->fid, tmp->uid, tmp->act_allow, tmp->parent, tmp->child, tmp->mode);
	}

	return 0;
}

ssize_t write_ptrace_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
	char *acts_buff = NULL;
	char *delim = "\n";
	char *token, *cur;
	hb_ptrace_ll *tmp = NULL;
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
	list_for_each_safe(pos, q, &hb_ptrace_list_head.list) {
		tmp = list_entry(pos, hb_ptrace_ll, list);
		list_del(pos);
		kfree(tmp->parent);
		kfree(tmp->child);
		kfree(tmp);
		tmp = NULL;
	}

       	cur = acts_buff;
	/* add acts_buff */
	while((token = strsep(&cur, delim)) && (strlen(token)>1)) {
		char uid[UID_STR_SIZE];
		unsigned int fid = 0;
		char act_allow = 'R';
		char *parent = NULL;
		char *child = NULL;
		unsigned int mode = 0;

		parent = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
		if (parent == NULL) {
			continue;
		}

		child = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
		if (child == NULL) {
			kfree(parent);
			continue;
		}

		sscanf(token, "%u %s %c %s %s %u", &fid, uid, &act_allow, parent, child, &mode);
		if (add_ptrace_record(HB_BPRM_SET_CREDS, uid, act_allow, parent, child, mode, 0) != 0) {
			printk(KERN_WARNING "Failure to add ptrace record %s, %s, %s\n", uid, parent, child);
		}

		kfree(parent);
		kfree(child);
	} //while
out1:
	kfree(acts_buff);
out:
	return count;
}


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
#include "kmod.h"
#include "notify.h"
#include "regex.h"
#include "honeybest.h"
#include "audit.h"

extern int locking;
extern int hb_level;
extern int enabled_audit;
extern int hb_interact;
extern unsigned long total_notify_record;
extern hb_notify_ll hb_notify_list_head;
struct proc_dir_entry *hb_proc_kmod_entry;
hb_kmod_ll hb_kmod_list_head;

int match_kmod_record(hb_kmod_ll *data, unsigned int fid, uid_t uid, char *name, char *filename, char *digest)
{
	int match = 0;
	bool do_compare_uid = false;
	unsigned long list_uid = 0;

	if (data->uid[0] == '*')
		do_compare_uid = true;
	else {
		if ((kstrtoul(data->uid, 10, &list_uid) == 0) && (list_uid < UINT_MAX))
			do_compare_uid = (uid == list_uid) ;
	}

	switch (fid) {
		case HB_KMOD_REQ:
			if ((data->fid == fid) && do_compare_uid && !compare_regex(data->name, name)) {
				/* we find the record */
				//printk(KERN_INFO "Found kernel module record !!!!\n");
				match = 1;
			}
			break;
		case HB_KMOD_LOAD_FROM_FILE:
			if ((data->fid == fid) && do_compare_uid && !compare_regex(data->filename, filename) && !strncmp(data->digest, digest, SHA1_HONEYBEST_DIGEST_SIZE)) {
				/* we find the record */
				//printk(KERN_INFO "Found kernel load module record !!!!\n");
				match = 1;
			}
			break;
		default:
			break;
	} // switch

	return match;
}

hb_kmod_ll *search_kmod_record(unsigned int fid, uid_t uid, char *name, char *filename, char *digest)
{
	struct list_head *pos = NULL;

	list_for_each(pos, &hb_kmod_list_head.list) {
		hb_kmod_ll *tmp = NULL;

		tmp = list_entry(pos, hb_kmod_ll, list);

		if(match_kmod_record(tmp, fid, uid, name, filename, digest))
			return tmp;
	} // linked list

	return NULL;
}

hb_kmod_ll *search_notify_kmod_record(unsigned int fid, char *uid, char *name, char *filename, char *digest)
{
	hb_notify_ll *tmp = NULL;
	struct list_head *pos = NULL;

	list_for_each(pos, &hb_notify_list_head.list) {

		tmp = list_entry(pos, hb_notify_ll, list);

		if (strstr(tmp->proc, HB_KMOD_PROC)) {
			hb_kmod_ll *data = tmp->data;
			unsigned long list_uid = 0;

			if(kstrtoul(uid, 10, &list_uid) != 0)
				printk(KERN_ERR "UID convert error\n");

			if(match_kmod_record(data, fid, list_uid, name, filename, digest)) {
				return data;
			}
		}
	} // notify linked list

	return NULL;
}

int add_kmod_record(unsigned int fid, char *uid, char act_allow, char *name, char *filename, char *digest)
{
	int err = 0;
	hb_kmod_ll *tmp = NULL;

	tmp = (hb_kmod_ll *)kmalloc(sizeof(hb_kmod_ll), GFP_KERNEL);
	if (!tmp) {
		err = -EOPNOTSUPP;
		return err;
	}

	memset(tmp, 0, sizeof(hb_kmod_ll));
	tmp->fid = fid;
	strncpy(tmp->uid, uid, UID_STR_SIZE-1);
	tmp->act_allow = act_allow;
	tmp->name = kmalloc(strlen(name)+1, GFP_KERNEL);
	if (tmp->name == NULL) {
		err = -EOPNOTSUPP;
		goto out;
	}
	memset(tmp->name, '\0', strlen(name)+1);

	tmp->filename = kmalloc(strlen(filename)+1, GFP_KERNEL);
	if (tmp->filename == NULL) {
		err = -EOPNOTSUPP;
		kfree(tmp->name);
		goto out;
	}
	memset(tmp->filename, '\0', strlen(filename)+1);


	switch (fid) {
		case HB_KMOD_REQ:
		case HB_KMOD_LOAD_FROM_FILE:
			strncpy(tmp->name, name, strlen(name));
			strncpy(tmp->filename, filename, strlen(filename));

			strncpy(tmp->digest, digest, SHA1_HONEYBEST_DIGEST_SIZE);
			break;
		default:
			break;
	}

	if ((err == 0) && (hb_interact == 0))
		list_add_tail(&(tmp->list), &(hb_kmod_list_head.list));

	if ((err == 0) && (hb_interact == 1)) {
		if (!search_notify_kmod_record(fid, uid, name, filename, digest) && (total_notify_record < MAX_NOTIFY_RECORD)) {
			if(add_notify_record(fid, tmp) != 0) {
				err = -EOPNOTSUPP;
				goto out;
			}
		}
		else {
			//printk(KERN_ERR "Notify record found or exceed number %lu\n", total_notify_record);
			err = -EOPNOTSUPP;
			goto out;
		}
	}

out:
	if(err != 0) {
		free_kmod_record(tmp);
		kfree(tmp);
	}
	return err;
}

int read_kmod_record(struct seq_file *m, void *v)
{
	struct list_head *pos = NULL;
	unsigned long total = 0;

	seq_printf(m, "NO\tFUNC\tUID\tACTION\tNAME\tFILE\t\t\tDIGEST\n");

	list_for_each(pos, &hb_kmod_list_head.list) {
		hb_kmod_ll *tmp = NULL;

		tmp = list_entry(pos, hb_kmod_ll, list);
		seq_printf(m, "%lu\t%u\t%s\t%c\t%s\t\t\t%s\t%s\n", total++, tmp->fid, tmp->uid, tmp->act_allow, tmp->name, tmp->filename, tmp->digest);
	}

	return 0;
}

void free_kmod_record(hb_kmod_ll *data)
{
	if (data->name)
	       	kfree(data->name);
	if (data->filename)
	       	kfree(data->filename);
}

ssize_t write_kmod_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
	char *acts_buff = NULL;
	char *delim = "\n";
	char *token, *cur;
	hb_kmod_ll *tmp = NULL;
	struct list_head *pos = NULL;
	struct list_head *q = NULL;

	if (locking == 1)
		goto out;

	if(*ppos > 0 || count > TOTAL_ACT_SIZE) {
		printk(KERN_WARNING "Write size is too big!\n");
		count = 0;
		goto out;
	}

	acts_buff = (char *)kmalloc(TOTAL_ACT_SIZE, GFP_KERNEL);
	if (acts_buff == NULL) {
		count = 0;
		goto out;
	}
	memset(acts_buff, '\0', TOTAL_ACT_SIZE);

	if (count == 0) {
		goto out1;
	}

	if(copy_from_user(acts_buff, buffer, count))
		goto out1;

	/* clean all acts_buff */
	list_for_each_safe(pos, q, &hb_kmod_list_head.list) {
		tmp = list_entry(pos, hb_kmod_ll, list);
		list_del(pos);
		free_kmod_record(tmp);
		kfree(tmp);
		tmp = NULL;
	}

       	cur = acts_buff;
	/* add acts_buff */
	while((token = strsep(&cur, delim)) && (strlen(token)>1)) {
		char uid[UID_STR_SIZE];
		unsigned int fid = 0;
		char act_allow = 'R';
		char *name = NULL;
		char *filename = NULL;
	       	char digest[SHA1_HONEYBEST_DIGEST_SIZE];

		name = (char *)kmalloc(32, GFP_KERNEL);
		if (name == NULL) {
			goto out;
		}

		filename = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
		if (filename == NULL) {
			kfree(name);
			goto out;
		}

		sscanf(token, "%u %5s %c %31s %4095s %40s", &fid, uid, &act_allow, name, filename, digest);
		if (add_kmod_record(fid, uid, act_allow, name, filename, digest) != 0) {
			printk(KERN_WARNING "Failure to add kmod record %s\n", name);
		}
		else {
			if (enabled_audit)
				honeybest_audit_report(token);
		}

		kfree(filename);
		kfree(name);
	}

out1:
	kfree(acts_buff);
out:
	return count;
}



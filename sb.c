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
#include "sb.h"
#include "notify.h"
#include "regex.h"
#include "honeybest.h"

struct proc_dir_entry *hb_proc_sb_entry;
hb_sb_ll hb_sb_list_head;
hb_sb_ll *search_sb_record(unsigned int fid, uid_t uid, char *s_id, char *name, \
		char *dev_name, char *type, int flags)
{
	hb_sb_ll *tmp = NULL;
	struct list_head *pos = NULL;

	list_for_each(pos, &hb_sb_list_head.list) {
		bool do_compare_uid = false;
		unsigned long list_uid = 0;

		tmp = list_entry(pos, hb_sb_ll, list);

		if (tmp->uid[0] == '*')
			do_compare_uid = true;
		else {
			if ((kstrtoul(tmp->uid, 10, &list_uid) == 0) && (list_uid < UINT_MAX))
				do_compare_uid = (uid == list_uid) ;
		}

		switch (fid) {
			case HB_SB_COPY_DATA:
				if ((tmp->fid == fid) && do_compare_uid) {
					/* we find the record */
					//printk(KERN_INFO "Found sb copy data record !!!!\n");
					return tmp;
				}
				break;
			case HB_SB_STATFS:
			case HB_SB_REMOUNT:
				if ((tmp->fid == fid) && do_compare_uid && !compare_regex(tmp->s_id, strlen(tmp->s_id), s_id, strlen(s_id)) && !compare_regex(tmp->name, strlen(tmp->name), name, strlen(name))) {
					/* we find the record */
					//printk(KERN_INFO "Found sb remount/statfs data record !!!!\n");
					return tmp;
				}
				break;
			case HB_SB_UMOUNT:
				if ((tmp->fid == fid) && do_compare_uid && !compare_regex(tmp->s_id, strlen(tmp->s_id), s_id, strlen(s_id)) && !compare_regex(tmp->name, strlen(tmp->name), name, strlen(name)) && (tmp->flags == flags)) {
					/* we find the record */
					//printk(KERN_INFO "Found sb umount data record !!!!\n");
					return tmp;
				}
				break;
			case HB_SB_MOUNT:
				if ((tmp->fid == fid) && do_compare_uid && !compare_regex(tmp->dev_name, strlen(tmp->dev_name), dev_name, strlen(dev_name)) && !strncmp(tmp->type, type, strlen(tmp->type)) && (tmp->flags == flags)) {
					/* we find the record */
					//printk(KERN_INFO "Found sb mount data record !!!!\n");
					return tmp;
				}
				break;
			default:
				break;
		} // switch
	} // path linked list

	return NULL;
}

int add_sb_record(unsigned int fid, char *uid, char act_allow, char *s_id, char *name, \
		char *dev_name, char *type, int flags, int interact)
{
	int err = 0;
	hb_sb_ll *tmp = NULL;

	if (!s_id || !name || !dev_name || !type)
		return err;

	tmp = (hb_sb_ll *)kmalloc(sizeof(hb_sb_ll), GFP_KERNEL);
	if (tmp) {
		memset(tmp, 0, sizeof(hb_sb_ll));
		tmp->fid = fid;
		strncpy(tmp->uid, uid, UID_STR_SIZE-1);
		tmp->act_allow = act_allow;

		tmp->s_id = kmalloc(strlen(s_id)+1, GFP_KERNEL);
		if (tmp->s_id == NULL) {
			err = -EOPNOTSUPP;
			goto out;
		}
		memset(tmp->s_id, '\0', strlen(s_id)+1);

		tmp->name = kmalloc(strlen(name)+1, GFP_KERNEL);
		if (tmp->name == NULL) {
			err = -EOPNOTSUPP;
			goto out1;
		}
		memset(tmp->name, '\0', strlen(name)+1);

		tmp->dev_name = kmalloc(strlen(dev_name)+1, GFP_KERNEL);
		if (tmp->dev_name == NULL) {
			err = -EOPNOTSUPP;
			goto out2;
		}
		memset(tmp->dev_name, '\0', strlen(dev_name)+1);

		tmp->type = kmalloc(strlen(type)+1, GFP_KERNEL);
		if (tmp->type == NULL) {
			err = -EOPNOTSUPP;
			goto out3;
		}
		memset(tmp->type, '\0', strlen(type)+1);

		if(s_id != NULL)
		       	strncpy(tmp->s_id, s_id, strlen(s_id));
		if(name != NULL)
			strncpy(tmp->name, name, strlen(name));
		if(dev_name != NULL)
			strncpy(tmp->dev_name, dev_name, strlen(dev_name));
		if(type != NULL)
			strncpy(tmp->type, type, strlen(type));

		tmp->flags = flags;

		printk(KERN_DEBUG "%s, %s, %s, %s, %s, %d\n", __FUNCTION__, tmp->s_id, tmp->name, tmp->dev_name, tmp->type, tmp->flags);
		if ((err == 0) && (interact == 0))
		       	list_add_tail(&(tmp->list), &(hb_sb_list_head.list));

		if ((err == 0) && (interact == 1))
			add_notify_record(fid, tmp);
	}
	else
		err = -EOPNOTSUPP;

	if(err != 0)
		kfree(tmp->type);
out3:
	if(err != 0)
		kfree(tmp->dev_name);
out2:
	if(err != 0)
		kfree(tmp->name);
out1:
	if(err != 0)
		kfree(tmp->s_id);
out:
	if(err != 0)
		kfree(tmp);
	return err;
}

int read_sb_record(struct seq_file *m, void *v)
{
	hb_sb_ll *tmp = NULL;
	struct list_head *pos = NULL;
	unsigned long total = 0;

	seq_printf(m, "NO\tFUNC\tUID\tACTION\tSID\tNAME\tDEV_NAME\tTYPE\tFLAGS\n");

	list_for_each(pos, &hb_sb_list_head.list) {
		tmp = list_entry(pos, hb_sb_ll, list);
		seq_printf(m, "%lu\t%u\t%s\t%c\t%s\t%s\t%s\t\t%s\t%d\n", total++, tmp->fid, tmp->uid, tmp->act_allow,
				tmp->s_id, tmp->name, tmp->dev_name, tmp->type, tmp->flags);
	}

	return 0;
}

ssize_t write_sb_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
	char *acts_buff = NULL;
	char *delim = "\n";
	char *token, *cur;
	hb_sb_ll *tmp = NULL;
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
		goto out;
	}
	memset(acts_buff, '\0', TOTAL_ACT_SIZE);

	if (count <= 0) {
		goto out1;
	}

	if(copy_from_user(acts_buff, buffer, count))
		goto out1;

	/* clean all acts_buff */
	list_for_each_safe(pos, q, &hb_sb_list_head.list) {
		tmp = list_entry(pos, hb_sb_ll, list);
		list_del(pos);
		kfree(tmp->s_id);
		kfree(tmp->name);
		kfree(tmp->dev_name);
		kfree(tmp->type);
		kfree(tmp);
		tmp = NULL;
	}

       	cur = acts_buff;
	/* add acts_buff */
	while((token = strsep(&cur, delim)) && (strlen(token)>1)) {
		char uid[UID_STR_SIZE];
		unsigned int fid = 0;
		char *s_id = NULL;
		char *name = NULL;
		char *dev_name = NULL;
		char *type = NULL;
		char act_allow = 'R';
		int flags = 0;

		/* 32 array reference to fs.h */
		s_id = (char *)kmalloc(32, GFP_KERNEL);
		if (s_id == NULL) {
			continue;
		}

		name = (char *)kmalloc(32, GFP_KERNEL);
		if (name == NULL) {
			goto out2;
		}

		dev_name = (char *)kmalloc(32, GFP_KERNEL);
		if (dev_name == NULL) {
			goto out3;
		}

		type = (char *)kmalloc(32, GFP_KERNEL);
		if (type == NULL) {
			goto out4;
		}

		sscanf(token, "%u %s %c %s %s %s %s %d", &fid, uid, &act_allow, s_id, name, dev_name, type, &flags);
		if (add_sb_record(fid, uid, act_allow, s_id, name, dev_name, type, flags, 0) != 0) {
			printk(KERN_WARNING "Failure to add sb record %s, %s %s %s\n", s_id, name, dev_name, type);
		}

		kfree(type);
out4:
		kfree(dev_name);
out3:
		kfree(name);
out2:
		kfree(s_id);
	}

out1:
	kfree(acts_buff);
out:
	return count;
}


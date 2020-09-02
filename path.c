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
#include <linux/string_helpers.h>
#include <linux/list.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <crypto/algapi.h>
#include <linux/path.h>
#include "path.h"
#include "regex.h"
#include "notify.h"
#include "honeybest.h"

extern hb_notify_ll hb_notify_list_head;
struct proc_dir_entry *hb_proc_path_entry;
hb_path_ll hb_path_list_head;

int match_path_record(hb_path_ll *data, unsigned int fid, uid_t uid, umode_t mode, char *s_path, char *t_path, uid_t suid, uid_t sgid, unsigned int dev, char *binprm)
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
		case HB_PATH_RENAME:
		case HB_PATH_TRUNCATE:
		case HB_PATH_RMDIR:
		case HB_PATH_SYMLINK:
		case HB_PATH_LINK:
		case HB_PATH_UNLINK:
			if ((data->fid == fid) && do_compare_uid && !compare_regex(data->s_path, strlen(data->s_path), s_path, strlen(s_path)) && !compare_regex(data->t_path, strlen(data->t_path), t_path, strlen(t_path)) && !compare_regex(data->binprm, strlen(data->binprm), binprm, strlen(binprm))) {
				/* we find the record */
				//printk(KERN_INFO "Found link/rename/rmdir/symlink/unlink path record !!!!\n");
				match = 1;
			}
			break;
		case HB_PATH_MKDIR:
		case HB_PATH_CHMOD:
			if ((data->fid == fid) && do_compare_uid && !compare_regex(data->s_path, strlen(data->s_path), s_path, strlen(s_path)) && (data->mode == mode) && !compare_regex(data->binprm, strlen(data->binprm), binprm, strlen(binprm))) {
				/* we find the record */
				//printk(KERN_INFO "Found chmod path record !!!!\n");
				match = 1;
			}
			break;
		case HB_PATH_CHOWN:
			if ((data->fid == fid) && do_compare_uid && !compare_regex(data->s_path, strlen(data->s_path), s_path, strlen(s_path)) && (data->suid == suid) && (data->sgid == sgid) && !compare_regex(data->binprm, strlen(data->binprm), binprm, strlen(binprm))) {
				/* we find the record */
				//printk(KERN_INFO "Found chown path record !!!!\n");
				match = 1;
			}
			break;
		case HB_PATH_MKNOD:
			if ((data->fid == fid) && do_compare_uid && !compare_regex(data->s_path, strlen(data->s_path), s_path, strlen(s_path)) && (data->dev == dev) && !compare_regex(data->binprm, strlen(data->binprm), binprm, strlen(binprm))) {
				/* we find the record */
				//printk(KERN_INFO "Found mknod path record !!!!\n");
				match = 1;
			}
			break;
		default:
			break;
	} // switch


	return match;
}

hb_path_ll *search_path_record(unsigned int fid, uid_t uid, umode_t mode, char *s_path, char *t_path, uid_t suid, uid_t sgid, unsigned int dev, char *binprm)
{
	hb_path_ll *tmp = NULL;
	struct list_head *pos = NULL;

	list_for_each(pos, &hb_path_list_head.list) {

		tmp = list_entry(pos, hb_path_ll, list);

		if(match_path_record(tmp, fid, uid, mode, s_path, t_path, suid, sgid, dev, binprm))
			return tmp;
	} // path linked list

	return NULL;
}

hb_path_ll *search_notify_path_record(unsigned int fid, char *uid, umode_t mode, char *s_path, char *t_path, uid_t suid, uid_t sgid, unsigned int dev, char *binprm)
{
	hb_notify_ll *tmp = NULL;
	struct list_head *pos = NULL;

	list_for_each(pos, &hb_notify_list_head.list) {

		tmp = list_entry(pos, hb_notify_ll, list);

		if (strstr(tmp->proc, HB_PATH_PROC)) {
			hb_path_ll *data = tmp->data;
			unsigned long list_uid = 0;

			if(kstrtoul(uid, 10, &list_uid) != 0)
				printk(KERN_ERR "UID convert error\n");

			if(match_path_record(data, fid, list_uid, mode, s_path, t_path, suid, sgid, dev, binprm)) {
				return data;
			}
		}
	} // notify linked list

	return NULL;
}

int add_path_record(unsigned int fid, char *uid, char act_allow, umode_t mode, char *s_path, char *t_path, \
		uid_t suid, uid_t sgid, unsigned int dev, char *binprm, int interact)
{
	int err = 0;
	hb_path_ll *tmp = NULL;

	tmp = (hb_path_ll *)kmalloc(sizeof(hb_path_ll), GFP_KERNEL);
	if (tmp) {
		memset(tmp, 0, sizeof(hb_path_ll));
		tmp->fid = fid;
		strncpy(tmp->uid, uid, UID_STR_SIZE-1);
		tmp->suid = 0;
		tmp->sgid = 0;
		tmp->dev = 0;
		tmp->mode = 0;
		tmp->act_allow = act_allow;
		tmp->s_path = kmalloc(strlen(s_path)+1, GFP_KERNEL);
		if (tmp->s_path == NULL) {
			err = -EOPNOTSUPP;
			goto out;
		}
		strcpy(tmp->s_path, s_path);

	       	tmp->t_path = kmalloc(strlen(t_path)+1, GFP_KERNEL);
		if (tmp->t_path == NULL) {
			kfree(tmp->s_path);
			err = -EOPNOTSUPP;
			goto out;
		}
		strcpy(tmp->t_path, t_path);

	       	tmp->binprm = kmalloc(strlen(binprm)+1, GFP_KERNEL);
		if (tmp->binprm == NULL) {
			kfree(tmp->s_path);
			kfree(tmp->t_path);
			err = -EOPNOTSUPP;
			goto out;
		}
		strcpy(tmp->binprm, binprm);

		switch (fid) {
			case HB_PATH_RENAME:
			case HB_PATH_SYMLINK:
			case HB_PATH_RMDIR:
			case HB_PATH_TRUNCATE:
			case HB_PATH_LINK:
			case HB_PATH_UNLINK:
				break;
			case HB_PATH_CHOWN:
				tmp->suid = suid;
				tmp->sgid = sgid;
				break;
			case HB_PATH_MKNOD:
				tmp->dev = dev;
				if (mode >= 0) //mknod from userspace look weird, bug?
				       	tmp->mode = mode;
				break;
			case HB_PATH_MKDIR:
			case HB_PATH_CHMOD:
				tmp->mode = mode;
				break;
			default:
				break;
		}

		if ((err == 0) && (interact == 0))
		       	list_add_tail(&(tmp->list), &(hb_path_list_head.list));

		if ((err == 0) && (interact == 1)) {
			if (!search_notify_path_record(fid, uid, mode, s_path, t_path, suid, sgid, dev, binprm))
			       	add_notify_record(fid, tmp);
			else {
				free_path_record(tmp);
				kfree(tmp);
			}
		}
	}
	else
		err = -EOPNOTSUPP;

out:
	if(err != 0)
		kfree(tmp);
	return err;
}

int read_path_record(struct seq_file *m, void *v)
{
	hb_path_ll *tmp = NULL;
	struct list_head *pos = NULL;
	unsigned long total = 0;

	seq_printf(m, "NO\tFUNC\tUID\tACTION\tMODE\tSUID\tGUID\tDEV NODE\tSOURCE PATH\t\t\tTARGET PATH\t\t\tBINPRM\n");

	if (list_empty(&hb_path_list_head.list)) {
		printk(KERN_WARNING "List is empty!!\n");
		return 0;
	}

	list_for_each(pos, &hb_path_list_head.list) {
		tmp = list_entry(pos, hb_path_ll, list);
		seq_printf(m, "%lu\t%u\t%s\t%c\t%u\t%u\t%u\t%u\t%s\t\t%s\t\t%s\n", total++, tmp->fid, tmp->uid, tmp->act_allow, tmp->mode, tmp->suid, tmp->sgid, tmp->dev, tmp->s_path, tmp->t_path, tmp->binprm);

	}

	return 0;
}

void free_path_record(hb_path_ll *data)
{
	kfree(data->s_path);
	kfree(data->t_path);
	kfree(data->binprm);
}

ssize_t write_path_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
	char *acts_buff = NULL;
	char *delim = "\n";
	char *token, *cur;
	hb_path_ll *tmp = NULL;
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
	list_for_each_safe(pos, q, &hb_path_list_head.list) {
		tmp = list_entry(pos, hb_path_ll, list);
		free_path_record(tmp);
		list_del(pos);
		kfree(tmp);
		tmp = NULL;
	}

       	cur = acts_buff;
	/* add acts_buff */
	while((token = strsep(&cur, delim)) && (strlen(token)>1)) {
		char uid[UID_STR_SIZE];
		uid_t suid = 0;
		uid_t sgid = 0;
		unsigned int dev = 0;
		unsigned int fid = 0;
		umode_t mode = 0;
		char act_allow = 'R';
		char *s_path = NULL;
		char *t_path = NULL;
		char *binprm = NULL;

		s_path = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
		if (s_path == NULL) {
			printk(KERN_ERR "s_path is null !\n");
			continue;
		}

		t_path = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
		if (t_path == NULL) {
			printk(KERN_ERR "t_path is null !\n");
			kfree(s_path);
			continue;
		}

		binprm = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
		if (binprm == NULL) {
			printk(KERN_ERR "binprm is null !\n");
			kfree(t_path);
			kfree(s_path);
			continue;
		}

		sscanf(token, "%u %s %c %hd %u %u %u %s %s %s", &fid, uid, &act_allow, &mode, &suid, &sgid, &dev, s_path, t_path, binprm);
		if (add_path_record(fid, uid, act_allow, mode, s_path, t_path, suid, sgid, dev, binprm, 0) != 0) {
			printk(KERN_WARNING "Failure to add path record %s, %s, %s, %s\n", uid, s_path, t_path, binprm);
		}

		kfree(s_path);
		kfree(t_path);
		kfree(binprm);
	} //while
out1:
	kfree(acts_buff);
out:
	return count;
}

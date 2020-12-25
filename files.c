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
#include "files.h"
#include "regex.h"
#include "notify.h"
#include "honeybest.h"
#include "audit.h"

extern int locking;
extern int hb_level;
extern int enabled_audit;
extern int hb_interact;
extern unsigned long total_notify_record;
extern hb_notify_ll hb_notify_list_head;
struct proc_dir_entry *hb_proc_file_entry;
hb_file_ll hb_file_list_head;

int match_file_record(hb_file_ll *data, unsigned int fid, uid_t uid, char *filename, char *binprm, unsigned int cmd, unsigned long arg)
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
		case HB_FILE_IOCTL:
			if (hb_level == 1)
				if ((data->fid == fid) && do_compare_uid && !compare_regex(data->filename, filename) && (data->cmd == cmd))
					match = 1;
			if (hb_level == 2)
				if ((data->fid == fid) && do_compare_uid && !compare_regex(data->filename, filename) && !compare_regex(data->binprm, binprm) && (data->cmd == cmd) && (data->arg == arg))
					match = 1;
			break;
		case HB_FILE_OPEN:
		case HB_FILE_RECEIVE:
			if (hb_level == 1)
				if ((data->fid == fid) && do_compare_uid && !compare_regex(data->filename, filename)) 
					match = 1;
			if (hb_level == 2)
				if ((data->fid == fid) && do_compare_uid && !compare_regex(data->filename, filename) && !compare_regex(data->binprm, binprm))
					match = 1;
			break;
		default:
			break;
	} // switch

	return match;
}

hb_file_ll *search_file_record(unsigned int fid, uid_t uid, char *filename, char *binprm, unsigned int cmd, unsigned long arg)
{
	struct list_head *pos = NULL;

	list_for_each(pos, &hb_file_list_head.list) {
		hb_file_ll *tmp = NULL;

		tmp = list_entry(pos, hb_file_ll, list);

		if(match_file_record(tmp, fid, uid, filename, binprm, cmd, arg))
			return tmp;
	} // file linked list

	return NULL;
}

hb_file_ll *search_notify_file_record(unsigned int fid, char *uid, char *filename, char *binprm, unsigned int cmd, unsigned long arg)
{
	hb_notify_ll *tmp = NULL;
	struct list_head *pos = NULL;

	list_for_each(pos, &hb_notify_list_head.list) {

		tmp = list_entry(pos, hb_notify_ll, list);

		if (strstr(tmp->proc, HB_FILE_PROC)) {
			hb_file_ll *data = tmp->data;
			unsigned long list_uid = 0;

			if(kstrtoul(uid, 10, &list_uid) != 0)
				printk(KERN_ERR "UID convert error\n");

			if(match_file_record(data, fid, list_uid, filename, binprm, cmd, arg)) {
				return data;
			}
		}
	} // notify linked list

	return NULL;
}

int add_file_record(unsigned int fid, char *uid, char act_allow, char *filename, char *binprm, unsigned int cmd, unsigned long arg)
{
	int err = 0;
	hb_file_ll *tmp = NULL;
       	int file_len = strlen(filename);
       	int binprm_len = strlen(binprm);

	if ((file_len <= 0) || (binprm_len <= 0))
		return -EOPNOTSUPP;

	tmp = (hb_file_ll *)kmalloc(sizeof(hb_file_ll), GFP_KERNEL);
	if (!tmp) {
		err = -EOPNOTSUPP;
		return err;
	}

	memset(tmp, 0, sizeof(hb_file_ll));
	tmp->fid = fid;
	strncpy(tmp->uid, uid, UID_STR_SIZE-1);
	tmp->act_allow = act_allow;
	tmp->filename = kmalloc(file_len+1, GFP_KERNEL);
	if (tmp->filename == NULL) {
		err = -EOPNOTSUPP;
		goto out;
	}
	memset(tmp->filename, '\0', file_len);

	tmp->binprm = kmalloc(binprm_len+1, GFP_KERNEL);
	if (tmp->binprm == NULL) {
		err = -EOPNOTSUPP;
		goto out;
	}
	memset(tmp->binprm, '\0', binprm_len);

	switch (fid) {
		case HB_FILE_IOCTL:
			tmp->cmd = cmd;
			tmp->arg = arg;
		case HB_FILE_RECEIVE:
		case HB_FILE_OPEN:
			strcpy(tmp->filename, filename);
			strcpy(tmp->binprm, binprm);
			break;
		default:
			break;
	}

	if ((err == 0) && (hb_interact == 0))
		list_add_tail(&(tmp->list), &(hb_file_list_head.list));

	if ((err == 0) && (hb_interact == 1)) {
		if (!search_notify_file_record(fid, uid, filename, binprm, cmd, arg) && (total_notify_record < MAX_NOTIFY_RECORD)) {
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
		free_file_record(tmp);
		kfree(tmp);
	}
	return err;
}

int read_file_record(struct seq_file *m, void *v)
{
	struct list_head *pos = NULL;
	unsigned long total = 0;

	seq_printf(m, "NO\tFUNC\tUID\tACTION\t\tPATH\t\t\t\tBINPRM\t\t\t\tCMD\tARG\n");
	list_for_each(pos, &hb_file_list_head.list) {
		hb_file_ll *tmp = NULL;

		tmp = list_entry(pos, hb_file_ll, list);
		seq_printf(m, "%lu\t%u\t%s\t%c\t%s\t%s\t%u\n", total++, tmp->fid, tmp->uid, tmp->act_allow, tmp->filename, tmp->binprm, tmp->cmd);
	}

	return 0;
}

void free_file_record(hb_file_ll *data)
{
	if (data->filename)
	       	kfree(data->filename);
	if (data->binprm)
	       	kfree(data->binprm);
}

ssize_t write_file_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
	char *acts_buff = NULL;
	char *delim = "\n";
	char *token, *cur;
	hb_file_ll *tmp = NULL;
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
		goto out1;
	}
	memset(acts_buff, '\0', TOTAL_ACT_SIZE);

	if (count == 0) {
		goto out1;
	}

	if(copy_from_user(acts_buff, buffer, count))
		goto out1;

	/* clean all acts_buff */
	list_for_each_safe(pos, q, &hb_file_list_head.list) {
		tmp = list_entry(pos, hb_file_ll, list);
		list_del(pos);
		free_file_record(tmp);
		kfree(tmp);
		tmp = NULL;
	}

       	cur = acts_buff;
	/* add acts_buff */
	while((token = strsep(&cur, delim)) && (strlen(token)>1)) {
		char uid[UID_STR_SIZE];
		unsigned int fid = 0;
		char *filename = NULL;
		char act_allow = 'R';
		char *binprm = NULL;
		unsigned int cmd = 0;
		unsigned long arg = 0;

		filename = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
		if (filename == NULL) {
			continue;
		}

		binprm = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
		if (binprm == NULL) {
			kfree(filename);
			continue;
		}

		sscanf(token, "%u %5s %c %4095s %4095s %u %lu", &fid, uid, &act_allow, filename, binprm, &cmd, &arg);
		if (add_file_record(fid, uid, act_allow, filename, binprm, cmd, arg) != 0) {
			printk(KERN_WARNING "Failure to add file record %s, %s, %s\n", uid, filename, binprm);
		}
		else {
			if (enabled_audit)
				honeybest_audit_report(token);
		}

		kfree(filename);
		kfree(binprm);
	} //while
out1:
	kfree(acts_buff);
out:
	return count;
}

// true if match
int allow_file_whitelist(char *path)
{
	if(!path)
		goto out;

	if (!strncmp(path, "/proc/sys/kernel/honeybest/", 27) || (!strncmp(path, "/proc/honeybest/", 16)) || (!strcmp(path, "/"))) {
		//printk(KERN_ERR "Whitelist pass!!\n");
		return 1;
	}

out:
	return 0;
}

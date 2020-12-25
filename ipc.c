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
#include "ipc.h"
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
struct proc_dir_entry *hb_proc_ipc_entry;
hb_ipc_ll hb_ipc_list_head;

int match_ipc_record(hb_ipc_ll *data, unsigned int fid, uid_t uid, char *binprm, \
		uid_t ipc_uid, uid_t ipc_gid, uid_t ipc_cuid, uid_t ipc_cgid, short flag)
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
		case HB_IPC_PERM:
			if ((data->fid == fid) && do_compare_uid && !compare_regex(data->binprm, binprm) && (data->ipc_uid == ipc_uid) && (data->ipc_gid == ipc_gid) && (data->ipc_cuid == ipc_cuid) && (data->ipc_cgid == ipc_cgid) && (data->flag == flag)) {
				/* we find the record */
				//printk(KERN_INFO "Found ipc perm record %s, %s!!!!\n", filename, data->filename);
				match = 1;
			}
			break;
		default:
			break;
	} // switch

	return match;
}

hb_ipc_ll *search_ipc_record(unsigned int fid, uid_t uid, char *binprm, \
		uid_t ipc_uid, uid_t ipc_gid, uid_t ipc_cuid, uid_t ipc_cgid, short flag, umode_t mode)
{
	struct list_head *pos = NULL;

	list_for_each(pos, &hb_ipc_list_head.list) {
		hb_ipc_ll *tmp = NULL;

		tmp = list_entry(pos, hb_ipc_ll, list);

		if(match_ipc_record(tmp, fid, uid, binprm, ipc_uid, ipc_gid, ipc_cuid, ipc_cgid, flag))
			return tmp;
	} // ipc linked list

	return NULL;
}

hb_ipc_ll *search_notify_ipc_record(unsigned int fid, char *uid, char *binprm, uid_t ipc_uid, uid_t ipc_gid, uid_t ipc_cuid, uid_t ipc_cgid, short flag)
{
	hb_notify_ll *tmp = NULL;
	struct list_head *pos = NULL;

	list_for_each(pos, &hb_notify_list_head.list) {

		tmp = list_entry(pos, hb_notify_ll, list);

		if (strstr(tmp->proc, HB_IPC_PROC)) {
			hb_ipc_ll *data = tmp->data;
			unsigned long list_uid = 0;

			if(kstrtoul(uid, 10, &list_uid) != 0)
				printk(KERN_ERR "UID convert error\n");

			if(match_ipc_record(data, fid, list_uid, binprm, ipc_uid, ipc_gid, ipc_cuid, ipc_cgid, flag)) {
				return data;
			}
		}
	} // notify linked list

	return NULL;
}

int add_ipc_record(unsigned int fid, char *uid, char act_allow, char *binprm, \
		uid_t ipc_uid, uid_t ipc_gid, uid_t ipc_cuid, uid_t ipc_cgid, short flag, umode_t mode)
{
	int err = 0;
	hb_ipc_ll *tmp = NULL;
       	int binprm_len = strlen(binprm);

	if (binprm_len <= 0)
		return -EOPNOTSUPP;

	tmp = (hb_ipc_ll *)kmalloc(sizeof(hb_ipc_ll), GFP_KERNEL);
	if (!tmp) {
		err = -EOPNOTSUPP;
		return err;
	}

	memset(tmp, 0, sizeof(hb_ipc_ll));
	tmp->fid = fid;
	strncpy(tmp->uid, uid, UID_STR_SIZE-1);
	tmp->act_allow = act_allow;
	tmp->binprm = kmalloc(binprm_len+1, GFP_KERNEL);
	if (tmp->binprm == NULL) {
		err = -EOPNOTSUPP;
		goto out;
	}

	switch (fid) {
		case HB_IPC_PERM:
			tmp->ipc_uid = ipc_uid;
			tmp->ipc_gid = ipc_gid;
			tmp->ipc_cuid = ipc_cuid;
			tmp->ipc_cgid = ipc_cgid;
			tmp->flag = flag;
			strcpy(tmp->binprm, binprm);
			break;
		default:
			break;
	}

	if ((err == 0) && (hb_interact == 0))
		list_add_tail(&(tmp->list), &(hb_ipc_list_head.list));

	if ((err == 0) && (hb_interact == 1)) {
		if (!search_notify_ipc_record(fid, uid, binprm, ipc_uid, ipc_gid, ipc_cuid, ipc_cgid, flag) && (total_notify_record < MAX_NOTIFY_RECORD)) {
			if(add_notify_record(fid, tmp) != 0) {
				err = -EOPNOTSUPP;
				goto out;
			}
		}
		else {
			//printk(KERN_ERR "notify record found or exceed number %lu\n", total_notify_record);
			err = -EOPNOTSUPP;
			goto out;
		}
	}

out:
	if(err != 0) {
		free_ipc_record(tmp);
		kfree(tmp);
	}
	return err;
}

int read_ipc_record(struct seq_file *m, void *v)
{
	struct list_head *pos = NULL;
	unsigned long total = 0;

	seq_printf(m, "NO\tFUNC\tUID\tACTION\tBINPRM\t\t\t\tI_UID\tI_GID\tI_CUID\tI_GID\tFLAGS\n");
	list_for_each(pos, &hb_ipc_list_head.list) {
		hb_ipc_ll *tmp = NULL;

		tmp = list_entry(pos, hb_ipc_ll, list);
		seq_printf(m, "%lu\t%u\t%s\t%c\t%s\t%d\t%d\t%d\t%d\t%u\n", total++, tmp->fid, tmp->uid, tmp->act_allow, tmp->binprm, tmp->ipc_uid, tmp->ipc_gid, tmp->ipc_cuid, tmp->ipc_cgid, tmp->flag);
	}

	return 0;
}

void free_ipc_record(hb_ipc_ll *data)
{
	if (data->binprm)
	       	kfree(data->binprm);
}

ssize_t write_ipc_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
	char *acts_buff = NULL;
	char *delim = "\n";
	char *token, *cur;
	hb_ipc_ll *tmp = NULL;
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
	list_for_each_safe(pos, q, &hb_ipc_list_head.list) {
		tmp = list_entry(pos, hb_ipc_ll, list);
		list_del(pos);
		free_ipc_record(tmp);
		kfree(tmp);
		tmp = NULL;
	}

       	cur = acts_buff;
	/* add acts_buff */
	while((token = strsep(&cur, delim)) && (strlen(token)>1)) {
		char uid[UID_STR_SIZE];
		unsigned int fid = 0;
		char act_allow = 'R';
		char *binprm = NULL;
		uid_t ipc_uid = 0;
		uid_t ipc_gid = 0;
		uid_t ipc_cuid = 0;
		uid_t ipc_cgid = 0;
		umode_t mode = 0;
		unsigned short flag = 0;

		binprm = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
		if (binprm == NULL) {
			continue;
		}

		sscanf(token, "%u %5s %c %4095s %d %d %d %d %hu %hu", &fid, uid, &act_allow, binprm, \
				&ipc_uid, &ipc_gid, &ipc_cuid, &ipc_cgid, &flag, &mode);
		if (add_ipc_record(fid, uid, act_allow, binprm, ipc_uid, ipc_gid, ipc_cuid, ipc_cgid, flag, mode) != 0) {
			printk(KERN_WARNING "Failure to add ipc perm record %s, %s\n", uid, binprm);
		}
		else {
			if (enabled_audit)
				honeybest_audit_report(token);
		}

		kfree(binprm);
	} //while
out1:
	kfree(acts_buff);
out:
	return count;
}


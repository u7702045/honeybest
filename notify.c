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
#include "notify.h"
#include "creds.h"
#include "files.h"
#include "tasks.h"
#include "socket.h"
#include "path.h"
#include "inode.h"
#include "sb.h"
#include "kmod.h"
#include "honeybest.h"

struct proc_dir_entry *hb_proc_notify_entry;
hb_notify_ll hb_notify_list_head;
int add_notify_record(unsigned int fid, void *data)
{
	int err = 0;
	hb_notify_ll *tmp = NULL;
	tmp = (hb_notify_ll *)kmalloc(sizeof(hb_notify_ll), GFP_KERNEL);
	if (tmp) {
		memset(tmp, 0, sizeof(hb_notify_ll));
		tmp->fid = fid;
		tmp->data = NULL;
		switch (fid) {
			case HB_BPRM_SET_CREDS:
				tmp->data = (void *)kmalloc(sizeof(hb_binprm_ll), GFP_KERNEL);
				strncpy(tmp->proc, HB_CREDS_PROC, strlen(HB_CREDS_PROC));
				if (tmp->data == NULL) {
					printk(KERN_ERR "unable to add binprm notify linked list\n");
					err = -EOPNOTSUPP;
				}
				else
					tmp->data = data;
				break;
			case HB_FILE_OPEN:
				tmp->data = (void *)kmalloc(sizeof(hb_file_ll), GFP_KERNEL);
				strncpy(tmp->proc, HB_FILE_PROC, strlen(HB_FILE_PROC));
				if (tmp->data == NULL) {
					printk(KERN_ERR "unable to add file notify linked list\n");
					err = -EOPNOTSUPP;
				}
				else
					tmp->data = data;
				break;
			case HB_TASK_SIGNAL:
				tmp->data = (void *)kmalloc(sizeof(hb_task_ll), GFP_KERNEL);
				strncpy(tmp->proc, HB_TASK_PROC, strlen(HB_TASK_PROC));
				if (tmp->data == NULL) {
					printk(KERN_ERR "unable to add task notify linked list\n");
					err = -EOPNOTSUPP;
				}
				else
					tmp->data = data;
				break;
			case HB_SOCKET_CREATE:
			case HB_SOCKET_CONNECT:
			case HB_SOCKET_BIND:
			case HB_SOCKET_SETSOCKOPT:
				tmp->data = (void *)kmalloc(sizeof(hb_socket_ll), GFP_KERNEL);
				strncpy(tmp->proc, HB_SOCKET_PROC, strlen(HB_SOCKET_PROC));
				if (tmp->data == NULL) {
					printk(KERN_ERR "unable to add socket notify linked list\n");
					err = -EOPNOTSUPP;
				}
				else
					tmp->data = data;
				break;
			case HB_PATH_RENAME:
			case HB_PATH_SYMLINK:
			case HB_PATH_RMDIR:
			case HB_PATH_TRUNCATE:
			case HB_PATH_LINK:
			case HB_PATH_UNLINK:
			case HB_PATH_CHOWN:
			case HB_PATH_MKNOD:
			case HB_PATH_MKDIR:
			case HB_PATH_CHMOD:
				tmp->data = (void *)kmalloc(sizeof(hb_path_ll), GFP_KERNEL);
				strncpy(tmp->proc, HB_PATH_PROC, strlen(HB_PATH_PROC));
				if (tmp->data == NULL) {
					printk(KERN_ERR "unable to add path notify linked list\n");
					err = -EOPNOTSUPP;
				}
				else
					tmp->data = data;
				break;
			case HB_INODE_REMOVEXATTR:
			case HB_INODE_GETXATTR:
			case HB_INODE_SETXATTR:
				tmp->data = (void *)kmalloc(sizeof(hb_inode_ll), GFP_KERNEL);
				strncpy(tmp->proc, HB_INODE_PROC, strlen(HB_INODE_PROC));
				if (tmp->data == NULL) {
					printk(KERN_ERR "unable to add inode notify linked list\n");
					err = -EOPNOTSUPP;
				}
				else
					tmp->data = data;
				break;
			case HB_SB_COPY_DATA:
			case HB_SB_STATFS:
			case HB_SB_REMOUNT:
			case HB_SB_UMOUNT:
			case HB_SB_MOUNT:
				tmp->data = (void *)kmalloc(sizeof(hb_sb_ll), GFP_KERNEL);
				strncpy(tmp->proc, HB_SB_PROC, strlen(HB_SB_PROC));
				if (tmp->data == NULL) {
					printk(KERN_ERR "unable to add sb notify linked list\n");
					err = -EOPNOTSUPP;
				}
				else
					tmp->data = data;
				break;
			case HB_KMOD_REQ:
				tmp->data = (void *)kmalloc(sizeof(hb_kmod_ll), GFP_KERNEL);
				strncpy(tmp->proc, HB_KMOD_PROC, strlen(HB_KMOD_PROC));
				if (tmp->data == NULL) {
					printk(KERN_ERR "unable to add kmod notify linked list\n");
					err = -EOPNOTSUPP;
				}
				else
					tmp->data = data;
				break;
			default:
				break;
		}

		if (err == 0)
		       	list_add(&(tmp->list), &(hb_notify_list_head.list));
	}
	else
		err = -EOPNOTSUPP;

	return err;
}

int read_notify_record(struct seq_file *m, void *v)
{
	hb_notify_ll *tmp = NULL;
	struct list_head *pos = NULL;
	struct list_head *q = NULL;
	unsigned long total = 0;
       	hb_binprm_ll *binprm = NULL;
       	hb_file_ll *files = NULL;
       	hb_task_ll *tasks = NULL;
       	hb_socket_ll *sockets = NULL;
       	hb_path_ll *paths = NULL;
       	hb_inode_ll *inodes = NULL;
       	hb_sb_ll *sbs = NULL;
       	hb_kmod_ll *kmods = NULL;

	seq_printf(m, "ID\tFILE\tFUNC\tUID\tDATA\n");
	list_for_each_safe(pos, q, &hb_notify_list_head.list) {
		tmp = list_entry(pos, hb_notify_ll, list);
		switch (tmp->fid) {
			case HB_BPRM_SET_CREDS:
				binprm = (hb_binprm_ll *)tmp->data;
				seq_printf(m, "%lu\t%s\t%u\t%d\t%s\t%s\n", total++, tmp->proc, binprm->fid, binprm->uid, binprm->digest, binprm->pathname);
				break;
			case HB_FILE_OPEN:
				files = (hb_file_ll *)tmp->data;
				seq_printf(m, "%lu\t%s\t%u\t%d\t%s\n", total++, tmp->proc, files->fid, files->uid, files->pathname);
				break;
			case HB_TASK_SIGNAL:
				tasks = (hb_task_ll *)tmp->data;
				seq_printf(m, "%lu\t%s\t%u\t%d\t%d\t%d\t%d\t%u\n", total++, tmp->proc, tasks->fid\
						, tasks->uid, tasks->sig, tasks->si_signo, tasks->si_errno\
						, tasks->secid);
				break;
			case HB_SOCKET_CREATE:
			case HB_SOCKET_CONNECT:
			case HB_SOCKET_BIND:
			case HB_SOCKET_SETSOCKOPT:
				sockets = (hb_socket_ll *)tmp->data;
				seq_printf(m, "%lu\t%s\t%u\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", total++, tmp->proc, sockets->fid, sockets->uid, sockets->family, sockets->type, sockets->protocol, sockets->kern, sockets->port, sockets->backlog, sockets->level, sockets->optname);
				break;
			case HB_PATH_RENAME:
			case HB_PATH_SYMLINK:
			case HB_PATH_RMDIR:
			case HB_PATH_TRUNCATE:
			case HB_PATH_LINK:
			case HB_PATH_UNLINK:
			case HB_PATH_CHOWN:
			case HB_PATH_MKNOD:
			case HB_PATH_MKDIR:
			case HB_PATH_CHMOD:
				paths = (hb_path_ll *)tmp->data;
				seq_printf(m, "%lu\t%s\t%u\t%d\t%u\t%u\t%u\t%u\t%s\t\t%s\n", total++, tmp->proc, paths->fid\
						, paths->uid, paths->mode, paths->suid, paths->sgid \
						, paths->dev, paths->source_pathname, paths->target_pathname);
				break;
			case HB_INODE_REMOVEXATTR:
			case HB_INODE_GETXATTR:
			case HB_INODE_SETXATTR:
				inodes = (hb_inode_ll *)tmp->data;
				seq_printf(m, "%lu\t%s\t%u\t%u\t%s\t%s\n", total++, tmp->proc, inodes->fid\
						, inodes->uid, inodes->name, inodes->binprm);
				break;
			case HB_SB_COPY_DATA:
			case HB_SB_STATFS:
			case HB_SB_REMOUNT:
			case HB_SB_UMOUNT:
			case HB_SB_MOUNT:
				sbs = (hb_sb_ll *)tmp->data;
				seq_printf(m, "%lu\t%s\t%u\t%u\t%s\t%s\t%s\t%s\t%d\n", total++, tmp->proc, sbs->fid\
						, sbs->uid, sbs->s_id, sbs->name, sbs->dev_name, sbs->type, sbs->flags);
				break;
			case HB_KMOD_REQ:
				kmods = (hb_kmod_ll *)tmp->data;
				seq_printf(m, "%lu\t%s\t%u\t%u\t%s\n", total++, tmp->proc, sbs->fid\
						, sbs->uid, sbs->name);
				break;
			default:
				break;
		}

		list_del(pos);
		if (tmp->data != NULL)
		       	kfree(tmp->data);
		kfree(tmp);
	}

	return 0;
}


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
#include "ptrace.h"
#include "ipc.h"
#include "honeybest.h"

extern int hblevel;
unsigned long total_notify_record = 0;
struct proc_dir_entry *hb_proc_notify_entry;
hb_notify_ll hb_notify_list_head;
unsigned long total = 0;

int add_notify_record(unsigned int fid, void *data)
{
	int err = 0;
	hb_notify_ll *tmp = NULL;

	tmp = (hb_notify_ll *)kmalloc(sizeof(hb_notify_ll), GFP_KERNEL);
	if (!tmp) {
		err = -EOPNOTSUPP;
		goto out;
	}

	memset(tmp, 0, sizeof(hb_notify_ll));
	tmp->fid = fid;
	tmp->data = NULL;
	switch (fid) {
		case HB_BPRM_SET_CREDS:
		case HB_FILE_MMAP:
			strncpy(tmp->proc, HB_CREDS_PROC, strlen(HB_CREDS_PROC));
			tmp->data = (hb_binprm_ll *)data;
			break;
		case HB_PTRACE_ACCESS_CHECK:
			strncpy(tmp->proc, HB_PTRACE_PROC, strlen(HB_PTRACE_PROC));
			tmp->data = (hb_ptrace_ll *)data;
			break;
		case HB_FILE_RECEIVE:
		case HB_FILE_IOCTL:
		case HB_FILE_OPEN:
			strncpy(tmp->proc, HB_FILE_PROC, strlen(HB_FILE_PROC));
			tmp->data = (hb_file_ll *)data;
			break;
		case HB_TASK_SIGNAL:
			strncpy(tmp->proc, HB_TASK_PROC, strlen(HB_TASK_PROC));
			tmp->data = (hb_task_ll *)data;
			break;
		case HB_SOCKET_CREATE:
		case HB_SOCKET_CONNECT:
		case HB_SOCKET_BIND:
		case HB_SOCKET_SETSOCKOPT:
			strncpy(tmp->proc, HB_SOCKET_PROC, strlen(HB_SOCKET_PROC));
			tmp->data = (hb_socket_ll *)data;
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
			strncpy(tmp->proc, HB_PATH_PROC, strlen(HB_PATH_PROC));
			tmp->data = (hb_path_ll *)data;
			break;
		case HB_INODE_REMOVEXATTR:
		case HB_INODE_GETXATTR:
		case HB_INODE_SETXATTR:
			strncpy(tmp->proc, HB_INODE_PROC, strlen(HB_INODE_PROC));
			tmp->data = (hb_inode_ll *)data;
			break;
		case HB_SB_COPY_DATA:
		case HB_SB_STATFS:
		case HB_SB_REMOUNT:
		case HB_SB_UMOUNT:
		case HB_SB_KERN_MOUNT:
		case HB_SB_MOUNT:
			strncpy(tmp->proc, HB_SB_PROC, strlen(HB_SB_PROC));
			tmp->data = (hb_sb_ll *)data;
			break;
		case HB_KMOD_LOAD_FROM_FILE:
		case HB_KMOD_REQ:
			strncpy(tmp->proc, HB_KMOD_PROC, strlen(HB_KMOD_PROC));
			tmp->data = (hb_kmod_ll *)data;
			break;
		case HB_IPC_PERM:
			strncpy(tmp->proc, HB_IPC_PROC, strlen(HB_IPC_PROC));
			tmp->data = (hb_ipc_ll *)data;
			break;
		default:
			break;
	}

	if (tmp->data == NULL) {
		printk(KERN_ERR "Don't add null data\n");
		err = -EOPNOTSUPP;
	}

	if (err == 0) {
		/* check repo before add */
		list_add(&(tmp->list), &(hb_notify_list_head.list));
		total_notify_record++;
	}
out:
	if (err != 0)
		kfree(tmp);
	return err;
}

void *hb_notify_seq_start(struct seq_file *s, loff_t *pos)
{
	seq_printf(s, "ID\tFILE\tFUNC\tUID\tDATA\n");
	return seq_list_start(&hb_notify_list_head.list, *pos);
}

void *hb_notify_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	return seq_list_next(v, &hb_notify_list_head.list, pos);
}

void hb_notify_seq_stop(struct seq_file *s, void *v)
{
	struct list_head *pos = NULL;
	struct list_head *q = NULL;

	list_for_each_safe(pos, q, &hb_notify_list_head.list) {
		hb_notify_ll *tmp = NULL;
	       	hb_binprm_ll *binprm = NULL;
	       	hb_file_ll *files = NULL;
	       	hb_task_ll *tasks = NULL;
	       	hb_socket_ll *sockets = NULL;
	       	hb_path_ll *paths = NULL;
	       	hb_inode_ll *inodes = NULL;
	       	hb_sb_ll *sbs = NULL;
	       	hb_kmod_ll *kmods = NULL;
	       	hb_ipc_ll *ipc = NULL;
	       	hb_ptrace_ll *ptrace = NULL;


		tmp = list_entry(pos, hb_notify_ll, list);
		if (tmp->dirty != true)
			continue;
		switch (tmp->fid) {
			case HB_BPRM_SET_CREDS:
			case HB_FILE_MMAP:
				binprm = (hb_binprm_ll *)tmp->data;
				free_cred_record(binprm);
				break;
			case HB_PTRACE_ACCESS_CHECK:
				ptrace = (hb_ptrace_ll *)tmp->data;
				free_ptrace_record(ptrace);
				break;
			case HB_FILE_OPEN:
			case HB_FILE_RECEIVE:
			case HB_FILE_IOCTL:
				files = (hb_file_ll *)tmp->data;
				free_file_record(files);
				break;
			case HB_TASK_SIGNAL:
				tasks = (hb_task_ll *)tmp->data;
				free_task_record(tasks);
				break;
			case HB_SOCKET_CREATE:
			case HB_SOCKET_CONNECT:
			case HB_SOCKET_BIND:
			case HB_SOCKET_SETSOCKOPT:
				sockets = (hb_socket_ll *)tmp->data;
				free_socket_record(sockets);
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
				free_path_record(paths);
				break;
			case HB_INODE_REMOVEXATTR:
			case HB_INODE_GETXATTR:
			case HB_INODE_SETXATTR:
				inodes = (hb_inode_ll *)tmp->data;
				free_inode_record(inodes);
				break;
			case HB_SB_COPY_DATA:
			case HB_SB_STATFS:
			case HB_SB_REMOUNT:
			case HB_SB_UMOUNT:
			case HB_SB_KERN_MOUNT:
			case HB_SB_MOUNT:
				sbs = (hb_sb_ll *)tmp->data;
				free_sb_record(sbs);
				break;
			case HB_KMOD_LOAD_FROM_FILE:
			case HB_KMOD_REQ:
				kmods = (hb_kmod_ll *)tmp->data;
				free_kmod_record(kmods);
				break;
			case HB_IPC_PERM:
				ipc = (hb_ipc_ll *)tmp->data;
				free_ipc_record(tmp->data);
				break;
			default:
				break;
		}

		list_del(pos);
		kfree(tmp);
		total_notify_record--;
	}
	total = 0;
}

int hb_notify_seq_show(struct seq_file *s, void *v)
{
	struct list_head *pos = NULL;
	struct list_head *q = NULL;

	list_for_each_safe(pos, q, &hb_notify_list_head.list) {
		hb_notify_ll *tmp = NULL;
	       	hb_binprm_ll *binprm = NULL;
	       	hb_file_ll *files = NULL;
	       	hb_task_ll *tasks = NULL;
	       	hb_socket_ll *sockets = NULL;
	       	hb_path_ll *paths = NULL;
	       	hb_inode_ll *inodes = NULL;
	       	hb_sb_ll *sbs = NULL;
	       	hb_kmod_ll *kmods = NULL;
	       	hb_ipc_ll *ipc = NULL;
	       	hb_ptrace_ll *ptrace = NULL;


		tmp = list_entry(pos, hb_notify_ll, list);
		if (tmp->dirty == true)
			continue;
		switch (tmp->fid) {
			case HB_BPRM_SET_CREDS:
			case HB_FILE_MMAP:
				binprm = (hb_binprm_ll *)tmp->data;
				seq_printf(s, "%lu\t%s\t%u\t%s\t%c\t%s\t%s\n", total++, tmp->proc, binprm->fid, binprm->uid, binprm->act_allow, binprm->digest, binprm->pathname);
				tmp->dirty = true;
				break;
			case HB_PTRACE_ACCESS_CHECK:
				ptrace = (hb_ptrace_ll *)tmp->data;
				seq_printf(s, "%lu\t%s\t%u\t%s\t%c\t%s\t%s\t%u\n", total++, tmp->proc, ptrace->fid, ptrace->uid, ptrace->act_allow, ptrace->parent, ptrace->child, ptrace->mode);
				tmp->dirty = true;
				break;
			case HB_FILE_OPEN:
			case HB_FILE_RECEIVE:
			case HB_FILE_IOCTL:
				files = (hb_file_ll *)tmp->data;
				seq_printf(s, "%lu\t%s\t%u\t%s\t%c\t%s\t%s\t%u\n", total++, tmp->proc, files->fid, files->uid, files->act_allow, files->filename, files->binprm, files->cmd);
				tmp->dirty = true;
				break;
			case HB_TASK_SIGNAL:
				tasks = (hb_task_ll *)tmp->data;
				seq_printf(s, "%lu\t%s\t%u\t%s\t%c\t%d\t%u\n", total++, tmp->proc, tasks->fid, tasks->uid, tasks->act_allow, tasks->sig, tasks->secid);
				tmp->dirty = true;
				break;
			case HB_SOCKET_CREATE:
			case HB_SOCKET_CONNECT:
			case HB_SOCKET_BIND:
			case HB_SOCKET_SETSOCKOPT:
				sockets = (hb_socket_ll *)tmp->data;
				seq_printf(s, "%lu\t%s\t%u\t%s\t%c\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n", total++, tmp->proc, sockets->fid, sockets->uid, sockets->act_allow, sockets->family, sockets->type, sockets->protocol, sockets->port, sockets->level, sockets->optname, sockets->binprm);
				tmp->dirty = true;
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
				seq_printf(s, "%lu\t%s\t%u\t%s\t%c\t%u\t%s\t%s\t%u\t%s\t\t%s\t\t%s\n", total++, tmp->proc, paths->fid , paths->uid, paths->act_allow, paths->mode, paths->suid, paths->sgid, paths->dev, paths->s_path, paths->t_path, paths->binprm);
				tmp->dirty = true;
				break;
			case HB_INODE_REMOVEXATTR:
			case HB_INODE_GETXATTR:
			case HB_INODE_SETXATTR:
				inodes = (hb_inode_ll *)tmp->data;
				seq_printf(s, "%lu\t%s\t%u\t%s\t%c\t%s\t%s\n", total++, tmp->proc, inodes->fid , inodes->uid, inodes->act_allow, inodes->name, inodes->binprm);
				tmp->dirty = true;
				break;
			case HB_SB_COPY_DATA:
			case HB_SB_STATFS:
			case HB_SB_REMOUNT:
			case HB_SB_UMOUNT:
			case HB_SB_KERN_MOUNT:
			case HB_SB_MOUNT:
				sbs = (hb_sb_ll *)tmp->data;
				seq_printf(s, "%lu\t%s\t%u\t%s\t%c\t%s\t%s\t%s\t%s\t%d\n", total++, tmp->proc, sbs->fid , sbs->uid, sbs->act_allow, sbs->s_id, sbs->name, sbs->dev_name, sbs->type, sbs->flags);
				tmp->dirty = true;
				break;
			case HB_KMOD_LOAD_FROM_FILE:
			case HB_KMOD_REQ:
				kmods = (hb_kmod_ll *)tmp->data;
				seq_printf(s, "%lu\t%s\t%u\t%s\t%c\t%s\t%s\t%s\n", total++, tmp->proc, kmods->fid , kmods->uid, kmods->act_allow, kmods->name, kmods->filename, kmods->digest);
				tmp->dirty = true;
				break;
			case HB_IPC_PERM:
				ipc = (hb_ipc_ll *)tmp->data;
				seq_printf(s, "%lu\t%s\t%u\t%s\t%c\t%s\t%d\t%d\t%d\t%d\t%d\n", total++, tmp->proc, ipc->fid, \
						ipc->uid, ipc->act_allow, ipc->binprm, ipc->ipc_uid, ipc->ipc_gid, \
						ipc->ipc_cuid, ipc->ipc_cgid, ipc->flag);
				tmp->dirty = true;
				break;
			default:
				break;
		}
	}
	return 0;
}


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
			case HL_BPRM_SET_CREDS:
				tmp->data = (void *)kmalloc(sizeof(hb_binprm_ll), GFP_KERNEL);
				strncpy(tmp->proc, HL_CREDS_PROC, strlen(HL_CREDS_PROC));
				if (tmp->data == NULL) {
					printk(KERN_ERR "unable to add binprm notify linked list\n");
					err = -EOPNOTSUPP;
				}
				else
					tmp->data = data;
				break;
			case HL_FILE_OPEN:
				tmp->data = (void *)kmalloc(sizeof(hb_file_ll), GFP_KERNEL);
				strncpy(tmp->proc, HL_FILE_PROC, strlen(HL_FILE_PROC));
				if (tmp->data == NULL) {
					printk(KERN_ERR "unable to add file notify linked list\n");
					err = -EOPNOTSUPP;
				}
				else
					tmp->data = data;
				break;
			case HL_TASK_SIGNAL:
				tmp->data = (void *)kmalloc(sizeof(hb_task_ll), GFP_KERNEL);
				strncpy(tmp->proc, HL_TASK_PROC, strlen(HL_TASK_PROC));
				if (tmp->data == NULL) {
					printk(KERN_ERR "unable to add task notify linked list\n");
					err = -EOPNOTSUPP;
				}
				else
					tmp->data = data;
				break;
			case HL_SOCKET_CREATE:
			case HL_SOCKET_CONNECT:
			case HL_SOCKET_BIND:
			case HL_SOCKET_SETSOCKOPT:
				tmp->data = (void *)kmalloc(sizeof(hb_socket_ll), GFP_KERNEL);
				strncpy(tmp->proc, HL_SOCKET_PROC, strlen(HL_SOCKET_PROC));
				if (tmp->data == NULL) {
					printk(KERN_ERR "unable to add socket notify linked list\n");
					err = -EOPNOTSUPP;
				}
				else
					tmp->data = data;
				break;
			case HL_PATH_RENAME:
			case HL_PATH_SYMLINK:
			case HL_PATH_RMDIR:
			case HL_PATH_TRUNCATE:
			case HL_PATH_LINK:
			case HL_PATH_UNLINK:
			case HL_PATH_CHOWN:
			case HL_PATH_MKNOD:
			case HL_PATH_MKDIR:
			case HL_PATH_CHMOD:
				tmp->data = (void *)kmalloc(sizeof(hb_path_ll), GFP_KERNEL);
				strncpy(tmp->proc, HL_PATH_PROC, strlen(HL_PATH_PROC));
				if (tmp->data == NULL) {
					printk(KERN_ERR "unable to add path notify linked list\n");
					err = -EOPNOTSUPP;
				}
				else
					tmp->data = data;
				break;
			case HL_INODE_REMOVEXATTR:
			case HL_INODE_GETXATTR:
			case HL_INODE_SETXATTR:
				tmp->data = (void *)kmalloc(sizeof(hb_inode_ll), GFP_KERNEL);
				strncpy(tmp->proc, HL_INODE_PROC, strlen(HL_INODE_PROC));
				if (tmp->data == NULL) {
					printk(KERN_ERR "unable to add inode notify linked list\n");
					err = -EOPNOTSUPP;
				}
				else
					tmp->data = data;
				break;
			case HL_SB_COPY_DATA:
			case HL_SB_STATFS:
			case HL_SB_REMOUNT:
			case HL_SB_UMOUNT:
			case HL_SB_MOUNT:
				tmp->data = (void *)kmalloc(sizeof(hb_sb_ll), GFP_KERNEL);
				strncpy(tmp->proc, HL_SB_PROC, strlen(HL_SB_PROC));
				if (tmp->data == NULL) {
					printk(KERN_ERR "unable to add sb notify linked list\n");
					err = -EOPNOTSUPP;
				}
				else
					tmp->data = data;
				break;
			case HL_KMOD_REQ:
				tmp->data = (void *)kmalloc(sizeof(hb_kmod_ll), GFP_KERNEL);
				strncpy(tmp->proc, HL_KMOD_PROC, strlen(HL_KMOD_PROC));
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
			case HL_BPRM_SET_CREDS:
				binprm = (hb_binprm_ll *)tmp->data;
				seq_printf(m, "%lu\t%s\t%u\t%d\t%s\t%s\n", total++, tmp->proc, binprm->fid, binprm->uid, binprm->digest, binprm->pathname);
				break;
			case HL_FILE_OPEN:
				files = (hb_file_ll *)tmp->data;
				seq_printf(m, "%lu\t%s\t%u\t%d\t%s\n", total++, tmp->proc, files->fid, files->uid, files->pathname);
				break;
			case HL_TASK_SIGNAL:
				tasks = (hb_task_ll *)tmp->data;
				seq_printf(m, "%lu\t%s\t%u\t%d\t%d\t%d\t%d\t%u\n", total++, tmp->proc, tasks->fid\
						, tasks->uid, tasks->sig, tasks->si_signo, tasks->si_errno\
						, tasks->secid);
				break;
			case HL_SOCKET_CREATE:
			case HL_SOCKET_CONNECT:
			case HL_SOCKET_BIND:
			case HL_SOCKET_SETSOCKOPT:
				sockets = (hb_socket_ll *)tmp->data;
				seq_printf(m, "%lu\t%s\t%u\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", total++, tmp->proc, sockets->fid, sockets->uid, sockets->family, sockets->type, sockets->protocol, sockets->kern, sockets->port, sockets->backlog, sockets->level, sockets->optname);
				break;
			case HL_PATH_RENAME:
			case HL_PATH_SYMLINK:
			case HL_PATH_RMDIR:
			case HL_PATH_TRUNCATE:
			case HL_PATH_LINK:
			case HL_PATH_UNLINK:
			case HL_PATH_CHOWN:
			case HL_PATH_MKNOD:
			case HL_PATH_MKDIR:
			case HL_PATH_CHMOD:
				paths = (hb_path_ll *)tmp->data;
				seq_printf(m, "%lu\t%s\t%u\t%d\t%u\t%u\t%u\t%u\t%s\t\t%s\n", total++, tmp->proc, paths->fid\
						, paths->uid, paths->mode, paths->suid, paths->sgid \
						, paths->dev, paths->source_pathname, paths->target_pathname);
				break;
			case HL_INODE_REMOVEXATTR:
			case HL_INODE_GETXATTR:
			case HL_INODE_SETXATTR:
				inodes = (hb_inode_ll *)tmp->data;
				seq_printf(m, "%lu\t%s\t%u\t%u\t%u\t%s\t%s\n", total++, tmp->proc, inodes->fid\
						, inodes->uid, inodes->mode, inodes->name, inodes->dname);
				break;
			case HL_SB_COPY_DATA:
			case HL_SB_STATFS:
			case HL_SB_REMOUNT:
			case HL_SB_UMOUNT:
			case HL_SB_MOUNT:
				sbs = (hb_sb_ll *)tmp->data;
				seq_printf(m, "%lu\t%s\t%u\t%u\t%s\t%s\t%s\t%s\t%d\n", total++, tmp->proc, sbs->fid\
						, sbs->uid, sbs->s_id, sbs->name, sbs->dev_name, sbs->type, sbs->flags);
				break;
			case HL_KMOD_REQ:
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


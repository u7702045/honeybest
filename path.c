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

struct proc_dir_entry *hb_proc_path_entry;
hb_path_ll hb_path_list_head;
hb_path_ll *search_path_record(unsigned int fid, uid_t uid, umode_t mode, char *source_pathname, char *target_pathname, uid_t suid, uid_t sgid, unsigned int dev)
{
	hb_path_ll *tmp = NULL;
	struct list_head *pos = NULL;

	list_for_each(pos, &hb_path_list_head.list) {
		tmp = list_entry(pos, hb_path_ll, list);
		switch (fid) {
			case HL_PATH_RENAME:
			case HL_PATH_TRUNCATE:
			case HL_PATH_RMDIR:
			case HL_PATH_SYMLINK:
			case HL_PATH_LINK:
			case HL_PATH_UNLINK:
				if ((tmp->fid == fid) && (uid == tmp->uid) && !compare_regex(tmp->source_pathname, source_pathname, strlen(source_pathname)) && !compare_regex(tmp->target_pathname, target_pathname, strlen(target_pathname))) {
					/* we find the record */
					printk(KERN_INFO "Found link/rename/rmdir/symlink/unlink path record !!!!\n");
					return tmp;
				}
				break;
			case HL_PATH_MKDIR:
			case HL_PATH_CHMOD:
				if ((tmp->fid == fid) && (uid == tmp->uid) && !compare_regex(tmp->source_pathname, source_pathname, strlen(source_pathname)) && (tmp->mode == mode)) {
					/* we find the record */
					printk(KERN_INFO "Found chmod path record !!!!\n");
					return tmp;
				}
				break;
			case HL_PATH_CHOWN:
				if ((tmp->fid == fid) && (uid == tmp->uid) && !compare_regex(tmp->source_pathname, source_pathname, strlen(source_pathname)) && (tmp->suid == suid) && (tmp->sgid == sgid)) {
					/* we find the record */
					printk(KERN_INFO "Found chown path record !!!!\n");
					return tmp;
				}
				break;
			case HL_PATH_MKNOD:
				if ((tmp->fid == fid) && (uid == tmp->uid) && !compare_regex(tmp->source_pathname, source_pathname, strlen(source_pathname)) && (tmp->dev == dev)) {
					/* we find the record */
					printk(KERN_INFO "Found mknod path record !!!!\n");
					return tmp;
				}
				break;
			default:
				break;
		} // switch
	} // path linked list

	return NULL;
}

int add_path_record(unsigned int fid, uid_t uid, umode_t mode, char *source_pathname, char *target_pathname, \
		uid_t suid, uid_t sgid, unsigned int dev, int interact)
{
	int err = 0;
	hb_path_ll *tmp = NULL;

	tmp = (hb_path_ll *)kmalloc(sizeof(hb_path_ll), GFP_KERNEL);
	if (tmp) {
		memset(tmp, 0, sizeof(hb_path_ll));
		tmp->fid = fid;
		tmp->uid = uid;
		tmp->suid = 0;
		tmp->sgid = 0;
		tmp->dev = 0;
		tmp->mode = 0;
		tmp->source_pathname = kmalloc(strlen(source_pathname)+1, GFP_KERNEL);
	       	tmp->target_pathname = kmalloc(strlen(target_pathname)+1, GFP_KERNEL);
		if (tmp->source_pathname == NULL) {
			err = -EOPNOTSUPP;
			goto out;
		}
		if (tmp->target_pathname == NULL) {
			kfree(tmp->source_pathname);
			err = -EOPNOTSUPP;
			goto out;
		}

		strcpy(tmp->source_pathname, source_pathname);
		strcpy(tmp->target_pathname, target_pathname);

		switch (fid) {
			case HL_PATH_RENAME:
			case HL_PATH_SYMLINK:
			case HL_PATH_RMDIR:
			case HL_PATH_TRUNCATE:
			case HL_PATH_LINK:
			case HL_PATH_UNLINK:
				break;
			case HL_PATH_CHOWN:
				tmp->suid = suid;
				tmp->sgid = sgid;
				break;
			case HL_PATH_MKNOD:
				tmp->dev = dev;
				if (mode >= 0) //mknod from userspace look weird, bug?
				       	tmp->mode = mode;
				break;
			case HL_PATH_MKDIR:
			case HL_PATH_CHMOD:
				tmp->mode = mode;
				break;
			default:
				break;
		}

		if ((err == 0) && (interact == 0))
		       	list_add(&(tmp->list), &(hb_path_list_head.list));

		if ((err == 0) && (interact == 1))
			add_notify_record(fid, tmp);
	}
	else
		err = -EOPNOTSUPP;

out:
	return err;
}

int read_path_record(struct seq_file *m, void *v)
{
	hb_path_ll *tmp = NULL;
	struct list_head *pos = NULL;
	unsigned long total = 0;

	seq_printf(m, "ID\tFUNC\tUID\tMODE\tSUID\tGUID\tDEV NODE\tSOURCE PATH\t\t\tTARGET PATH\n");

	if (list_empty(&hb_path_list_head.list)) {
		printk(KERN_WARNING "List is empty!!\n");
		return 0;
	}

	list_for_each(pos, &hb_path_list_head.list) {
		tmp = list_entry(pos, hb_path_ll, list);
		seq_printf(m, "%lu\t%u\t%u\t%u\t%u\t%u\t%u\t%s\t\t%s\n", total++, tmp->fid, tmp->uid, tmp->mode, tmp->suid, tmp->sgid, tmp->dev, tmp->source_pathname, tmp->target_pathname);

	}

	return 0;
}

ssize_t write_path_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
	char rules[BUF_SIZE];
	char *delim = "\n";
	char *token, *cur = rules;
	hb_path_ll *tmp = NULL;
	struct list_head *pos = NULL;
	struct list_head *q = NULL;

	if(*ppos > 0 || count > BUF_SIZE) {
		printk(KERN_WARNING "Write size is too big!\n");
	       	return -EFAULT;
	}

	memset(rules, '\0', BUF_SIZE);
	if (count > 0) {
		if(copy_from_user(rules, buffer, count))
			    return -EFAULT;

		/* clean all rules */
		list_for_each_safe(pos, q, &hb_path_list_head.list) {
			tmp = list_entry(pos, hb_path_ll, list);
			list_del(pos);
			kfree(tmp->source_pathname);
			kfree(tmp->target_pathname);
			kfree(tmp);
			tmp = NULL;
		}

		/* add rules */
		while((token = strsep(&cur, delim)) && (strlen(token)>1)) {
			uid_t uid = 0;
			uid_t suid = 0;
			uid_t sgid = 0;
			unsigned int dev = 0;
			unsigned int fid = 0;
			umode_t mode = 0;
			char source_pathname[PATH_MAX];
			char target_pathname[PATH_MAX];

			sscanf(token, "%u %u %hd %u %u %u %s %s", &fid, &uid, &mode, &suid, &sgid, &dev, source_pathname, target_pathname);
		       	if (add_path_record(fid, uid, mode, source_pathname, target_pathname, suid, sgid, dev, 0) != 0) {
				printk(KERN_WARNING "Failure to add path record %u, %s, %s\n", uid, source_pathname, target_pathname);
			}
		}
	}
	return count;
}

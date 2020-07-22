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
#include "inode.h"
#include "hashlock.h"

struct proc_dir_entry *hb_proc_inode_entry;
hb_inode_ll hb_inode_list_head;
hb_inode_ll *search_inode_record(unsigned int fid, uid_t uid, char *pathname, umode_t mode)
{
	hb_inode_ll *tmp = NULL;
	struct list_head *pos = NULL;
	int err = 0;

	list_for_each(pos, &hb_inode_list_head.list) {
		tmp = list_entry(pos, hb_inode_ll, list);
		switch (fid) {
			case HL_INODE_CREATE:
				if ((!strcmp(tmp->pathname, pathname)) &&(uid == tmp->uid) && (tmp->mode == mode)) {
					/* we find the record */
					printk(KERN_INFO "Found inode open record !!!!\n");
					return tmp;
				}
				break;
			default:
				break;
		}
	}
	return NULL;
}

int add_inode_record(unsigned int fid, uid_t uid, char *pathname, umode_t mode)
{
	int err = 0;
#if 0
	hb_inode_ll *tmp = NULL;

	tmp = (hb_inode_ll *)kmalloc(sizeof(hb_inode_ll), GFP_KERNEL);
	if (tmp) {
		tmp->fid = fid;
		tmp->uid = uid;
		tmp->sig = sig;
		tmp->si_signo = si_signo;
		tmp->si_errno = si_errno;
		tmp->secid = secid;
		list_add(&(tmp->list), &(hb_inode_list_head.list));
	}
	else
		err = -EOPNOTSUPP;
#endif
	return err;
}

int read_inode_record(struct seq_file *m, void *v)
{
#if 0
	hb_inode_ll *tmp = NULL;
	struct list_head *pos = NULL;
	unsigned long total = 0;

	list_for_each(pos, &hb_inode_list_head.list) {
		tmp = list_entry(pos, hb_inode_ll, list);
		seq_printf(m, "%lu %u %d %d %d %u\n", total++, tmp->uid, tmp->sig, tmp->si_signo, tmp->si_errno, tmp->secid);
	}
#endif
	return 0;
}

ssize_t write_inode_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
#if 0
	char rules[BUF_SIZE];
	char *delim = "\n";
	char *token, *cur = rules;
	hb_inode_ll *tmp = NULL;
	struct list_head *pos = NULL;
	struct list_head *q = NULL;

	if(*ppos > 0 || count > BUF_SIZE) {
		printk(KERN_ERR "Write size is too big!\n");
	       	return -EFAULT;
	}

	memset(rules, '\0', BUF_SIZE);
	if (count > 0) {
		if(copy_from_user(rules, buffer, count))
			    return -EFAULT;

		/* clean all rules */
		list_for_each_safe(pos, q, &hb_inode_list_head.list) {
			tmp = list_entry(pos, hb_inode_ll, list);
			list_del(pos);
			kfree(tmp);
			tmp = NULL;
		}

		/* add rules */
		while((token = strsep(&cur, delim)) && (strlen(token)>1)) {
			uid_t uid = 0;
			int sig = 0;
			int si_signo = 0;
			int si_errno = 0;
			u32 secid = 0;

			sscanf(token, "%u %d %d %d %u", &uid, &sig, &si_signo, &si_errno, &secid);
		       	if (add_inode_record(HL_TASK_SIGNAL, uid, sig, si_signo, si_errno, secid) != 0) {
				printk(KERN_ERR "Failure to add inode record %u, %d\n", uid, sig);
			}
		}
	}
#endif
	return count;
}


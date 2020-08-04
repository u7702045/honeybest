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
#include "socket.h"
#include "notify.h"
#include "honeybest.h"

struct proc_dir_entry *hb_proc_socket_entry;
hb_socket_ll hb_socket_list_head;

static unsigned short lookup_source_port(struct socket *sock, struct sockaddr *address, int addrlen)
{
	struct sock *sk = sock->sk;
	u16 family = sk->sk_family;

	if (family == PF_INET || family == PF_INET6) {
	       	unsigned short snum;
		struct sockaddr_in *addr4 = NULL;
		struct sockaddr_in6 *addr6 = NULL;
		char *addrp = NULL;
		if (family == PF_INET) {
			if (addrlen < sizeof(struct sockaddr_in)) {
				goto out;
			}
			addr4 = (struct sockaddr_in *)address;
			snum = ntohs(addr4->sin_port);
			addrp = (char *)&addr4->sin_addr.s_addr;
		} else {
			if (addrlen < SIN6_LEN_RFC2133) {
				goto out;
			}
			addr6 = (struct sockaddr_in6 *)address;
			snum = ntohs(addr6->sin6_port);
			addrp = (char *)&addr6->sin6_addr.s6_addr;
		}

		return snum;
	}

out:
	return 0;
}

hb_socket_ll *search_socket_record(unsigned int fid, uid_t uid, int family, int type, int protocol, int kern,
		int backlog, int level, int optname, struct socket *sock, struct sockaddr *address, int addrlen)
{
	hb_socket_ll *tmp = NULL;
	struct list_head *pos = NULL;
       	unsigned short snum = 0;

	list_for_each(pos, &hb_socket_list_head.list) {
		tmp = list_entry(pos, hb_socket_ll, list);
		switch (fid) {
			case HB_SOCKET_CREATE:
			case HB_SOCKET_CONNECT:
				if ((tmp->fid == fid) && (uid == tmp->uid) && (tmp->family == family) && (tmp->type == type) && (tmp->protocol == protocol) && (tmp->kern == kern)) {
					printk(KERN_INFO "Found socket create record !!!!\n");
					return tmp;
				}
				break;
			case HB_SOCKET_BIND:
				snum = lookup_source_port(sock, address, addrlen);
				if ((tmp->fid == fid) && (uid == tmp->uid) && (tmp->port == snum)) {
					printk(KERN_INFO "Found socket bind record !!!!\n");
					return tmp;
				}
				break;
			case HB_SOCKET_SETSOCKOPT:
				if ((tmp->fid == fid) && (uid == tmp->uid) && (tmp->level == level) && (tmp->optname == optname)) {
					printk(KERN_INFO "Found socket setsockopt record !!!!\n");
					return tmp;
				}
				break;
			default:
				break;
		} // switch
	} // socket linked list

	return NULL;
}

int read_socket_record(struct seq_file *m, void *v)
{
	hb_socket_ll *tmp = NULL;
	struct list_head *pos = NULL;
	unsigned long total = 0;

	seq_printf(m, "NO\tFUNC\tUID\tFAMILY\tTYPE\tPROTO\tKERN\tPORT\tBACKLOG\tLEVEL\tOPTNAME\n");
	list_for_each(pos, &hb_socket_list_head.list) {
		tmp = list_entry(pos, hb_socket_ll, list);
		seq_printf(m, "%lu\t%u\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", total++, tmp->fid, tmp->uid, tmp->family, tmp->type, tmp->protocol, tmp->kern, tmp->port, tmp->backlog, tmp->level, tmp->optname);
	}

	return 0;
}

int add_socket_record(unsigned int fid, uid_t uid, int family, int type,
		int protocol, int kern, int port, int backlog, int level, int optname,
	       	struct socket *sock, struct sockaddr *address, int addrlen, int interact)
{
	int err = 0;
	hb_socket_ll *tmp = NULL;

	tmp = (hb_socket_ll *)kmalloc(sizeof(hb_socket_ll), GFP_KERNEL);
	if (tmp) {
		memset(tmp, 0, sizeof(hb_socket_ll));
		tmp->fid = fid;
		tmp->uid = uid;
		switch (fid) {
			case HB_SOCKET_CREATE:
			case HB_SOCKET_CONNECT:
				tmp->family = family;
				tmp->type = type;
				tmp->protocol = protocol;
				tmp->kern = kern;
			       	break;
			case HB_SOCKET_BIND:
				if (interact == 0)
					tmp->port = 0;
				else
				       	tmp->port = lookup_source_port(sock, address, addrlen);
				break;
			case HB_SOCKET_SETSOCKOPT:
				tmp->level = level;
				tmp->optname = optname;
				break;
			default:
				break;
		}
		if ((err == 0) && (interact == 0))
			list_add(&(tmp->list), &(hb_socket_list_head.list));

		if ((err == 0) && (interact == 1))
			add_notify_record(fid, tmp);
	}
	else
		err = -EOPNOTSUPP;

	return err;
}

ssize_t write_socket_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
	char *acts_buff = NULL;
	char *delim = "\n";
	char *token, *cur;
	hb_socket_ll *tmp = NULL;
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
	list_for_each_safe(pos, q, &hb_socket_list_head.list) {
		tmp = list_entry(pos, hb_socket_ll, list);
		list_del(pos);
		kfree(tmp);
		tmp = NULL;
	}

       	cur = acts_buff;
	/* add acts_buff */
	while((token = strsep(&cur, delim)) && (strlen(token)>1)) {
		unsigned int fid = 0;
		uid_t uid = 0;
		int family = 0;
		int type = 0;
		int protocol = 0;
		int kern = 0;
		int port = 0;
		int backlog = 0;
		int level = 0;
		int optname = 0;

		sscanf(token, "%u %u %d %d %d %d %d %d %d %d", &fid, &uid, &family, &type, &protocol,
				&kern, &port, &backlog, &level, &optname);
		if (add_socket_record(fid, uid, family, type, protocol, kern,
					port, backlog, level, optname, NULL, NULL, 0, 0) != 0) {
			printk(KERN_WARNING "Failure to add socket record %u, %d, %d, %d\n", uid, family, type, protocol);
		}
	} //while
out1:
	kfree(acts_buff);
out:
	return count;
}


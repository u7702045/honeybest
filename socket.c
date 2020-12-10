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
#include <linux/version.h>
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
#include "regex.h"
#include "honeybest.h"

extern int locking;
extern int hb_level;
extern int hb_interact;
extern unsigned long total_notify_record;
extern hb_notify_ll hb_notify_list_head;
struct proc_dir_entry *hb_proc_socket_entry;
hb_socket_ll hb_socket_list_head;

unsigned short lookup_source_port(struct socket *sock, struct sockaddr *address, int addrlen)
{
	struct sock *sk = NULL;
	u16 family = 0;

	if (!sock || !address || (addrlen<=0)) {
		printk(KERN_ERR "%s is null, %d\n", __FUNCTION__, addrlen);
		goto out;
	}

	sk = sock->sk;
	family = sk->sk_family;

	if (family == PF_INET || family == PF_INET6) {
	       	unsigned short snum;
		struct sockaddr_in *addr4 = NULL;
		struct sockaddr_in6 *addr6 = NULL;
		char *addrp = NULL;
		if (family == PF_INET) {
			if (addrlen < sizeof(struct sockaddr_in)) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,4,0)
				printk(KERN_ERR "addrlen less than sizeof struct sockaddr_in(%d)\n", sizeof(struct sockaddr_in));
#else
				printk(KERN_ERR "addrlen less than sizeof struct sockaddr_in(%lu)\n", sizeof(struct sockaddr_in));
#endif
				goto out;
			}
			addr4 = (struct sockaddr_in *)address;
			snum = ntohs(addr4->sin_port);
			addrp = (char *)&addr4->sin_addr.s_addr;
		} else {
			if (addrlen < SIN6_LEN_RFC2133) {
				printk(KERN_ERR "addrlen less than SIN6_LEN_RFC2133(%d)\n", SIN6_LEN_RFC2133);
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

int match_socket_record(hb_socket_ll *data, unsigned int fid, uid_t uid, int family, int type, int protocol,
		int port, int level, int optname, char *binprm)
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
		case HB_SOCKET_CONNECT:
			if ((data->fid == fid) && do_compare_uid && (data->family == family) && (data->type == type) && (data->protocol == protocol) && (data->port == port) && !compare_regex(data->binprm, binprm)) {
				match = 1;
			}
			break;
		case HB_SOCKET_CREATE:
			if ((data->fid == fid) && do_compare_uid && (data->family == family) && (data->type == type) && (data->protocol == protocol) && !compare_regex(data->binprm, binprm)) {
				//printk(KERN_INFO "Found socket create record !!!!\n");
				match = 1;
			}
			break;
		case HB_SOCKET_BIND:
			if ((data->fid == fid) && do_compare_uid && (data->port == port) && !compare_regex(data->binprm, binprm)) {
				//printk(KERN_INFO "Found socket bind record !!!!\n");
				match = 1;
			}
			break;
		case HB_SOCKET_SETSOCKOPT:
			if ((data->fid == fid) && do_compare_uid && (data->level == level) && (data->optname == optname) && !compare_regex(data->binprm, binprm)) {
				//printk(KERN_INFO "Found socket setsockopt record !!!!\n");
				match = 1;
			}
			break;
		default:
			break;
	} // switch


	return match;
}

hb_socket_ll *search_socket_record(unsigned int fid, uid_t uid, int family, int type, int protocol,
		int port, int level, int optname, char *binprm)
{
	struct list_head *pos = NULL;

	list_for_each(pos, &hb_socket_list_head.list) {
		hb_socket_ll *tmp = NULL;

		tmp = list_entry(pos, hb_socket_ll, list);

		if(match_socket_record(tmp, fid, uid, family, type, protocol, port, level, optname, binprm))
			return tmp;
	} // socket linked list

	return NULL;
}

hb_socket_ll *search_notify_socket_record(unsigned int fid, char *uid, int family, int type, int protocol,
		int port, int level, int optname, char *binprm)
{
	hb_notify_ll *tmp = NULL;
	struct list_head *pos = NULL;

	list_for_each(pos, &hb_notify_list_head.list) {

		tmp = list_entry(pos, hb_notify_ll, list);

		if (strstr(tmp->proc, HB_SOCKET_PROC)) {
			hb_socket_ll *data = tmp->data;
			unsigned long list_uid = 0;

			if(kstrtoul(uid, 10, &list_uid) != 0)
				printk(KERN_ERR "UID convert error\n");

			if(match_socket_record(data, fid, list_uid, family, type, protocol, port, level, optname, binprm)) {
				return data;
			}
		}
	} // notify linked list

	return NULL;
}

int read_socket_record(struct seq_file *m, void *v)
{
	struct list_head *pos = NULL;
	unsigned long total = 0;

	seq_printf(m, "NO\tFUNC\tUID\tACTION\tFAMILY\tTYPE\tPROTO\tPORT\tLEVEL\tOPTNAME\tBINPRM\n");
	list_for_each(pos, &hb_socket_list_head.list) {
		hb_socket_ll *tmp = NULL;

		tmp = list_entry(pos, hb_socket_ll, list);
		seq_printf(m, "%lu\t%u\t%s\t%c\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n", total++, tmp->fid, tmp->uid, tmp->act_allow, tmp->family, tmp->type, tmp->protocol, tmp->port, tmp->level, tmp->optname, tmp->binprm);
	}

	return 0;
}

int add_socket_record(unsigned int fid, char *uid, char act_allow, int family, int type, int protocol, 
		int port, int level, int optname, char *binprm)
{
	int err = 0;
	hb_socket_ll *tmp = NULL;

	tmp = (hb_socket_ll *)kmalloc(sizeof(hb_socket_ll), GFP_KERNEL);
	if (!tmp) {
		err = -EOPNOTSUPP;
		return err;
	}

	memset(tmp, 0, sizeof(hb_socket_ll));
	tmp->fid = fid;
	strncpy(tmp->uid, uid, UID_STR_SIZE-1);
	tmp->act_allow = act_allow;
	tmp->binprm = kmalloc(strlen(binprm), GFP_KERNEL);
	if (!tmp->binprm) {
		err = -EOPNOTSUPP;
		goto out;
	}
	strcpy(tmp->binprm, binprm);
	switch (fid) {
		case HB_SOCKET_CREATE:
		case HB_SOCKET_CONNECT:
			tmp->family = family;
			tmp->type = type;
			tmp->protocol = protocol;
			tmp->port = port;
			break;
		case HB_SOCKET_BIND:
			tmp->port = port;
			break;
		case HB_SOCKET_SETSOCKOPT:
			tmp->level = level;
			tmp->optname = optname;
			break;
		default:
			break;
	}
	if ((err == 0) && (hb_interact == 0))
		list_add(&(tmp->list), &(hb_socket_list_head.list));

	if ((err == 0) && (hb_interact == 1)) {
		if (!search_notify_socket_record(fid, uid, family, type, protocol, port, level, optname, binprm) && (total_notify_record < MAX_NOTIFY_RECORD)) {
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
		free_socket_record(tmp);
		kfree(tmp);
	}
	return err;
}

void free_socket_record(hb_socket_ll *data)
{
	kfree(data->binprm);
}

ssize_t write_socket_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
	char *acts_buff = NULL;
	char *delim = "\n";
	char *token, *cur;
	hb_socket_ll *tmp = NULL;
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
	list_for_each_safe(pos, q, &hb_socket_list_head.list) {
		tmp = list_entry(pos, hb_socket_ll, list);
		free_socket_record(tmp);
		list_del(pos);
		kfree(tmp);
		tmp = NULL;
	}

       	cur = acts_buff;
	/* add acts_buff */
	while((token = strsep(&cur, delim)) && (strlen(token)>1)) {
		unsigned int fid = 0;
		char uid[UID_STR_SIZE];
		int family = 0;
		int type = 0;
		int protocol = 0;
		int port = 0;
		int level = 0;
		char act_allow = 'R';
		char *binprm = NULL;
		int optname = 0;

		binprm = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!binprm)
			goto out1;

		sscanf(token, "%u %5s %c %d %d %d %d %d %d %4095s", &fid, uid, &act_allow, &family, &type, &protocol,
				&port, &level, &optname, binprm);
		if (add_socket_record(fid, uid, act_allow, family, type, protocol,
					port, level, optname, binprm) != 0) {
			printk(KERN_WARNING "Failure to add socket record %s, %d, %d, %d\n", uid, family, type, protocol);
		}
	} //while
out1:
	kfree(acts_buff);
out:
	return count;
}


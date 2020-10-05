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
#include "regex.h"
#include "honeybest.h"

// support only 1 * at the last,middle & full match, example /home/files.* or /proc/*maps
int compare_regex(char *str1, int len1, char *str2, int len2)
{
	int i = 0;
	int asterik_offset = 0;
	int have_asterik = 0;
	int str1_leftover = 0;
	enum regex_match match = End;

	if ((len1 <= 0) || (len2 <= 0))
		return 1;

	// check * offset
	for(i=0; i<len1; i++) {
		asterik_offset = i;
		if(str1[i] == '*') {
			have_asterik = 1;
		       	break;
		}
	}

	if (have_asterik == 0)
		match = Full;
	else {
		// verify if * is in the middle of the str1
		if (asterik_offset == len1-1)
			match = End;
		else {
			match = Middle;
			str1_leftover = asterik_offset+1;
		}
	}

	;//printk(KERN_ERR  "Match is [%d], len %d, ", match, len1);

	if (match == Full) {
	       	;//printk(KERN_ERR  "str1 %s, compare %d bytes\n", str1, len1>len2?len1:len2);
		if (len1 > len2)
		       	return strncmp(str1, str2, len1) && 1;
		else
		       	return strncmp(str1, str2, len2) && 1;
	}
	else if (match == Middle) {
			int ret = 1;
			int ret1 = 1;
			char *p = NULL;

			ret = strncmp(str1, str2, asterik_offset) && 1;

			p = strstr(str2, str1+str1_leftover);
			if (p) {
				/**< find the leftover only if match last char */
				if (p[strlen(str1+str1_leftover)] == '\0') {
					ret1 = 0;
				}
			}

	       		return (ret || ret1);
	}
	else if (match == End) {
	       	;//printk(KERN_ERR  "str1 %s, compare %d bytes\n", str1, asterik_offset);
		if (strlen(str1) <= strlen(str2))
	       		return strncmp(str1, str2, asterik_offset) && 1;
	}
	else
	       	printk(KERN_ERR  "Unknown regular expression.\n");

	return 1;
}



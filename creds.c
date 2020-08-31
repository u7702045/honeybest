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
#include <linux/version.h>
#include "creds.h"
#include "regex.h"
#include "notify.h"
#include "honeybest.h"

struct proc_dir_entry *hb_proc_binprm_entry;
hb_binprm_ll hb_binprm_list_head;

int match_binprm_record(hb_binprm_ll *data, unsigned int fid, uid_t uid, char *pathname, char *digest)
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

	if ((data->fid == HB_BPRM_SET_CREDS) && !memcmp(data->digest, digest, SHA1_HONEYBEST_DIGEST_SIZE-1) && do_compare_uid && !compare_regex(data->pathname, strlen(data->pathname), pathname, strlen(pathname))) {
		/* we find the record */
		//printk(KERN_INFO "Found binprm set record !!!!\n");
		match = 1;
	}

	return match;

}

hb_binprm_ll *search_binprm_record(unsigned int fid, uid_t uid, char *pathname, char *digest)
{
	hb_binprm_ll *tmp = NULL;
	struct list_head *pos = NULL;

	list_for_each(pos, &hb_binprm_list_head.list) {

		tmp = list_entry(pos, hb_binprm_ll, list);

		if(match_binprm_record(tmp, fid, uid, pathname, digest))
			return tmp;
	}

	return NULL;
}

int add_binprm_record(unsigned int fid, char *uid, char act_allow, char *pathname, char *digest, int interact)
{
	int err = 0;
	hb_binprm_ll *tmp = NULL;
       	int len = strlen(pathname);

	tmp = (hb_binprm_ll *)kmalloc(sizeof(hb_binprm_ll), GFP_KERNEL);
	if (tmp) {
		memset(tmp, 0, sizeof(hb_binprm_ll));
		tmp->fid = fid;
		strncpy(tmp->uid, uid, UID_STR_SIZE-1);
		tmp->act_allow = act_allow;
		strcpy(tmp->digest, digest);
		tmp->pathname = kmalloc(len+1, GFP_KERNEL);
		if (tmp->pathname == NULL) {
			err = -EOPNOTSUPP;
			goto out;
		}

		switch (fid) {
			case HB_BPRM_SET_CREDS:
				strcpy(tmp->pathname, pathname);
			       	break;
			default:
				break;
		}
		if ((err == 0) && (interact == 0))
		       	list_add_tail(&(tmp->list), &(hb_binprm_list_head.list));

		if ((err == 0) && (interact == 1))
			add_notify_record(fid, tmp);
	}
	else
		err = -EOPNOTSUPP;

out:
	if(err != 0)
		kfree(tmp);

	return err;
}

int lookup_binprm_digest(struct file *file, char *digest)
{
	int err = 0;
	int size = 0;
       	int rc = 0;
	int i = 0;
       	int offset = 0;
	u8 hash[SHA1_DIGEST_SIZE];
       	struct crypto_shash *tfm = NULL;
       	struct shash_desc *desc = NULL;
       	char *rbuf = NULL;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,4,0)
       	struct inode *inode = file_inode(file);
#else
       	struct dentry *dentry = file->f_path.dentry;
       	struct inode *inode = d_backing_inode(dentry);
#endif

	tfm = crypto_alloc_shash("sha1", 0, 0);

	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		//printk(KERN_WARNING "failed to setup sha1 hasher\n");
		goto out;
	}
       	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);

	if (!desc) {
		//printk(KERN_WARNING "Failed to kmalloc desc\n");
		goto out1;
	}

       	desc->tfm = tfm;
       	desc->flags = crypto_shash_get_flags(tfm);
       	err = crypto_shash_init(desc);

	if (err) {
		//printk(KERN_WARNING "failed to crypto_shash_init\n");
		goto out2;
	}

	rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!rbuf) {
		//printk(KERN_WARNING "failed to kzalloc\n");
		err = -ENOMEM;
		goto out2;
	}

	size = i_size_read(inode);

	while (offset < size) {
		int rbuf_len;
		rbuf_len = kernel_read(file, offset, rbuf, PAGE_SIZE);
		//printk(KERN_DEBUG "rbuf_len is %d, offset is %d\n", rbuf_len, offset);

		if (rbuf_len < 0) {
			rc = rbuf_len;
			break;
		}

		if (rbuf_len == 0)
			break;

		offset += rbuf_len;

		rc = crypto_shash_update(desc, rbuf, rbuf_len);

		if (rc)
			break;
	}
	kfree(rbuf);

	if (!rc)
		rc = crypto_shash_final(desc, hash);

	for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
		snprintf(digest + (i * 2), 4, "%02x", hash[i]);
	}
	//printk(KERN_DEBUG "digest is %s\n", digest);

out2:
       	kfree(desc);
out1:
       	crypto_free_shash(tfm);
out:
	return err;
}

int read_binprm_record(struct seq_file *m, void *v)
{
	hb_binprm_ll *tmp = NULL;
	struct list_head *pos = NULL;
	unsigned long total = 0;

	seq_printf(m, "NO\tFUNC\tUID\tACTION\tDIGEST\t\t\t\t\t\tPATH\n");
	list_for_each(pos, &hb_binprm_list_head.list) {
		tmp = list_entry(pos, hb_binprm_ll, list);
		seq_printf(m, "%lu\t%u\t%s\t%c\t%s\t%s\n", total++, tmp->fid, tmp->uid, tmp->act_allow, tmp->digest, tmp->pathname);
	}

	return 0;
}

void free_cred_record(hb_binprm_ll *data)
{
	kfree(data->pathname);
}

ssize_t write_binprm_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
	char *acts_buff = NULL;
	char *delim = "\n";
	char *token, *cur;
	hb_binprm_ll *tmp = NULL;
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
	list_for_each_safe(pos, q, &hb_binprm_list_head.list) {
		tmp = list_entry(pos, hb_binprm_ll, list);
		list_del(pos);
		free_cred_record(tmp);
		kfree(tmp);
		tmp = NULL;
	}

       	cur = acts_buff;
	/* add acts_buff */
	while((token = strsep(&cur, delim)) && (strlen(token)>1)) {
		char uid[UID_STR_SIZE];
		unsigned int fid = 0;
		char *digest = NULL;
		char act_allow = 'R';
		char *pathname = NULL;

		digest = (char *)kmalloc(SHA1_HONEYBEST_DIGEST_SIZE, GFP_KERNEL);
		if (digest == NULL) {
			continue;
		}

		pathname = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
		if (pathname == NULL) {
			kfree(digest);
			continue;
		}

		sscanf(token, "%u %s %c %s %s", &fid, uid, &act_allow, digest, pathname);
		if (add_binprm_record(HB_BPRM_SET_CREDS, uid, act_allow, pathname, digest, 0) != 0) {
			printk(KERN_WARNING "Failure to add binprm record %s, %s, %s\n", uid, pathname, digest);
		}

		kfree(pathname);
		kfree(digest);
	} //while
out1:
	kfree(acts_buff);
out:
	return count;
}


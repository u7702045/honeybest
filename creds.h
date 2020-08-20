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

#define SHA1_HONEYBEST_DIGEST_SIZE (SHA1_DIGEST_SIZE * 2)+1	// leave '\0' at the end
#define HB_BINPRM_DATA 
typedef struct hb_binprm_ll_t {
	uid_t uid;
	unsigned int fid;	/**< security hook function binprm by program */
	char act_allow;		/**< 'A'llow / 'R'eject action */
	char digest[SHA1_HONEYBEST_DIGEST_SIZE];	/**< exec program xattr hash */
	char *pathname;		/**< open file path */
	struct list_head list;
} hb_binprm_ll;

hb_binprm_ll *search_binprm_record(unsigned int fid, uid_t uid, char *pathname, char *digest);
int add_binprm_record(unsigned int fid, uid_t uid, char act_allow, char *pathname, char *digest, int interact);
int lookup_binprm_digest(struct file *file, char *digest);

int read_binprm_record(struct seq_file *m, void *v);
ssize_t write_binprm_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);

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
typedef struct hb_sb_ll_t {
	uid_t uid;
	unsigned int fid;	/**< security hook function run super block mount by program */
	char act_allow;		/**< 'A'llow / 'R'eject action */
	char *s_id;
	char *name;
	char *dev_name;
	char *type;
	int flags;
	struct list_head list;
} hb_sb_ll;

hb_sb_ll *search_sb_record(unsigned int fid, uid_t uid, char *s_id, char *name, \
		char *dev_name, char *type, int flags);
int add_sb_record(unsigned int fid, uid_t uid, char act_allow, char *s_id, char *name, \
		char *dev_name, char *type, int flags, int interact);

int read_sb_record(struct seq_file *m, void *v);
ssize_t write_sb_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);


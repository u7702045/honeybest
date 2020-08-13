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

typedef struct hb_inode_ll_t {
	unsigned int fid;	// security hook function run inode by program
	uid_t uid;
	char *binprm;
	char *name;
	struct list_head list;
} hb_inode_ll;

hb_inode_ll *search_inode_record(unsigned int fid, uid_t uid, char *name, char *binprm);
int add_inode_record(unsigned int fid, uid_t uid, char *name, char *binprm, int interact);

int read_inode_record(struct seq_file *m, void *v);
ssize_t write_inode_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);

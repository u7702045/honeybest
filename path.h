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

typedef struct hb_path_ll_t {
	unsigned int fid;	// security hook function run path by program
	uid_t uid;
	umode_t mode;
	char *source_pathname;
	char *target_pathname;
	uid_t suid;		// source file uid
	gid_t sgid;		// source file gid
	unsigned int dev;
	struct list_head list;
} hb_path_ll;

hb_path_ll *search_path_record(unsigned int fid, uid_t uid, umode_t mode, char *source_pathname, char *target_pathname, uid_t suid, uid_t sgid, unsigned int dev);
int add_path_record(unsigned int fid, uid_t uid, umode_t mode, char *source_pathname, char *target_pathname, uid_t suid, uid_t sgid, unsigned int dev, int interact);

int read_path_record(struct seq_file *m, void *v);
ssize_t write_path_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);

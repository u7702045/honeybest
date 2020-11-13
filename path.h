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
#include "honeybest.h"

typedef struct hb_path_ll_t {
	unsigned int fid;	/**< security hook function run path by program */
	char uid[UID_STR_SIZE];
	char act_allow;		/**< 'A'llow / 'R'eject action */
	umode_t mode;
	char *s_path;
	char *t_path;
	char suid[UID_STR_SIZE];/**< source file uid */
	char sgid[UID_STR_SIZE];/**< source file gid */
	char *binprm;
	unsigned int dev;
	struct list_head list;
} hb_path_ll;

hb_path_ll *search_path_record(unsigned int fid, uid_t uid, umode_t mode, char *s_path, char *t_path, uid_t suid, uid_t sgid, unsigned int dev, char *binprm);
int add_path_record(unsigned int fid, char *uid, char act_allow, umode_t mode, char *s_path, char *t_path, char *suid, char *sgid, unsigned int dev, char *binprm);

int read_path_record(struct seq_file *m, void *v);
ssize_t write_path_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);
void free_path_record(hb_path_ll *data);

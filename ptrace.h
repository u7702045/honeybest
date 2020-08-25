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

typedef struct hb_ptrace_ll_t {
	unsigned int fid;				/**< security hook function ptrace by program */
	char uid[UID_STR_SIZE];
	char *parent;					/**< parent task name */
	char *child;					/**< descendant child task name */
	char act_allow;					/**< 'A'llow / 'R'eject action */
	unsigned int mode;				/**< attach / noaudit */
	struct list_head list;
} hb_ptrace_ll;

hb_ptrace_ll *search_ptrace_record(unsigned int fid, uid_t uid, char *parent, char *child, unsigned int mode);
int add_ptrace_record(unsigned int fid, char *uid, char act_allow, char *parent, char *child, unsigned int mode, int interact);
int lookup_ptrace_digest(struct file *file, char *digest);

int read_ptrace_record(struct seq_file *m, void *v);
ssize_t write_ptrace_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);


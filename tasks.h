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

typedef struct hb_task_ll_t {
	unsigned int fid;	/**< security hook function run task by program */
	char uid[UID_STR_SIZE];
	char act_allow;		/**< 'A'llow / 'R'eject action */
	int sig;
	int si_signo;
	int si_errno;
	u32 secid;
	char *binprm;
	struct list_head list;
} hb_task_ll;

hb_task_ll *search_task_record(unsigned int fid, uid_t uid, struct siginfo *info, int sig, u32 secid, char *binprm);
int add_task_record(unsigned int fid, char *uid, char act_allow, int sig, int si_signo, \
		int si_errno, u32 secid, char *binprm, int interact);

int read_task_record(struct seq_file *m, void *v);
ssize_t write_task_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);

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

typedef struct hb_ipc_ll_t {
	unsigned int fid;	/**< security hook function open ipc by program */
	char uid[UID_STR_SIZE];
	char act_allow;		/**< 'A'llow / 'R'eject action */
	char *binprm;		/**< binary open ipcname */
	uid_t ipc_uid;
	uid_t ipc_gid;
	uid_t ipc_cuid;
	uid_t ipc_cgid;
	short flag;		/**< request permission */
	struct list_head list;
} hb_ipc_ll;

hb_ipc_ll *search_ipc_record(unsigned int fid, uid_t uid, char *binprm, uid_t ipc_uid, \
		uid_t ipc_gid, uid_t ipc_cuid, uid_t ipc_cgid, short flag);
int add_ipc_record(unsigned int fid, char *uid, char act_allow, char *binprm, \
		uid_t ipc_uid, uid_t ipc_gid, uid_t ipc_cuid, uid_t ipc_cgid, short flag, int interact);

int read_ipc_record(struct seq_file *m, void *v);
ssize_t write_ipc_record(struct file *file, const char __user *buffer, size_t count, loff_t *pos);
void free_ipc_record(hb_ipc_ll *data);


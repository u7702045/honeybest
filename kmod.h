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

typedef struct hb_kmod_ll_t {
	unsigned int fid;	/**< security hook function run kernel modules by program */
	char uid[UID_STR_SIZE];
	char act_allow;		/**< 'A'llow / 'R'eject action */
	char *name;
	char *filename;		/**< driver file name */
        char digest[SHA1_HONEYBEST_DIGEST_SIZE];        /**< *.ko driver hash */
	struct list_head list;
} hb_kmod_ll;

hb_kmod_ll *search_kmod_record(unsigned int fid, uid_t uid, char *name, char *filename, char *digest);
int add_kmod_record(unsigned int fid, char *uid, char act_allow, char *name, char *filename, char *digest);

int read_kmod_record(struct seq_file *m, void *v);
ssize_t write_kmod_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);
void free_kmod_record(hb_kmod_ll *data);



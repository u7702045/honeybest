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
typedef struct hb_notify_ll_t {
	unsigned int fid;		// security hook function binprm by program
	char proc[HB_PROC_FSIZE];	//name of /proc/honeybest/*
	void *data;			// pointer to different type of struct
	struct list_head list;
} hb_notify_ll;

int add_notify_record(unsigned int fid, void *data);
int read_notify_record(struct seq_file *m, void *v);


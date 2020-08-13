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

typedef struct hb_socket_ll_t {
	unsigned int fid;	// security hook function open socket by program
	uid_t uid;
	int family;
	int type;
	int protocol;
	int port;
	int level;
	int optname;
	char *binprm;
	struct socket sock;
	struct sockaddr address;
	int addrlen;
	struct list_head list;
} hb_socket_ll;

hb_socket_ll *search_socket_record(unsigned int fid, uid_t uid, int family, int type, int protocol, int port,
		int level, int optname, char *binprm);

int add_socket_record(unsigned int fid, uid_t uid, int family, int type, int protocol,
	       	int port, int level, int optname, char *binprm, int interact);

int read_socket_record(struct seq_file *m, void *v);
ssize_t write_socket_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);
unsigned short lookup_source_port(struct socket *sock, struct sockaddr *address, int addrlen);

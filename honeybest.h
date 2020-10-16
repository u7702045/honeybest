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

#ifndef HONEYBEST_INCLUDED
#define HONEYBEST_INCLUDED

/** prevent compiler shout due to const */
#define cred_cxt(X) (X)->security
#define __task_cred(task)	\
	rcu_dereference((task)->real_cred)

#define SHA1_HONEYBEST_DIGEST_SIZE (SHA1_DIGEST_SIZE * 2)+1	// leave '\0' at the end

#define HOOK_FUNC_STR_SIZE		5	/**< 4 digits with null terminal */
#define UID_STR_SIZE			6	/**< unsigned int in string with null terminal */

#define TOTAL_ACT_SIZE			204800

#define HB_INITIALIZE			1000

#define HB_BPRM_SET_CREDS		2000
#define HB_CRED_ALLOC_BLANK		2001
#define HB_TASK_CREATE			2002

#define HB_FILE_OPEN			5000
#define HB_FILE_IOCTL			5001
#define HB_FILE_RECEIVE			5002
#define HB_FILE_MMAP			5003

#define HB_SOCKET_CREATE		4001
#define HB_SOCKET_BIND			4002
#define HB_SOCKET_CONNECT		4003
#define HB_SOCKET_LISTEN		4004
#define HB_SOCKET_ACCEPT		4005
#define HB_SOCKET_SETSOCKOPT		4006

#define HB_TASK_SIGNAL			9000

#define HB_INODE_CREATE			3010
#define HB_INODE_INIT_SEC		3011
#define HB_INODE_LINK			3012
#define HB_INODE_UNLINK			3013
#define HB_INODE_SYMLINK		3014
#define HB_INODE_MKDIR			3015
#define HB_INODE_SETXATTR		3016
#define HB_INODE_GETXATTR		3017
#define HB_INODE_REMOVEXATTR		3018
#define HB_INODE_LISTXATTR		3019

#define HB_PTRACE_ACCESS_CHECK		6000

#define HB_PATH_LINK			19
#define HB_PATH_RENAME			20
#define HB_PATH_CHMOD			21
#define HB_PATH_CHOWN			22
#define HB_PATH_SYMLINK			23
#define HB_PATH_TRUNCATE		24
#define HB_PATH_MKNOD			25
#define HB_PATH_RMDIR			26
#define HB_PATH_MKDIR			27
#define HB_PATH_UNLINK			28

#define HB_SB_COPY_DATA			6030
#define HB_SB_REMOUNT			6031
#define HB_SB_KERN_MOUNT		6032
#define HB_SB_STATFS			6033
#define HB_SB_MOUNT			6034
#define HB_SB_UMOUNT			6035

#define HB_KMOD_REQ			7000
#define HB_KMOD_LOAD_FROM_FILE		7001

#define HB_IPC_PERM			8000

#define HB_DENTRY_INIT_SEC		160

#define HB_NOTIFY_ADD			500


#define HB_PROC_FSIZE			10
#define HB_CREDS_PROC			"binprm"
#define HB_FILE_PROC			"files"
#define HB_TASK_PROC			"tasks"
#define HB_INODE_PROC			"inode"
#define HB_PATH_PROC			"path"
#define HB_SOCKET_PROC			"socket"
#define HB_SB_PROC			"sb"
#define HB_KMOD_PROC			"kmod"
#define HB_PTRACE_PROC			"ptrace"
#define HB_IPC_PROC			"ipc"

#endif

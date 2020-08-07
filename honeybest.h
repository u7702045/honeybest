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
#define TOTAL_ACT_SIZE			10240

#define HB_INITIALIZE			1000

#define HB_BPRM_SET_CREDS		2000
#define HB_CRED_ALLOC_BLANK		2001
#define HB_TASK_CREATE			2002

#define HB_FILE_OPEN			2

#define HB_SOCKET_CREATE		3
#define HB_SOCKET_BIND			4
#define HB_SOCKET_CONNECT		5
#define HB_SOCKET_LISTEN		6
#define HB_SOCKET_ACCEPT		7
#define HB_SOCKET_SETSOCKOPT		8

#define HB_TASK_SIGNAL			9

#define HB_INODE_CREATE			10
#define HB_INODE_INIT_SEC		11
#define HB_INODE_LINK			12
#define HB_INODE_UNLINK			13
#define HB_INODE_SYMLINK		14
#define HB_INODE_MKDIR			15
#define HB_INODE_SETXATTR		16
#define HB_INODE_GETXATTR		17
#define HB_INODE_REMOVEXATTR		18

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

#define HB_SB_COPY_DATA			30
#define HB_SB_REMOUNT			31
#define HB_SB_KERN_MOUNT		32
#define HB_SB_STATFS			33
#define HB_SB_MOUNT			34
#define HB_SB_UMOUNT			35

#define HB_KMOD_REQ			40

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

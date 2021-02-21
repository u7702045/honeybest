/*
 * Mock of Security Hash Locking Module
 *
 * Copyright 2020 Moxa Inc.
 *
 * Author: Chuck Lee <chucksc.lee@moxa.com>
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

#include <stdlib.h>
#include "linux/seq_file.h"
#include "linux/list.h"
#include "notify.h"

hb_notify_ll hb_notify_list_head = {
    .fid = 0,
    .proc = {0},
    .data = NULL,
    .dirty = 0,
    .list = {
        .next = NULL,
        .prev = NULL,
    }
};

int __wrap_add_notify_record(unsigned int fid, void *data)
{
    hb_notify_ll *tmp = NULL;

    if (!data) {
        return -EOPNOTSUPP;
    }

    tmp = (hb_notify_ll *)malloc(sizeof(hb_notify_ll));
    if (!tmp) {
        return -EOPNOTSUPP;
    }

    memset(tmp, 0, sizeof(hb_notify_ll));
    tmp->fid = fid;
    tmp->data = data;
    switch (fid) {
        case HB_BPRM_SET_CREDS:
        case HB_FILE_MMAP:
            strncpy(tmp->proc, HB_CREDS_PROC, strlen(HB_CREDS_PROC));
            break;
        case HB_PTRACE_ACCESS_CHECK:
            strncpy(tmp->proc, HB_PTRACE_PROC, strlen(HB_PTRACE_PROC));
            break;
        case HB_FILE_RECEIVE:
        case HB_FILE_IOCTL:
        case HB_FILE_OPEN:
            strncpy(tmp->proc, HB_FILE_PROC, strlen(HB_FILE_PROC));
            break;
        case HB_TASK_SIGNAL:
            strncpy(tmp->proc, HB_TASK_PROC, strlen(HB_TASK_PROC));
            break;
        case HB_SOCKET_CREATE:
        case HB_SOCKET_CONNECT:
        case HB_SOCKET_BIND:
        case HB_SOCKET_SETSOCKOPT:
            strncpy(tmp->proc, HB_SOCKET_PROC, strlen(HB_SOCKET_PROC));
            break;
        case HB_PATH_RENAME:
        case HB_PATH_SYMLINK:
        case HB_PATH_RMDIR:
        case HB_PATH_TRUNCATE:
        case HB_PATH_LINK:
        case HB_PATH_UNLINK:
        case HB_PATH_CHOWN:
        case HB_PATH_MKNOD:
        case HB_PATH_MKDIR:
        case HB_PATH_CHMOD:
            strncpy(tmp->proc, HB_PATH_PROC, strlen(HB_PATH_PROC));
            break;
        case HB_INODE_REMOVEXATTR:
        case HB_INODE_GETXATTR:
        case HB_INODE_SETXATTR:
            strncpy(tmp->proc, HB_INODE_PROC, strlen(HB_INODE_PROC));
            break;
        case HB_SB_COPY_DATA:
        case HB_SB_STATFS:
        case HB_SB_REMOUNT:
        case HB_SB_UMOUNT:
        case HB_SB_KERN_MOUNT:
        case HB_SB_MOUNT:
            strncpy(tmp->proc, HB_SB_PROC, strlen(HB_SB_PROC));
            break;
        case HB_KMOD_LOAD_FROM_FILE:
        case HB_KMOD_REQ:
            strncpy(tmp->proc, HB_KMOD_PROC, strlen(HB_KMOD_PROC));
            break;
        case HB_IPC_PERM:
            strncpy(tmp->proc, HB_IPC_PROC, strlen(HB_IPC_PROC));
            break;
        default:
            break;
    }

    list_add(&(tmp->list), &(hb_notify_list_head.list));
    return 0;
}

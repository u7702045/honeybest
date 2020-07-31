#define TOTAL_ACT_SIZE			10240

#define HL_BPRM_SET_CREDS		1

#define HL_FILE_OPEN			2

#define HL_SOCKET_CREATE		3
#define HL_SOCKET_BIND			4
#define HL_SOCKET_CONNECT		5
#define HL_SOCKET_LISTEN		6
#define HL_SOCKET_ACCEPT		7
#define HL_SOCKET_SETSOCKOPT		8

#define HL_TASK_SIGNAL			9

#define HL_INODE_CREATE			10
#define HL_INODE_INIT_SEC		11
#define HL_INODE_LINK			12
#define HL_INODE_UNLINK			13
#define HL_INODE_SYMLINK		14
#define HL_INODE_MKDIR			15
#define HL_INODE_SETXATTR		16
#define HL_INODE_GETXATTR		17
#define HL_INODE_REMOVEXATTR		18

#define HL_PATH_LINK			19
#define HL_PATH_RENAME			20
#define HL_PATH_CHMOD			21
#define HL_PATH_CHOWN			22
#define HL_PATH_SYMLINK			23
#define HL_PATH_TRUNCATE		24
#define HL_PATH_MKNOD			25
#define HL_PATH_RMDIR			26
#define HL_PATH_MKDIR			27
#define HL_PATH_UNLINK			28

#define HL_SB_COPY_DATA			30
#define HL_SB_REMOUNT			31
#define HL_SB_KERN_MOUNT		32
#define HL_SB_STATFS			33
#define HL_SB_MOUNT			34
#define HL_SB_UMOUNT			35

#define HL_KMOD_REQ			40

#define HL_DENTRY_INIT_SEC		160

#define HL_NOTIFY_ADD			500


#define HL_PROC_FSIZE			10
#define HL_CREDS_PROC			"binprm"
#define HL_FILE_PROC			"files"
#define HL_TASK_PROC			"tasks"
#define HL_INODE_PROC			"inode"
#define HL_PATH_PROC			"path"
#define HL_SOCKET_PROC			"socket"
#define HL_SB_PROC			"sb"
#define HL_KMOD_PROC			"kmod"

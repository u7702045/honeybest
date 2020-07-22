
typedef struct hb_path_ll_t {
	unsigned int fid;	// security hook function run path by program
	uid_t uid;
	umode_t mode;
	char *source_pathname;
	char *target_pathname;
	uid_t suid;		// source file uid
	gid_t sgid;		// source file gid
	unsigned int dev;
	struct list_head list;
} hb_path_ll;

hb_path_ll *search_path_record(unsigned int fid, uid_t uid, umode_t mode, char *source_pathname, char *target_pathname, uid_t suid, uid_t sgid, unsigned int dev);
int add_path_record(unsigned int fid, uid_t uid, umode_t mode, char *source_pathname, char *target_pathname, uid_t suid, uid_t sgid, unsigned int dev);

int read_path_record(struct seq_file *m, void *v);
ssize_t write_path_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);

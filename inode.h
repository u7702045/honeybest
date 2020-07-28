
typedef struct hb_inode_ll_t {
	unsigned int fid;	// security hook function run inode by program
	uid_t uid;
	char *dname;
	char *name;
	umode_t mode;
	struct list_head list;
} hb_inode_ll;

hb_inode_ll *search_inode_record(unsigned int fid, uid_t uid, char *name, char *dname, umode_t mode);
int add_inode_record(unsigned int fid, uid_t uid, char *name, char *dname, umode_t mode, int interact);

int read_inode_record(struct seq_file *m, void *v);
ssize_t write_inode_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);

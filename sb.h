typedef struct hb_sb_ll_t {
	unsigned int fid;	// security hook function run super block mount by program
	uid_t uid;
	char *s_id;
	char *name;
	char *dev_name;
	char *type;
	int flags;
	struct list_head list;
} hb_sb_ll;

hb_sb_ll *search_sb_record(unsigned int fid, uid_t uid, char *s_id, char *name, \
		char *dev_name, char *type, int flags);
int add_sb_record(unsigned int fid, uid_t uid, char *s_id, char *name, \
		char *dev_name, char *type, int flags, int interact);

int read_sb_record(struct seq_file *m, void *v);
ssize_t write_sb_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);



typedef struct hb_notify_ll_t {
	unsigned int fid;	// security hook function run notify by program
	uid_t uid;
	int sig;
	struct list_head list;
} hb_notify_ll;

int add_notify_record(unsigned int fid, uid_t uid, int sig);
int read_notify_record(struct seq_file *m, void *v);
ssize_t write_notify_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);


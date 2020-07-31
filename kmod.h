typedef struct hb_kmod_ll_t {
	unsigned int fid;	// security hook function run kernel modules by program
	uid_t uid;
	char *name;
	struct list_head list;
} hb_kmod_ll;

hb_kmod_ll *search_kmod_record(unsigned int fid, uid_t uid, char *name);
int add_kmod_record(unsigned int fid, uid_t uid, char *name, int interact);

int read_kmod_record(struct seq_file *m, void *v);
ssize_t write_kmod_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);



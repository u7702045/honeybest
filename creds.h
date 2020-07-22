
#define SHA1_HASHLOCK_DIGEST_SIZE (SHA1_DIGEST_SIZE * 2)+1	// leave '\0' at the end
typedef struct hb_binprm_ll_t {
	uid_t uid;
	unsigned int fid;	// security hook function binprm by program
	char digest[SHA1_HASHLOCK_DIGEST_SIZE];	// exec program xattr hash
	char *pathname;	// open file path
	struct list_head list;
} hb_binprm_ll;

hb_binprm_ll *search_binprm_record(unsigned int fid, uid_t uid, char *pathname, char *digest);
int add_binprm_record(unsigned int fid, uid_t uid, char *pathname, char *digest);
int lookup_binprm_digest(struct file *file, char *digest);

int read_binprm_record(struct seq_file *m, void *v);
ssize_t write_binprm_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);

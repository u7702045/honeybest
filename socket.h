
typedef struct hb_socket_ll_t {
	unsigned int fid;	// security hook function open socket by program
	uid_t uid;
	int family;
	int type;
	int protocol;
	int kern;
	int port;
	int backlog;
	int level;
	int optname;
	struct socket sock;
	struct sockaddr address;
	int addrlen;
	struct list_head list;
} hb_socket_ll;

hb_socket_ll *search_socket_record(unsigned int fid, uid_t uid, int family, int type, int protocol, int kern,
	       	int backlog, int level, int optname, struct socket *sock, struct sockaddr *address, int addrlen);

int add_socket_record(unsigned int fid, uid_t uid, int family, int type, int protocol, int kern,
	       	int port, int backlog, int level, int optname, struct socket *sock, struct sockaddr *address, int addrlen);

int read_socket_record(struct seq_file *m, void *v);
ssize_t write_socket_record(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);

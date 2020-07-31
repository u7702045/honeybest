#include "honeybest.h"
typedef struct hb_notify_ll_t {
	unsigned int fid;		// security hook function binprm by program
	char proc[HB_PROC_FSIZE];	//name of /proc/honeybest/*
	void *data;			// pointer to different type of struct
	struct list_head list;
} hb_notify_ll;

int add_notify_record(unsigned int fid, void *data);
int read_notify_record(struct seq_file *m, void *v);


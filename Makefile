# If you wnat disable all debug massage, nullify the following command

# DEBUG = y

 

ifeq ($(DEBUG),y)
EXTRA_CFLAGS += -O -g -DHONEYBEST_DEBUG
else
EXTRA_CFLAGS +=
endif

obj-$(CONFIG_SECURITY_HONEYBEST) += honeybest.o notify.o creds.o files.o socket.o tasks.o \
	inode.o path.o sb.o kmod.o ptrace.o ipc.o regex.o audit.o

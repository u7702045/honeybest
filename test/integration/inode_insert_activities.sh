#!/bin/bash
ENABLE_PROC=/proc/sys/kernel/honeybest/enabled
ENABLE_INODE=/proc/sys/kernel/honeybest/inode
LOCK_PROC=/proc/sys/kernel/honeybest/locking
INODE_PROC=/proc/honeybest/inode
HB_TEMPLATE=./template/
HB_INODE=${HB_TEMPLATE}/inode
TMP_FILE=/dev/shm/xxxx
activate(){
	if [ $1 == 'start' ]; then
		echo 1 > ${ENABLE_INODE}
		echo 1 > ${ENABLE_PROC}
	else
		echo 0 > ${ENABLE_INODE}
		echo 0 > ${ENABLE_PROC}
       	fi
}

locking(){
	if [ $1 == 'start' ]; then
		echo 1 > ${LOCK_PROC}
	else
		echo 0 > ${LOCK_PROC}
       	fi
}

status() {
	cat ${ENABLE_PROC}
}

clean_inode_proc() {
	echo "" > ${INODE_PROC}
	cat ${INODE_PROC}
}

insert_inode_proc() {
	cat ${HB_INODE} > ${INODE_PROC}
	cat ${INODE_PROC} > ${TMP_FILE}
}

test_clean_inode() {
	activate "stop"

	tmp=$(clean_inode_proc)
	actual=`echo $tmp|wc -l`
	expected=1
	assertEquals "test clean inode" "$expected" "$actual"
}

test_insert_inode() {
	activate "stop"

	insert_inode_proc
	actual=`cat ${TMP_FILE}|wc -l`
	expected=2
	assertEquals "test insert file" "$expected" "$actual"
}

test_inode_context() {
	activate "stop"

	tmp=$(clean_inode_proc)
	insert_inode_proc
	actual=`cat ${TMP_FILE}|grep security.xxx|awk '{print $6}'|cut -d '/' -f 2`
	expected='a.txt'

	assertEquals "test file context" "$expected" "$actual"
}

test_inode_enable() {
	activate "stop"
	activate "start"

	tmp=$(clean_inode_proc)
	touch /tmp/a.txt
	setfattr -n 'security.xxx' -v 1234 /tmp/a.txt
	sleep 2
	cat ${INODE_PROC}|grep security.xxx > /dev/null
	actual=$?
	expected=0

	assertEquals "test inode enable" "$expected" "$actual"

	activate "stop"
	tmp=$(clean_inode_proc)
}

test_inode_lock() {
	activate "stop"

	tmp=$(clean_inode_proc)
	locking "start"
	activate "start"

	setfattr -n 'security.xxx' -v 1234 /tmp/a.txt
	actual=$?
	expected=0

	assertNotEquals "test inode lock" "$expected" "$actual"

	activate "stop"
	locking "stop"
	tmp=$(clean_inode_proc)
}

source "/usr/bin/shunit2"

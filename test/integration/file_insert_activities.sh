#!/bin/bash
ENABLE_PROC=/proc/sys/kernel/honeybest/enabled
ENABLE_FILE=/proc/sys/kernel/honeybest/files
LOCK_PROC=/proc/sys/kernel/honeybest/locking
FILE_PROC=/proc/honeybest/files
HB_TEMPLATE=./template/
HB_FILE=${HB_TEMPLATE}/files
TMP_FILE=/dev/shm/xxxx
activate(){
	if [ $1 == 'start' ]; then
		echo 1 > ${ENABLE_FILE}
		echo 1 > ${ENABLE_PROC}
	else
		echo 0 > ${ENABLE_FILE}
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

clean_file_proc() {
	echo "" > ${FILE_PROC}
	cat ${FILE_PROC}
}

insert_file_proc() {
	cat ${HB_FILE} > ${FILE_PROC}
	cat ${FILE_PROC} > ${TMP_FILE}
}

test_clean_file() {
	activate "stop"

	tmp=$(clean_file_proc)
	actual=`echo $tmp|wc -l`
	expected=1
	assertEquals "test clean file" "$expected" "$actual"
}

test_insert_file() {
	activate "stop"

	insert_file_proc
	actual=`cat ${TMP_FILE}|wc -l`
	expected=7
	assertEquals "test insert file" "$expected" "$actual"
}

test_file_context() {
	activate "stop"

	tmp=$(clean_file_proc)
	insert_file_proc
	actual=`cat ${TMP_FILE}|grep cgroup|awk '{print $5}'|cut -d '/' -f 4`
	expected='cgroup'

	assertEquals "test file context" "$expected" "$actual"
}

test_file_enable() {
	activate "stop"
	activate "start"

	tmp=$(clean_file_proc)
	cat /proc/cpuinfo > /dev/null
	sleep 2
	cat ${FILE_PROC}|grep cpuinfo > /dev/null
	actual=$?
	expected=0

	assertEquals "test file enable" "$expected" "$actual"

	activate "stop"
	tmp=$(clean_file_proc)
}

test_file_lock() {
	activate "stop"

	tmp=$(clean_file_proc)
	locking "start"
	activate "start"

	cat /etc/issue 2> /dev/null
	actual=$?
	expected=1

	assertEquals "test file lock" "$expected" "$actual"

	activate "stop"
	locking "stop"
	tmp=$(clean_file_proc)
}


source "/usr/bin/shunit2"

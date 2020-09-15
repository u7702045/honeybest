#!/bin/bash
ENABLE_PROC=/proc/sys/kernel/honeybest/enabled
LOCK_PROC=/proc/sys/kernel/honeybest/locking
PATH_PROC=/proc/honeybest/path
HB_TEMPLATE=./template/
HB_PATH=${HB_TEMPLATE}/path
TMP_FILE=/dev/shm/xxxx
activate(){
	if [ $1 == 'start' ]; then
		echo 1 > ${ENABLE_PROC}
	else
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

clean_path_proc() {
	echo "" > ${PATH_PROC}
	cat ${PATH_PROC}
}

insert_path_proc() {
	cat ${HB_PATH} > ${PATH_PROC}
	cat ${PATH_PROC} > ${TMP_FILE}
}

test_clean_path() {
	activate "stop"

	tmp=$(clean_path_proc)
	actual=`echo $tmp|wc -l`
	expected=1
	assertEquals "test clean path" "$expected" "$actual"
}

test_insert_path() {
	activate "stop"

	insert_path_proc
	actual=`cat ${TMP_FILE}|wc -l`
	expected=2
	assertEquals "test insert path" "$expected" "$actual"
}

test_path_context() {
	activate "stop"

	tmp=$(clean_path_proc)
	insert_path_proc
	cat ${TMP_FILE}|grep aaa > /dev/null
	actual=$?
	expected=0

	assertEquals "test path context" "$expected" "$actual"
}

test_path_enable() {
	rm -rf /tmp/aaa
	activate "stop"
	activate "start"

	tmp=$(clean_path_proc)
	mkdir /tmp/aaa
	sleep 2
	cat ${PATH_PROC}|grep aaa > /dev/null
	actual=$?
	expected=0

	assertEquals "test path enable" "$expected" "$actual"

	activate "stop"
	tmp=$(clean_path_proc)
	rm -rf /tmp/aaa
}

test_path_lock() {
	rm -rf /tmp/aaa
	activate "stop"

	tmp=$(clean_path_proc)
	locking "start"
	activate "start"

	mkdir /tmp/aaa
	actual=$?
	expected=0

	assertNotEquals "test path lock" "$expected" "$actual"

	activate "stop"
	locking "stop"
	tmp=$(clean_path_proc)
	rm -rf /tmp/aaa
}

source "/usr/bin/shunit2"

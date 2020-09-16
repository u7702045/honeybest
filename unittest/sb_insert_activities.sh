#!/bin/bash
ENABLE_PROC=/proc/sys/kernel/honeybest/enabled
LOCK_PROC=/proc/sys/kernel/honeybest/locking
SB_PROC=/proc/honeybest/sb
HB_TEMPLATE=./template/
HB_SB=${HB_TEMPLATE}/sb
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

clean_sb_proc() {
	echo "" > ${SB_PROC}
	cat ${SB_PROC}
}

insert_sb_proc() {
	cat ${HB_SB} > ${SB_PROC}
	cat ${SB_PROC} > ${TMP_FILE}
}

test_clean_sb() {
	activate "stop"

	tmp=$(clean_sb_proc)
	actual=`echo $tmp|wc -l`
	expected=1
	assertEquals "test clean sb" "$expected" "$actual"
}

test_insert_sb() {
	activate "stop"

	insert_sb_proc
	actual=`cat ${TMP_FILE}|wc -l`
	expected=3
	assertEquals "test insert sb" "$expected" "$actual"
}

test_sb_context() {
	activate "stop"

	tmp=$(clean_sb_proc)
	insert_sb_proc
	cat ${TMP_FILE}|grep ramfs > /dev/null
	actual=$?
	expected=0

	assertEquals "test sb context" "$expected" "$actual"
}

test_sb_enable() {
	mkdir /tmp/aaa
	activate "stop"
	activate "start"

	tmp=$(clean_sb_proc)
	mount -t ramfs -o loop size=1M /tmp/aaa
	sleep 2
	cat ${SB_PROC}|grep ramfs > /dev/null
	actual=$?
	expected=0

	assertEquals "test sb enable" "$expected" "$actual"

	activate "stop"
	tmp=$(clean_sb_proc)
	umount /tmp/aaa
	rm -rf /tmp/aaa
}

test_sb_lock() {
	activate "stop"
	mkdir /tmp/aaa

	tmp=$(clean_sb_proc)
	locking "start"
	activate "start"

	mount -t ramfs -o loop size=1M /tmp/aaa
	actual=$?
	expected=0
	assertNotEquals "test sb lock" "$expected" "$actual"

	activate "stop"
	locking "stop"

	tmp=$(clean_sb_proc)

	rm -rf /tmp/aaa
}

source "/usr/bin/shunit2"

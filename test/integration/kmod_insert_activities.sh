#!/bin/bash
ENABLE_PROC=/proc/sys/kernel/honeybest/enabled
ENABLE_KMOD=/proc/sys/kernel/honeybest/kmod
LOCK_PROC=/proc/sys/kernel/honeybest/locking
KMOD_PROC=/proc/honeybest/kmod
HB_TEMPLATE=./template/
HB_KMOD=${HB_TEMPLATE}/kmod
TMP_FILE=/dev/shm/xxxx
activate(){
	if [ $1 == 'start' ]; then
		echo 1 > ${ENABLE_KMOD}
		echo 1 > ${ENABLE_PROC}
	else
		echo 0 > ${ENABLE_KMOD}
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

clean_kmod_proc() {
	echo "" > ${KMOD_PROC}
	cat ${KMOD_PROC}
}

insert_kmod_proc() {
	cat ${HB_KMOD} > ${KMOD_PROC}
	cat ${KMOD_PROC} > ${TMP_FILE}
}

test_clean_kmod() {
	activate "stop"

	tmp=$(clean_kmod_proc)
	actual=`echo $tmp|wc -l`
	expected=1
	assertEquals "test clean kmod" "$expected" "$actual"
}

test_insert_kmod() {
	activate "stop"

	insert_kmod_proc
	actual=`cat ${TMP_FILE}|wc -l`
	expected=3
	assertEquals "test insert kmod" "$expected" "$actual"
}

test_kmod_context() {
	activate "stop"

	tmp=$(clean_kmod_proc)
	insert_kmod_proc
	cat ${TMP_FILE}|grep iptable > /dev/null
	actual=$?
	expected=0

	assertEquals "test file context" "$expected" "$actual"
}

test_kmod_enable() {
	tmp=$(clean_kmod_proc)
	rmmod iptable_filter 2> /dev/null
       	rmmod ip_tables 2> /dev/null
	activate "stop"
	activate "start"

	iptables -L > /dev/null 2>&1
	sleep 3
	cat ${KMOD_PROC}|grep table > /dev/null
	actual=$?
	expected=0

	assertEquals "test kmod enable" "$expected" "$actual"

	activate "stop"
	tmp=$(clean_kmod_proc)

}

test_kmod_lock() {
	activate "stop"

	rmmod iptable_filter 2> /dev/null
       	rmmod ip_tables 2> /dev/null
	tmp=$(clean_kmod_proc)
	locking "start"
	activate "start"

	iptables -L > /dev/null 2>&1
	actual=$?
	expected=0

	assertNotEquals "test kmod lock" "$expected" "$actual"

	activate "stop"
	locking "stop"
	tmp=$(clean_kmod_proc)
}

source "/usr/bin/shunit2"

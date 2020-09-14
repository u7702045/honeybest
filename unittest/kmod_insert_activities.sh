#!/bin/bash
ENABLE_PROC=/proc/sys/kernel/honeybest/enabled
LOCK_PROC=/proc/sys/kernel/honeybest/locking
KMOD_PROC=/proc/honeybest/kmod
HB_TEMPLATE=./template/
HB_KMOD=${HB_TEMPLATE}/kmod
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
	expected=2
	assertEquals "test insert kmod" "$expected" "$actual"
}

test_kmod_context() {
	activate "stop"

	tmp=$(clean_kmod_proc)
	insert_kmod_proc
	cat ${TMP_FILE}|grep net-pf-0 > /dev/null
	actual=$?
	expected=0

	assertEquals "test file context" "$expected" "$actual"
}

test_kmod_enable() {
	kversion=`uname -a|awk '{print $3}'|cut -d '-' -f 1`
	if [ ${kversion} == '4.4.0' ]; then
		# 4.4.0 do not support kmod LSM
		actual=0
		expected=0
		assertEquals "test kmod enable" "$expected" "$actual"
	else
		activate "stop"
		activate "start"

		tmp=$(clean_kmod_proc)
		rmmod ip_tables
		modprobe ip_tables
		sleep 2
		cat ${KMOD_PROC}|grep ip_tables > /dev/null
		actual=$?
		expected=0

		assertEquals "test kmod enable" "$expected" "$actual"

		activate "stop"
		tmp=$(clean_kmod_proc)

	fi
}

test_kmod_lock() {
	kversion=`uname -a|awk '{print $3}'|cut -d '-' -f 1`
	if [ ${kversion} == '4.4.0' ]; then
		# 4.4.0 do not support kmod LSM
		actual=0
		expected=0
		assertEquals "test kmod enable" "$expected" "$actual"
	else
		activate "stop"

		tmp=$(clean_kmod_proc)
		locking "start"
		activate "start"

		modprobe ip_tables
		actual=$?
		expected=0

		assertNotEquals "test kmod lock" "$expected" "$actual"

		activate "stop"
		locking "stop"
		tmp=$(clean_kmod_proc)
	fi
}

source "/usr/bin/shunit2"

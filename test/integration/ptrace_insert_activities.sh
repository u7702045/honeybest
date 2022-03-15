#!/bin/bash
EXEC_PWD=$(dirname $(realpath $0))
ENABLE_PROC=/proc/sys/kernel/honeybest/enabled
ENABLE_PTRACE=/proc/sys/kernel/honeybest/ptrace
LOCK_PROC=/proc/sys/kernel/honeybest/locking
PTRACE_PROC=/proc/honeybest/ptrace
HB_TEMPLATE=${EXEC_PWD}/template/
HB_PTRACE=${HB_TEMPLATE}/ptrace
TMP_FILE=/dev/shm/xxxx
activate(){
	if [ $1 == 'start' ]; then
		echo 1 > ${ENABLE_PTRACE}
		echo 1 > ${ENABLE_PROC}
	else
		echo 0 > ${ENABLE_PTRACE}
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

clean_ptrace_proc() {
	echo "" > ${PTRACE_PROC}
	cat ${PTRACE_PROC}
}

insert_ptrace_proc() {
	cat ${HB_PTRACE} > ${PTRACE_PROC}
	cat ${PTRACE_PROC} > ${TMP_FILE}
}

test_clean_ptrace() {
	activate "stop"

	tmp=$(clean_ptrace_proc)
	actual=`echo $tmp|wc -l`
	expected=1
	assertEquals "test clean ptrace" "$expected" "$actual"
}

test_insert_ptrace() {
	activate "stop"

	insert_ptrace_proc
	actual=`cat ${TMP_FILE}|wc -l`
	expected=6
	assertEquals "test insert ptrace" "$expected" "$actual"
}

test_ptrace_context() {
	activate "stop"

	tmp=$(clean_ptrace_proc)
	insert_ptrace_proc
	cat ${TMP_FILE}|grep ntpd > /dev/null
	actual=$?
	expected=0

	assertEquals "test ptrace context" "$expected" "$actual"
}

test_ptrace_enable() {
	activate "stop"
	activate "start"

	tmp=$(clean_ptrace_proc)
	/etc/init.d/ntp restart
	sleep 2
	cat ${PTRACE_PROC}|grep ntpd > /dev/null
	actual=$?
	expected=0

	assertEquals "test ptrace enable" "$expected" "$actual"

	activate "stop"
	tmp=$(clean_ptrace_proc)
	rm -rf /tmp/aaa
}

test_ptrace_lock() {
	activate "stop"

	tmp=$(clean_ptrace_proc)
	locking "start"
	activate "start"

	/etc/init.d/ntp restart > /dev/null 2>&1
	actual=$?
	expected=1
	assertNotEquals "test ptrace lock" "$expected" "$actual"

	activate "stop"
	locking "stop"

	tmp=$(clean_ptrace_proc)

}

source "/usr/bin/shunit2"

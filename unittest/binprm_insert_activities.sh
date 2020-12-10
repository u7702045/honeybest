#!/bin/bash
ENABLE_PROC=/proc/sys/kernel/honeybest/enabled
ENABLE_BINPRM=/proc/sys/kernel/honeybest/binprm
LOCK_PROC=/proc/sys/kernel/honeybest/locking
BINPRM_PROC=/proc/honeybest/binprm
HB_TEMPLATE=./template/
HB_BINPRM=${HB_TEMPLATE}/binprm
TMP_FILE=/dev/shm/xxxx
activate(){
	if [ $1 == 'start' ]; then
		echo 1 > ${ENABLE_BINPRM}
		echo 1 > ${ENABLE_PROC}
	else
		echo 0 > ${ENABLE_PROC}
		echo 0 > ${ENABLE_BINPRM}
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

clean_binprm_proc() {
	echo "" > ${BINPRM_PROC}
	cat ${BINPRM_PROC}
}

insert_binprm_proc() {
	cat ${HB_BINPRM} > ${BINPRM_PROC}
	cat ${BINPRM_PROC} > ${TMP_FILE}
}

test_clean_binprm() {
	activate "stop"

	tmp=$(clean_binprm_proc)
	actual=`echo $tmp|wc -l`
	expected=1
	assertEquals "test clean file" "$expected" "$actual"
}

test_insert_file() {
	activate "stop"

	insert_binprm_proc
	actual=`cat ${TMP_FILE}|wc -l`
	expected=2
	assertEquals "test insert file" "$expected" "$actual"
}

test_file_context() {
	activate "stop"

	tmp=$(clean_binprm_proc)
	insert_binprm_proc
	actual=`cat ${TMP_FILE}|grep kmod|awk '{print $6}'|cut -d '/' -f 3`
	expected='kmod'

	assertEquals "test file context" "$expected" "$actual"
}

test_binprm_enable() {
	activate "stop"
	activate "start"

	tmp=$(clean_binprm_proc)
	cat /proc/cpuinfo > /dev/null
	sleep 2
	cat ${BINPRM_PROC}|grep cat > /dev/null
	actual=$?
	expected=0

	assertEquals "test binprm enable" "$expected" "$actual"

	activate "stop"
	tmp=$(clean_binprm_proc)
}

test_binprm_lock() {
	activate "stop"

	tmp=$(clean_binprm_proc)
	locking "start"
	activate "start"

	cat /etc/issue 2> /dev/null
	actual=$?
	expected=1

	assertNotEquals "test binprm lock" "$expected" "$actual"

	activate "stop"
	locking "stop"
	tmp=$(clean_binprm_proc)
}


source "/usr/bin/shunit2"

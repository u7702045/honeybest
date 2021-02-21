#!/bin/bash
EXEC_PWD=$(dirname $(realpath $0))
ENABLE_PROC=/proc/sys/kernel/honeybest/enabled
ENABLE_IPC=/proc/sys/kernel/honeybest/ipc
LOCK_PROC=/proc/sys/kernel/honeybest/locking
IPC_PROC=/proc/honeybest/ipc
HB_TEMPLATE=${EXEC_PWD}/template/
HB_IPC=${HB_TEMPLATE}/ipc
TMP_FILE=/dev/shm/xxxx
ID=0
activate(){
	if [ $1 == 'start' ]; then
		echo 1 > ${ENABLE_IPC}
		echo 1 > ${ENABLE_PROC}
	else
		echo 0 > ${ENABLE_IPC}
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

clean_ipc_proc() {
	echo "" > ${IPC_PROC}
	cat ${IPC_PROC}
}

insert_ipc_proc() {
        sed -e "s/\${EXEC_PWD}/${EXEC_PWD}/g" ${HB_IPC} > ${IPC_PROC}
	cat ${IPC_PROC} > ${TMP_FILE}
}

test_clean_ipc() {
	activate "stop"

	tmp=$(clean_ipc_proc)
	actual=`echo $tmp|wc -l`
	expected=1
	assertEquals "test clean ipc" "$expected" "$actual"
}

test_insert_ipc() {
	activate "stop"

	insert_ipc_proc
	actual=`cat ${TMP_FILE}|wc -l`
	expected=2
	assertEquals "test insert ipc" "$expected" "$actual"
}

test_ipc_context() {
	activate "stop"

	tmp=$(clean_ipc_proc)
	insert_ipc_proc
	cat ${TMP_FILE}|grep shmctl > /dev/null
	actual=$?
	expected=0

	assertEquals "test file context" "$expected" "$actual"
}

test_ipc_enable() {
	activate "stop"
	activate "start"

	tmp=$(clean_ipc_proc)
	ipcrm -a
	ipcmk -M 1 > ${TMP_FILE}
	ID=`cat ${TMP_FILE}|awk '{print $4}'`
	${EXEC_PWD}/utilities/shmctl $ID
	sleep 2
	cat ${IPC_PROC}|grep shmctl > /dev/null
	actual=$?
	expected=0

	assertEquals "test ipc enable" "$expected" "$actual"

	activate "stop"
	tmp=$(clean_ipc_proc)
}

test_ipc_lock() {
	activate "stop"

	tmp=$(clean_ipc_proc)
	ipcmk -M 1 > ${TMP_FILE}
	ID=`cat ${TMP_FILE}|awk '{print $4}'`
	locking "start"
	activate "start"

	${EXEC_PWD}/utilities/shmctl ${ID}
	actual=$?
	expected=1

	assertNotEquals "test ipc lock" "$expected" "$actual"

	activate "stop"
	locking "stop"
	tmp=$(clean_ipc_proc)
	ipcrm -a
}

source "/usr/bin/shunit2"

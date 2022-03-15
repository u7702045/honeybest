#!/bin/bash
EXEC_PWD=$(dirname $(realpath $0))
ENABLE_PROC=/proc/sys/kernel/honeybest/enabled
ENABLE_SOCKET=/proc/sys/kernel/honeybest/socket
LOCK_PROC=/proc/sys/kernel/honeybest/locking
SOCKET_PROC=/proc/honeybest/socket
HB_TEMPLATE=${EXEC_PWD}/template/
HB_SOCKET=${HB_TEMPLATE}/socket
TMP_FILE=/dev/shm/xxxx
activate(){
	if [ $1 == 'start' ]; then
		echo 1 > ${ENABLE_SOCKET}
		echo 1 > ${ENABLE_PROC}
	else
		echo 0 > ${ENABLE_SOCKET}
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

clean_socket_proc() {
	echo "" > ${SOCKET_PROC}
	cat ${SOCKET_PROC}
}

insert_socket_proc() {
	cat ${HB_SOCKET} > ${SOCKET_PROC}
	cat ${SOCKET_PROC} > ${TMP_FILE}
}

test_clean_socket() {
	activate "stop"

	tmp=$(clean_socket_proc)
	actual=`echo $tmp|wc -l`
	expected=1
	assertEquals "test clean socket" "$expected" "$actual"
}

test_insert_socket() {
	activate "stop"

	insert_socket_proc
	actual=`cat ${TMP_FILE}|wc -l`
	expected=3
	assertEquals "test insert socket" "$expected" "$actual"
}

test_socket_context() {
	activate "stop"

	tmp=$(clean_socket_proc)
	insert_socket_proc
	cat ${TMP_FILE}|grep 'nc.traditional' > /dev/null
	actual=$?
	expected=0

	assertEquals "test socket context" "$expected" "$actual"
}

test_socket_enable() {
	activate "stop"
	activate "start"

	tmp=$(clean_socket_proc)
	timeout 2s /bin/nc -v www.google.com 80
	cat ${SOCKET_PROC}|grep 'nc.traditional' > /dev/null
	actual=$?
	expected=0

	assertEquals "test socket enable" "$expected" "$actual"

	activate "stop"
	tmp=$(clean_socket_proc)
}

test_socket_lock() {
	activate "stop"

	tmp=$(clean_socket_proc)
	locking "start"
	activate "start"

	timeout 2s /bin/nc -v www.google.com 80
	actual=$?
	expected=0
	assertNotEquals "test socket lock" "$expected" "$actual"

	activate "stop"
	locking "stop"

	tmp=$(clean_socket_proc)

}

source "/usr/bin/shunit2"

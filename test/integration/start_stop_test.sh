#!/bin/bash
EXEC_PWD=$(dirname $(realpath $0))
ENABLE_PROC=/proc/sys/kernel/honeybest/enabled
HB_TEMPLATE=${EXEC_PWD}/template/
activate(){
	if [ $1 == 'start' ]; then
		echo 1 > ${ENABLE_PROC}
	else
		echo 0 > ${ENABLE_PROC}
       	fi
}

status() {
	cat ${ENABLE_PROC}
}

test_enable() {
	activate 'start'
	actual=$(status)
	expected=1
	assertEquals "start" "$expected" "$actual"
}

test_disable() {
	activate 'stop'
	actual=$(status)
	expected=0
	assertEquals "stop" "$expected" "$actual"
}

source "/usr/bin/shunit2"

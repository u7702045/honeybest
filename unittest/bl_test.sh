#!/bin/bash
ENABLE_PROC=/proc/sys/kernel/honeybest/bl
HB_TEMPLATE=./template/
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

test_enable_bl() {
	activate 'start'
	actual=$(status)
	expected=1
	assertEquals "start" "$expected" "$actual"
}

test_disable_bl() {
	activate 'stop'
	actual=$(status)
	expected=0
	assertEquals "stop" "$expected" "$actual"
}

source "/usr/bin/shunit2"

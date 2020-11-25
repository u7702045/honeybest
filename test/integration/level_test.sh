#!/bin/bash
EXEC_PWD=$(dirname $(realpath $0))
ENABLE_PROC=/proc/sys/kernel/honeybest/level
HB_TEMPLATE=${EXEC_PWD}/template/
turn_level(){
	if [ $1 == '1' ]; then
		echo 1 > ${ENABLE_PROC}
	else
		echo 2 > ${ENABLE_PROC}
       	fi
}

status() {
	cat ${ENABLE_PROC}
}

test_turn_level_2() {
	turn_level '2'
	actual=$(status)
	expected=2
	assertEquals "start" "$expected" "$actual"
}

test_turn_level_1() {
	turn_level '1'
	actual=$(status)
	expected=1
	assertEquals "stop" "$expected" "$actual"
}

source "/usr/bin/shunit2"

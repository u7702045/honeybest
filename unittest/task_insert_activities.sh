#!/bin/bash
ENABLE_PROC=/proc/sys/kernel/honeybest/enabled
ENABLE_TASKS=/proc/sys/kernel/honeybest/tasks
LOCK_PROC=/proc/sys/kernel/honeybest/locking
TASKS_PROC=/proc/honeybest/tasks
HB_TEMPLATE=./template/
HB_TASKS=${HB_TEMPLATE}/tasks
TMP_FILE=/dev/shm/xxxx
activate(){
	if [ $1 == 'start' ]; then
		echo 1 > ${ENABLE_TASKS}
		echo 1 > ${ENABLE_PROC}
	else
		echo 0 > ${ENABLE_TASKS}
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

clean_tasks_proc() {
	echo "" > ${TASKS_PROC}
	cat ${TASKS_PROC}
}

insert_tasks_proc() {
	cat ${HB_TASKS} > ${TASKS_PROC}
	cat ${TASKS_PROC} > ${TMP_FILE}
}

test_clean_tasks() {
	activate "stop"

	tmp=$(clean_tasks_proc)
	actual=`echo $tmp|wc -l`
	expected=1
	assertEquals "test clean tasks" "$expected" "$actual"
}

test_insert_tasks() {
	activate "stop"

	insert_tasks_proc
	actual=`cat ${TMP_FILE}|wc -l`
	expected=3
	assertEquals "test insert tasks" "$expected" "$actual"
}

test_tasks_context() {
	activate "stop"

	tmp=$(clean_tasks_proc)
	insert_tasks_proc
	cat ${TMP_FILE}|grep 'timeout' > /dev/null
	actual=$?
	expected=0

	assertEquals "test tasks context" "$expected" "$actual"
}

test_tasks_enable() {
	activate "stop"
	activate "start"

	tmp=$(clean_tasks_proc)
	timeout 2s ping 8.8.8.8 > /dev/null
	cat ${TASKS_PROC}|grep 'timeout' > /dev/null
	actual=$?
	expected=0

	assertEquals "test tasks enable" "$expected" "$actual"

	activate "stop"
	tmp=$(clean_tasks_proc)
}

test_tasks_lock() {
	activate "stop"

	tmp=$(clean_tasks_proc)
	locking "start"
	activate "start"

	ping 8.8.8.8 > /dev/null &
	pid=$!
	kill -9 $pid
	actual=$?
	expected=0
	assertNotEquals "test tasks lock" "$expected" "$actual"

	activate "stop"
	locking "stop"

	tmp=$(clean_tasks_proc)
	kill $pid
}

source "/usr/bin/shunit2"

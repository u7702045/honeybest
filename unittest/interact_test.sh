#!/bin/bash
ENABLE_PROC=/proc/sys/kernel/honeybest/enabled
ENABLE_KMOD=/proc/sys/kernel/honeybest/kmod
INTERACT_PROC=/proc/sys/kernel/honeybest/interact
NOTIFY_PROC=/proc/honeybest/notify
HB_TEMPLATE=./template/
activate(){
	if [ $1 == 'start' ]; then
		echo 1 > ${ENABLE_KMOD}
		echo 1 > ${ENABLE_PROC}
	else
		echo 0 > ${ENABLE_KMOD}
		echo 0 > ${ENABLE_PROC}
       	fi
}

status() {
	cat ${ENABLE_PROC}
}

test_enable_interact() {
	activate 'start'
	actual=$(status)
	expected=1
	assertEquals "start" "$expected" "$actual"
}

test_disable_interact() {
	activate 'stop'
	actual=$(status)
	expected=0
	assertEquals "stop" "$expected" "$actual"
}

test_notify_redirect() {
	rmmod iptable_filter 2> /dev/null
       	rmmod ip_tables 2> /dev/null
	activate 'stop'
	echo "" > /proc/honeybest/kmod
	cat ${NOTIFY_PROC} > /dev/null
	echo 1 > ${INTERACT_PROC}
	activate 'start'
	iptables -L > /dev/null 2>&1
	cat ${NOTIFY_PROC} | grep iptable > /dev/null
	actual=$?
	expected=0
	echo 0 > ${INTERACT_PROC}
	activate 'stop'

	assertEquals "notify file test" "$expected" "$actual"
	echo 0 > ${INTERACT_PROC}
}

source "/usr/bin/shunit2"

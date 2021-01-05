#!/bin/bash
ENABLE_PROC=/proc/sys/kernel/honeybest/enabled
ENABLE_AUDIT=/proc/sys/kernel/honeybest/audit
BINPRM_PROC=/proc/honeybest/binprm
HB_TEMPLATE=./template/
LS_ACCEPT=${HB_TEMPLATE}/ls_accept
AUDIT_LOG=/var/log/audit/audit.log
activate(){
	if [ $1 == 'start' ]; then
		echo 1 > ${ENABLE_AUDIT}
	else
		echo 0 > ${ENABLE_AUDIT}
       	fi
}

status() {
	cat ${ENABLE_AUDIT}
}

clean_audit_log() {
	echo "" > ${AUDIT_LOG}
}

test_audit_enable() {
	activate "start"
	clean_audit_log

	actual=$(status)
	expected=1
	assertEquals "audit enable" "$expected" "$actual"

	activate "stop"
}

test_audit_disable() {
	activate "start"
	activate "stop"
	clean_audit_log

	actual=$(status)
	expected=0
	assertEquals "audit disable" "$expected" "$actual"
	activate "stop"
}

test_audit_data() {
	activate "start"

	clean_audit_log

	cat ${LS_ACCEPT} > ${BINPRM_PROC}
	sleep 2
	ausearch -m KERNEL_OTHER |grep selinux > /dev/null
	actual=$?
	expected=0
	assertEquals "audit data fail, may be you need to install auditd package" "$expected" "$actual"
	activate "stop"
}

source "/usr/bin/shunit2"

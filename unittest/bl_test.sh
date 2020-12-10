#!/bin/bash
ENABLE_PROC=/proc/sys/kernel/honeybest/enabled
ENABLE_FILE=/proc/sys/kernel/honeybest/files
ENABLE_BINPRM=/proc/sys/kernel/honeybest/binprm
BL_PROC=/proc/sys/kernel/honeybest/bl
FILE_PROC=/proc/honeybest/files
BINPRM_PROC=/proc/honeybest/binprm
LOCK_PROC=/proc/sys/kernel/honeybest/locking
HB_TEMPLATE=./template/
LS_ACCEPT=${HB_TEMPLATE}/ls_accept
LS_REJECT=${HB_TEMPLATE}/ls_reject
activate_binprm(){
	if [ $1 == 'start' ]; then
		echo 1 > ${ENABLE_BINPRM}
		echo 1 > ${ENABLE_PROC}
	else
		echo 0 > ${ENABLE_BINPRM}
		echo 0 > ${ENABLE_PROC}
       	fi
}

activate_file(){
	if [ $1 == 'start' ]; then
		echo 1 > ${ENABLE_FILE}
		echo 1 > ${ENABLE_PROC}
	else
		echo 0 > ${ENABLE_FILE}
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

switch_bl(){
	if [ $1 == 'on' ]; then
		echo 1 > ${BL_PROC}
	else
		echo 0 > ${BL_PROC}
       	fi
}

status() {
	cat ${BL_PROC}
}

clean_file_proc() {
	echo "" > ${FILE_PROC}
}

clean_binprm_proc() {
	echo "" > ${BINPRM_PROC}
}

prepare_locking() {
	clean_binprm_proc
	switch_bl 'off'
	locking 'stop'
	activate_binprm 'start'

	ls > /dev/null

	activate_binprm 'stop'
	switch_bl 'off'
	locking 'stop'
}


test_enable_bl() {
	activate_binprm 'start'
	switch_bl 'on'

	actual=$(status)
	expected=1
	assertEquals "check bl status" "$expected" "$actual"

	activate_binprm 'stop'
	switch_bl 'off'
}

#default is whitelist mode
test_switch_bl_files_0() {
	clean_file_proc
	switch_bl 'on'
	activate_file 'start'

	#any action that trigger insert files contect
	ps aux > /dev/null

	switch_bl 'off'
	activate_file 'stop'

	actual=$(tail -n 1 ${FILE_PROC}|awk '{print $4}')
	expected='R'
	assertEquals "check switch bl files test 0" "$expected" "$actual"

	clean_file_proc
}

#default is blacklist mode
test_switch_bl_files_1() {
	clean_file_proc
	switch_bl 'off'
	activate_file 'start'

	#any action that trigger insert files contect
	ps aux > /dev/null

	activate_file 'stop'
	switch_bl 'off'

	actual=$(tail -n 1 ${FILE_PROC}|awk '{print $4}')
	expected='A'
	assertEquals "check switch bl files test 1" "$expected" "$actual"

	clean_file_proc
}

#default is whitelist mode
test_switch_bl_binprm_0() {
	clean_binprm_proc
	switch_bl 'on'
	activate_binprm 'start'

	#any action that trigger insert files contect
	ps aux > /dev/null

	switch_bl 'off'
	activate_binprm 'stop'

	actual=$(tail -n 1 ${BINPRM_PROC}|awk '{print $4}')
	expected='R'
	assertEquals "check switch bl binprm test 0" "$expected" "$actual"

	clean_binprm_proc
}

#default is blacklist mode
test_switch_bl_binprm_1() {
	clean_binprm_proc
	switch_bl 'off'
	activate_binprm 'start'

	#any action that trigger insert files contect
	ps aux > /dev/null

	activate_binprm 'stop'
	switch_bl 'off'

	actual=$(tail -n 1 ${BINPRM_PROC}|awk '{print $4}')
	expected='A'
	assertEquals "check switch bl binprm test 1" "$expected" "$actual"

	clean_binprm_proc
}

test_switch_all_reject_binprm_context_0() {
	prepare_locking
	clean_binprm_proc
	cat ${LS_ACCEPT} > ${BINPRM_PROC}
	switch_bl 'off'
	locking 'start'
	activate_binprm 'start'

	#all reject, test accept
	ls --help > /dev/null
	actual=$?

	switch_bl 'off'
	locking 'stop'
	activate_binprm 'stop'

	expected=0
	assertEquals "check switch bl binprm context test 0" "$expected" "$actual"

	clean_binprm_proc
}

#test_switch_bl_all_accept_binprm_context_1() {
#	prepare_locking
#	clean_binprm_proc
#	cat ${LS_REJECT} > ${BINPRM_PROC}
#	#all accept, test reject
#	switch_bl 'on'
#	locking 'start'
#	activate_binprm 'start'
#
#	#any action that trigger insert files contect
#	ls > /dev/null
#	actual=$?
#
#	activate_binprm 'stop'
#	switch_bl 'off'
#	locking 'stop'
#
#	expected=0
#	assertNotEquals "check switch bl binprm context test 1" "$expected" "$actual"
#
#	clean_binprm_proc
#}

source "/usr/bin/shunit2"

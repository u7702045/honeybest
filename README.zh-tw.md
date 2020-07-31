# 漢妮安全模組<br/><img src="HoneyBest.png" width="100" height="150" />
漢妮專案主要目標為打造一個基於白名單設計的全新安全模組.<br/> 
*Read this in other languages: [English](README.md), [正體中文](README.zh-tw.md).*
### __背景__
###### Over the year few security modules have been developed on Linux distribution, such as SELinux / Apparmor / Smack / Tomoyo project, but there is still huge space to make improvement nevertheless. Until now, most of the Linux user keep apart from existing security modules mainly because it make a high entry barrier for those who have little understanding of system behavior & security module rules. In order to build the more user friendly module, our target is to hide the complexity of rules, but also allow advanced user to be able to refine the granularity.<br/> 
###### For most of the user case, security module begin to involve in post software development. Take an embedded devices, NAS appliance for the example. Security developer have to write a bunch of rules to protect applications, configuration files from other unauthorized process & restriction to certain resources. In order to do so, they had to go deep understanding through every single process to prevent from threads. We start to ask ourselves few question, is there any possible we can build an auto generation secure module policy base on real time scenario? How if the secure module policy support interaction with developer whether or not to add new rules or requesting permission under safe condition? Is there an alternative approach to replace rules concept? HoneyBest secure module might be for those answer. <br/>
### __概念__
###### Let us imaging few conditions here.
##### Condition A – Environment complexity is hard to apply rules
###### Team of developers have complete their software development on Linux box. The appliance involve NGIX server for user to configure setting; Samba server for file sharing; SNMP server for remote setting; Syslog server to track system record. They handle the appliance to one of their security guy, Bob, who are the expertise in security module. In order to create thread model, Bob have to understand every single process running on the box, how each process interfere with system and other processes. He now create rules to protect base on the thread model. At first, he create rules to restrict process to access only certain system resource, such as Syslog server. Syslog server is allowed to create files under /var/log/*.log, with WRITE permission only; Syslog server is allow to create only localhost 514 UDP port, receive other application log message. Here come small part of complicate scenario, log message files could grow up over the time and Logrotate daemon are design into system to handle compression job; log message files need permission rules to MOVE files(DELETE/CREATE/READ/WRITE); Meanwhile, NGIX we server need permission READ in order to show context while user login via web page. After Bob figure out all those cross over relationship & rules, he start to apply into system. It turn out, the box does not act as normal as expect to pass system integration test. Bob have to invite developer to figure out what going on to the system. It turn out that NGIX web server need permission rules to interact with 514 UDP port for logging itself message. In real world, security expertise feel frustrate to do their job because of complexity environment involve.<br/>
##### Condition B – High learning curves
###### User, roles, level, category, labeling, and hats are not easy to understand, those are security expertise concept with specific tools. Most of the small/medium company do not have security expertise to rely on. We want to help software developers secure their product as much as we can.<br/>
##### Condition C – Untrusted root in design
###### The complete security policies should treat super user (root) as normal root. Root are not allow to change others policies but its own. Penetration to root user might corrupt whole policies wall you made. In our design, policies update or change should bind tightly with secure boot process, more precisely, with hardware Root of Trust.<br/>
##### Condition D – Interaction in real time instead of post rules applied
###### Real time interaction feedback mechanism are more easy way for developers to understand what going. Instead of rules, pop out dialogue asking permission to explain activity is an effective way to make progress. For the fine-grain advanced user, our design also consider to fulfill such needs.<br/>
##### Condition E – Different perspective of software protection
###### In some privacy scenario, system designer not only require the task to have restriction from accessing resources, but also restriction from other resources to access the task. Here are the 2 examples, I want to protect my private libraries/program from piracy, however, still allow certain program to use; I want only “upgrade-firmware” command to be able upgrade system firmware, not “dd” command, and the integrity of “upgrade-firmware” command is concerned. <br/>
### __設計__
###### Our core design is to focus on capturing the kernel activities triggered by user space program. Activities which is tracking will later turn into list data structure for security module to detect an unexpected occur event. The size of list data structure is tightly depends on level of granularity. The more precise restriction or control to be chosen, the higher space requirement for data structure to be saved. Above the surface of such design, here is the approach to apply secure module. Unfreeze the box in your security environment, run all activities as you can to create a model, then freeze the box. Once you freeze the box, all activities are restrict to previous model. You might consider fine-grain the model because some activities are not able to perform in your security environment. Either use an editor to edit the model or turn on interaction mode, developers are able to selectively choose prompt up dialogue with new activity in real world situation. Below figure show how the lifecycle go:
1.	###### Product finish development
2.	###### Turn on unfreeze mode / Turn off interaction mode
3.	###### 1st End to End System Integration Test 
4.	###### Turn off unfreeze mode / Turn on interaction mode
5.	###### 2nd End to End System Integration Test or Manually edit model
6.	###### Turn off interaction mode.
### __Compiling__
###### Similar to SELinux/Apparmor design, HoneyBest security module is hooked on Linux Security Module layer. Clone the source code into Linux kernel source and follow instruction below:
1.	###### Create a new directory called honeybest under [KERNEL SOURCE]/security directory.
2.	###### Clone Honeybest source code into honeybest directory.
3.	###### If you are Debian/Ubuntu environment, install necessary packages to compile new kernel (`apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev bc`).
4.	###### Change directory to honeybest and run the Kconfig.patch & Makefile.path
5.	###### Copy original kernel configuration to [KERNEL SOURCE]/.config (`cat /boot/config-4.9.X > [KERNEL SOURCE/.config`.
6.	###### Select HoneyBest security module (`make menuconfig`)
7.	###### Compiling kernel under [KERNEL SOURCE] (`make modules bzImage`)
8.	###### Install new kernel & modules (`make install`)
### __使用__
##### Enablement option – on mode or off mode
###### HoneyBest security module stay in deactivate mode / non-interactive mode as default. It provides 2 activation options, below: 
1.	###### Add string hashlock.enabled=1 into GRUB parameter.
2.	###### Enable at initrd-ramfs stage (`echo 1 > /proc/sys/kernel/honeybest/enabled`)
##### **__There is no deactivate after activate for security reason, update GRUB/initrd image must design tightly with secure boot verification process.__**
###### Once you activate HoneyBest, kernel tracking activities start to record into different files under directory /proc/honeybest. User can monitor the tracking progress via read file application such as tail/cat/head. 

##### Locking option – on mode or off mode
###### Locking option only take effective once enablement option mode turn on (default locking option mode is turn off). Once turn on, only expect activities is allow to operate on system. Locking mode toggle can be set via command (`echo 1 > /proc/sys/kernel/honeybest/locking` or `echo 0 > /proc/sys/kernel/honeybest/locking`)
##### Interactive option - manual mode vs auto mode
###### Interactive & auto mode only take effectively when enablement mode turn into true. The default interactive option is switch to auto mode, all activities occur in kernel are immediately tracking after enablement option turn into true. Selecting manual mode are mandatory to install libhoneybest-notify package (still in developing progress). Interactive mode toggle can be set via command (`echo 1 > /proc/sys/kernel/honeybest/interact` or `echo 0 > /proc/sys/kernel/honeybest/interact`)

### __Configure activities__
##### Every single files in directory /proc/honeybest tracking different behavior. We will explain each single file corresponding on next section. In general, every file share the common column, e.g NO/FUNCTION/USER ID.
* ###### NO – sequence number, honeybest compare the occurrence activities begin from lower to higher number.
* ###### FUNCTION – functional identification, honeybest use to identify different activities. Under certain category such as ‘socket’, different activities are label as listen/bind/accept/open/setsocketopt and so on. 
* ###### USER ID – user identification, honeybest use to reference relationship between identity and function. 

##### 檔案
* ###### binprm – Tracking all executable file path name, process UID belong to and most importantly, calculate file context into HASH to protect the integrity.
* ###### files – Tracking ordinary file behavior, such as open/read/write/delete/rename.
* ###### inode – Tracking inode operation, such as create/delete/read/update/setxattr/getxattr.
* ###### path – Tracking behavior of all type of file such as device node, hard/soft symbolic, directory, pipe, unix socket.
* ###### socket – Tracking TCP/UDP/ICMP socket activity, including port number.
* ###### task – Tracking activity between process, such as signal exchanging.
* ###### sb – Tracking superblock information. Activities such as mount/umount/df will stamp into this category. Highly relate to file/path categories due to system register /proc information.
* ###### kmod – Tracking Linux kernel modules activity. Kernel modprobe will stamp into this category. 
* ###### notify – Notification between security module and user space application. In interactive mode, detect to unexpected events are save into this file for user space program to notify user later. Dialogue pop up to acquiring security expertise allow or ignore such activities. Context in 


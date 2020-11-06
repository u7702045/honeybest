# HoneyBest LSM <br/><img src="images/HoneyBest.png" width="100" height="150" />
HoneyBest is the new implementation of Linux Security Module project.<br/> 
*Read this in other languages: [English](README.md), [正體中文](README.zh-tw.md).*
## __Background__
Over the years few security modules have been developed on Linux distribution, such as SELinux / Apparmor / Smack / Tomoyo project, but there is still huge space to make improvement nevertheless. Until now, the high entry barrier keep apart from most of the Linux user. For those who have little understanding of system behavior & security thread model are frustracte to apply the software. In order to build the more user friendly module, our target is to hide the complexity of rules, but also allow advanced user to be able to refine the granularity.<br/> 
Most of the case, security module begin to involve in post software development stage. Take an embedded devices, NAS appliance for the example. Security developer have to write a bunch of rules to protect applications, configuration files from other unauthorized process & restriction to certain resources. In order to do so, they had to go deep understanding through every single process to prevent from threats. We ask ourselves few question, is there any possible we can build an auto generation secure module policy base on real time scenario? How if the secure module policy support interaction with developer whether or not to add new rules or requesting permission under safe condition? Is there an alternative approach to replace rules concept? HoneyBest secure module might be for those answer. <br/>
## __Concept__
Let us imaging few conditions here.
#### Condition A – Environment complexity is hard to apply rules
Team of developers have complete their software development on Linux box. The appliance involve NGINX server for user to configure setting; Samba server for file sharing; SNMP server for remote setting; Syslog server to track system record. They handle the appliance to one of their security guy, Bob, who are the expertise in security module. In order to create threat model, Bob have to understand every single process running on the box, how each process interfere with system and other processes. He now create rules to protect base on the threat model. At first, he create rules to restrict process to access only certain system resource, such as Syslog server. Syslog server is allowed to create files under /var/log/*.log, with WRITE permission only; Syslog server is allow to create only localhost 514 UDP port, receive other application log message. Here come small part of complicate scenario, log message files could grow up over the time and Logrotate daemon are design into system to handle compression job; log message files need permission rules to MOVE files(DELETE/CREATE/READ/WRITE); Meanwhile, NGINX we server need permission READ in order to show context while user login via web page. After Bob figure out all those cross over relationship & rules, he start to apply into system. It turn out, the box does not act as normal as expect to pass system integration test. Bob have to invite developer to figure out what going on to the system. It turn out that NGINX web server need permission rules to interact with 514 UDP port for logging itself message. <br/>
In real world, security expertise feel frustrate to do their job because of complexity environment involve. Honeybest change the way to more adaptive into development flow, see below:<br/>
<img src="images/DevelopmentFlow.JPG" width="500" height="220" />

#### Condition B – High learning curves
User, roles, level, category, labeling, and hats are not easy to understand, those are security expertise concept with specific tools. Most of the small/medium company do not have security expertise to rely on. We want to help software developers secure their product as much as we can.<br/>
#### Condition C – Untrusted root in design
he complete security policies should treat super user (root) as normal root. Root are not allow to change others policies but its own. Penetration to root user might corrupt whole policies wall you made. In our design, policies update or change should bind tightly with secure boot process, more precisely, with hardware Root of Trust.<br/>
#### Condition D – Interaction in real time instead of post rules applied
Real time interaction feedback mechanism are more easy way for developers to understand what going. Instead of rules, pop out dialogue asking permission to explain activity is an effective way to make progress. For the fine-grain advanced user, our design also consider to fulfill such needs.<br/>
#### Condition E – Different perspective of software protection
In some privacy scenario, system designer not only require the task to have restriction from accessing resources, but also restriction from other resources to access the task. Here are the 2 examples, I want to protect my private libraries/program from piracy, however, still allow certain program to use; I want only “upgrade-firmware” command to be able upgrade system firmware, not “dd” command, and the integrity of “upgrade-firmware” command is concerned. <br/>
### __Design__
Our core design is to focus on capturing the kernel activities triggered by user space program. Activities which is tracking will later turn into list data structure for security module to detect an unexpected occur event. The size of list data structure is tightly depends on level of granularity. The more precise restriction or control to be chosen, the higher space requirement for data structure to be saved. Above the surface of such design, here is the approach to apply secure module. Unfreeze the box in your security environment, run all activities as you can to create a model, then freeze the box. Once you freeze the box, all activities are restrict to previous model. You might consider fine-grain the model because some activities are not able to perform in your security environment. Either use an editor to edit the model or turn on interaction mode, developers are able to selectively choose prompt up dialogue with new activity in real world situation. Below figure show how the lifecycle go:
1.	Product finish development
2.	Turn on unfreeze mode / Turn off interaction mode
3.	1st End to End System Integration Test 
4.	Turn off unfreeze mode / Turn on interaction mode
5.	2nd End to End System Integration Test or Manually edit model
6.	Turn off interaction mode.
### __Compiling__
Similar to SELinux/Apparmor design, HoneyBest security module is hooked on Linux Security Module layer. Clone the source code into Linux kernel source and follow instruction below:
1.	Create a new directory called honeybest under [KERNEL SOURCE]/security directory.
2.	Clone Honeybest source code into honeybest directory.
3.	If you are Debian/Ubuntu environment, install necessary packages to compile new kernel (`apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev bc`).
4.	Change directory to honeybest and run the Kconfig.patch & Makefile.path
5.	Copy original kernel configuration to [KERNEL SOURCE]/.config (`cat /boot/config-4.9.X > [KERNEL SOURCE/.config`.
6.	Select HoneyBest security module (`make menuconfig`)
7.	Compiling kernel under [KERNEL SOURCE] (`make modules bzImage`)
8.	Install new kernel & modules (`make install`)
### __Usage__
##### Enablement option – on mode or off mode
HoneyBest security module stay in deactivate mode / non-interactive mode as default. It provides 2 activation options, below: 
1.	Add string hashlock.enabled=1 into GRUB parameter.
2.	Enable at initrd-ramfs stage (`echo 1 > /proc/sys/kernel/honeybest/enabled`)
**__There is no deactivate after activate for security reason (compiling kernel with option CONFIG_HONEYBEST_PROD), update GRUB/initrd image must design tightly with secure boot verification process.__**
Once you activate HoneyBest, kernel tracking activities start to record into different files under directory /proc/honeybest. User can monitor the tracking progress via read file application such as tail/cat/head. 
##### selective features option – on mode or off mode
HoneyBest offer rich feature set to tracking from different perspective, such as binary file, socket, ipc, inode and so on. Section "Files" expose more detail to each different perspective features. Enabling selective features with command (`echo 1 > /proc/sys/kernel/honeybest/[Files]`), e.g to turn on binary hash, command (`echo 1 > /proc/sys/kernel/honeybest/binprm`)
##### Locking option – on mode or off mode
Locking option only take effective once enablement option mode turn on (default locking option mode is turn off). Once turn on, only expect activities is allow to operate on system. Locking mode toggle can be set via command (`echo 1 > /proc/sys/kernel/honeybest/locking` or `echo 0 > /proc/sys/kernel/honeybest/locking`). This option take effectived only when enablement option is in turn on mode.

##### Interactive option - manual mode vs auto mode
Interactive & auto mode only take effectively when enablement mode turn into true. The default interactive option is switch to auto mode, all activities occur in kernel are immediately tracking after enablement option turn into true. Selecting manual mode are mandatory to install libhoneybest-notify package (still in developing progress). Interactive mode toggle can be set via command (`echo 1 > /proc/sys/kernel/honeybest/interact` or `echo 0 > /proc/sys/kernel/honeybest/interact`). This option take effectived only when enablement option is in turn on mode; Locking option is in turn off mode.

##### Black list option - whitelist mode vs blacklist mode
The default mode is whitelist mode, all activities pass through the list will be allow as default. The easy way to think of this mode is iptables default policy, REJECT or ACCEPT. The toggle can be set via command (`echo 1 > /proc/sys/kernel/honeybest/bl` or `echo 0 > /proc/sys/kernel/honeybest/bl`).

##### Granularity option - level 1,2
The default granularity of match/track activities is 0, which is we think of suitable to most of the user case. The higher the level number, the more time to consumpt during comparison stage. High granularity of activities tracking caused the OS environment turn to low flexibility. The toggle can be set via command (`echo [1,2] > /proc/sys/kernel/honeybest/level`).

### __Configure activities__
Every single files in directory /proc/honeybest tracking different behavior. We will explain each single file corresponding on next section. In general, every file share the common column, e.g NO/FUNCTION/USER ID.
* NO – sequence number, honeybest compare the occurrence activities begin from lower to higher number.
* FUNCTION – functional identification, honeybest use to identify different activities. Under certain category such as ‘socket’, different activities are label as listen/bind/accept/open/setsocketopt and so on. 
* USER ID – user identification, honeybest use to reference relationship between identity and function. This column support RE(regular expression, digits & '*' asterisk).
* ACTION - Matching action refer to 'A'ccept or 'R'eject. Default value depend on bl option, accept actions are appended when bl toggle to 0; vice versa, reject actions are appended.

#### Files
* binprm – Tracking all executable file path name, process UID belong to and most importantly, calculate file context into HASH to protect the integrity.
* files – Tracking ordinary file behavior, such as open/read/write/delete/rename.
* inode – Tracking inode operation, such as create/delete/read/update/setxattr/getxattr.
* path – Tracking behavior of all type of file such as device node, hard/soft symbolic, directory, pipe, unix socket.
* socket – Tracking TCP/UDP/ICMP socket activity, including port number.
* task – Tracking activity between process, such as signal exchanging.
* sb – Tracking superblock information. Activities such as mount/umount/df will stamp into this category. Highly relate to file/path categories due to system register /proc information.
* kmod – Tracking Linux kernel modules activity. Kernel modprobe will stamp into this category.
* ptrace - Tracking ptrace activities.
* ipc - Tracking Linux internal process communication activities such as share memory, message queue & semaphore.
* notify – Notification between security module and user space application. In interactive mode, detect to unexpected events are save into this file for user space program to notify user later. Dialogue pop up to acquiring security expertise allow or ignore such activities. Once the interactive mode is enable, all events go through this file could expose memory exhaust. Thurs, design a READ scheduler from user space program is vital. Context in notify file will be cleaned after each single READ operation is executed.
##### Tuning example (`/proc/honeybest/path`)
In general, developer usually run through the flow below: <br/>
1. Enable the HoneyBest LSM. `echo 1 > /proc/sys/kernel/honeybest/enabled`
2. Running the system test. The example here we focus on path file, which have high relative to symbolic file create activity. Let mimic our system test involve to creating symbolic link. `ln -s /etc/services /tmp/services`
3. Now, disable the HoneyBest before tuning whitelist. `echo 0 > /proc/sys/kernel/honeybest/enabled`
4. Review the activities relates to path. `cat /proc/honeybest/path | grep services`
5. If you find out result show `23 0 0 0 0 0 /etc/services /tmp/services`, that indicate whitelist is automatically track.
6. Another advance case here. Let say your system test involve udev daemon constantly accumulate new symbolic file with constant pattern, e.g /dev/usb0, /dev/usb1…n link to /dev/ttyUSB. We notice that multi line relate to /dev/ttyusb have attach into path file context after enable the HoneyBest LSM. Here is an approach to solve the matching issue. <br/>
	6.1. Disable the HoneyBest LSM. <br/>
	6.2. Dump context to new file. `cat /proc/honeybest/path > /etc/hb/path` <br/>
	6.3. Example Figure 1 is the example context of /etc/hb/path file.  <br/>
	6.4. Eliminate first row & first column, eliminate all duplicate line and leave only one line with regular express at increasing character, Figure 2. <br/>
	6.5. Re-apply new activities to HoneyBest LSM. `cat /etc/hb/path > /proc/honeybest/path`<br/>
	6.6 Enable the HoneyBest LSM. <br/>
Developer can enable the locking mode during system test to verify the outcome. If system test failure, disable the locking mode and run again the activities. Comparing the files context will give you hint what missing activity need to inject.
#### Figure 1

|NO|FUNC|UID|MODE|SUID|GUID|DEV|SOURCE PATH|TARGET PATH|
|--|----|---|----|----|----|---|-----------|-----------|
|0|23|0|0|0|0|0|/dev/usb0|/dev/ttyUSB0|
|1|23|0|0|0|0|0|/dev/usb0|/dev/ttyUSB1|
|2|23|0|0|0|0|0|/dev/usb0|/dev/ttyUSB2|
|3|20|0|420|0|0|0|/etc/resolv.conf.dhclient-new.1115|/etc/resolv.conf|

#### Figure 2
| | | | | | | | | |
|--|----|---|----|----|----|---|-----------|-----------|
|23|0|0|0|0|0|/dev/usb0|/dev/ttyUSB*|
|23|0|0|0|0|0||/etc/resolv.conf.dhclient-new.1115|/etc/resolv.conf|

##### Save & Restore configuration
Saving the HoneyBest LSM configuration are pretty simple. All you need is to dump it out into separate file and restore once the system restart (initrd or rc.local). __Redo the step 6.4 is necessary after save the context, HoneyBest LSM will not restore correctly if step 6.4 is not complete.__
* save – Dump current setting to file, command `cat /proc/honeybest/binprm > /etc/hb/binprm`.
* restore – Restore current setting to system, command `cat /etc/hb/binprm > /proc/honeybest/binprm`.
* lock down – After restore, lock down HoneyBest to prevent tracking, command `echo 1 > /proc/sys/kernel/honeybest/locking`.
* enable – Enable HoneyBest, command `echo 1 > /proc/sys/kernel/honeybest/enabled`
* select feature set - binary hash example, command `echo 1 > /proc/sys/kernel/honeybest/binprm`

#### Examples
##### Proprietary shared libraries protection from root & users
In our example here, we want to protect few shared libraries list below from scp or copy out of box:
* /usr/lib/arm-linux-gnueabihf/libtss2-sys.so.0.0.0
* /usr/lib/arm-linux-gnueabihf/libtss2-mu.so.0.0.0
* /usr/lib/arm-linux-gnueabihf/libcrypto.so.1.1
* /usr/lib/arm-linux-gnueabihf/libtss2-tcti-device.so.0.0.0

You need to enabling/design secure boot process in order to prohibit kernel & initramfs from replacing. In addition, we suggesting use hardware security module(HSM) such as TPM/ArmTrustZone to involve into secure boot process. Reformat your partition with LUKs and bind LUKs's key to HSM. Here are the few steps:
1. Recompiling kernel option with CONFIG_HONEYBEST_PROD=y.
2. Add 'files' feature set configuration into initramfs, save it into directory /etc/honeybest/files:
<img src="images/honeybest blacklist files shared libraries protection.JPG" width="1000" height="150" />
3. Add 'binprm' feature set configuration into initramfs, save it into directory /etc/honeybest/binprm:
<img src="images/honeybest blacklist binprm shared libraries protection.JPG" width="1000" height="150" />
4. Add 'sb' feature set configuration into initramfs, save it into directory /etc/honeybest/sb:
<img src="images/honeybest blacklist sb shared libraries protection.JPG" width="700" height="20" />
5. Add initramfs script (init-top) to run before chroot into LUKs filesystem:
<img src="images/honeybest blacklist setup shared libraries protection.JPG" width="700" height="500" />






# HoneyBest LSM

<img src="images/HoneyBest.jpg" width="200" height="250" />

**HoneyBest** is a Linux Security Module (LSM) designed to provide adaptive, user-friendly security policies through activity-based whitelisting and real-time interaction mechanisms.

*Read this in other languages: [English](README.md), [正體中文](README.zh-tw.md).*

---

## Table of Contents

- [Overview](#overview)
- [Background](#background)
- [Design Philosophy](#design-philosophy)
  - [Condition A: Environment Complexity](#condition-a-environment-complexity)
  - [Condition B: High Learning Curve](#condition-b-high-learning-curve)
  - [Condition C: Untrusted Root](#condition-c-untrusted-root)
  - [Condition D: Real-Time Interaction](#condition-d-real-time-interaction)
  - [Condition E: Bidirectional Protection](#condition-e-bidirectional-protection)
- [Architecture](#architecture)
- [Building and Installation](#building-and-installation)
- [Configuration](#configuration)
  - [Enablement Options](#enablement-options)
  - [Feature Selection](#feature-selection)
  - [Locking Mode](#locking-mode)
  - [Interactive Mode](#interactive-mode)
  - [Blacklist/Whitelist Mode](#blacklistwhitelist-mode)
  - [Granularity Levels](#granularity-levels)
- [Activity Configuration](#activity-configuration)
  - [Common Fields](#common-fields)
  - [Activity Files](#activity-files)
  - [Tuning Example](#tuning-example)
  - [Save and Restore](#save-and-restore)
- [Use Cases](#use-cases)
  - [Proprietary Shared Library Protection](#proprietary-shared-library-protection)
- [License](#license)

---

## Overview

HoneyBest is a Linux Security Module that addresses the complexity and usability challenges of traditional security modules like SELinux, AppArmor, Smack, and Tomoyo. Unlike rule-based security modules that require extensive expertise to configure, HoneyBest uses an activity-based approach that automatically generates security policies from observed system behavior.

**Key Features:**
- **Activity-based policy generation**: Automatically creates security policies by tracking kernel activities
- **Real-time interaction**: Interactive mode allows developers to approve or deny new activities as they occur
- **Low learning curve**: Hides rule complexity while allowing advanced users to fine-tune granularity
- **Bidirectional protection**: Protects both resources from tasks and tasks from unauthorized access
- **Production-ready**: Supports secure boot integration and hardware Root of Trust binding

---

## Background

Traditional Linux security modules have been available for years, including SELinux, AppArmor, Smack, and Tomoyo. However, these solutions present significant barriers to adoption:

- **High entry barrier**: Most Linux users lack the expertise to configure complex rule-based security policies
- **Post-development integration**: Security modules are typically integrated after software development, requiring security experts to understand every process and interaction
- **Complex rule management**: Creating and maintaining security rules requires deep understanding of system behavior and threat models

HoneyBest addresses these challenges by:

1. **Automatic policy generation**: Building security policies based on real-time system scenarios rather than manual rule creation
2. **Interactive development**: Supporting real-time interaction with developers to approve or deny activities under safe conditions
3. **Alternative to rules**: Providing an activity-based model that eliminates the need for traditional rule concepts

---

## Design Philosophy

HoneyBest addresses five core challenges in security module design:

### Condition A: Environment Complexity

**Problem**: Complex environments make it difficult to apply security rules correctly.

**Example Scenario**: A development team completes software for a Linux appliance that includes:
- NGINX server for web configuration
- Samba server for file sharing
- SNMP server for remote management
- Syslog server for system logging

A security expert (Bob) must understand every process, how they interact with the system and each other, and create rules accordingly. For example:
- Syslog server needs to create files under `/var/log/*.log` with WRITE permission only
- Syslog server needs to bind to localhost UDP port 514 to receive log messages
- Logrotate daemon needs permission to MOVE log files (DELETE/CREATE/READ/WRITE)
- NGINX web server needs READ permission to display log content via web interface
- NGINX also needs permission to interact with UDP port 514 for its own logging

After creating rules based on this threat model, the system fails integration tests. Investigation reveals that NGINX requires permission to interact with UDP port 514, which was overlooked.

**HoneyBest Solution**: HoneyBest adapts to the development workflow by automatically tracking activities during system integration testing, eliminating the need to manually map all process interactions.

<img src="images/DevelopmentFlow.JPG" width="500" height="220" />

### Condition B: High Learning Curve

**Problem**: Security concepts like users, roles, levels, categories, labeling, and hats are difficult to understand and require specialized tools and expertise.

**HoneyBest Solution**: HoneyBest simplifies security configuration for software developers who may not have security expertise, while still providing advanced features for those who need fine-grained control.

### Condition C: Untrusted Root

**Problem**: Complete security policies should treat the superuser (root) as untrusted. Root should not be allowed to change other policies, only its own. Root compromise could corrupt all security policies.

**HoneyBest Solution**: Policy updates and changes are tightly bound to the secure boot process, specifically with hardware Root of Trust, preventing unauthorized policy modifications even if root is compromised.

### Condition D: Real-Time Interaction

**Problem**: Post-application rule management is reactive and difficult to understand.

**HoneyBest Solution**: Real-time interaction feedback mechanisms allow developers to understand system behavior as it happens. Instead of complex rules, interactive dialogs explain activities and request permission, making security decisions more intuitive. Advanced users can still access fine-grained controls.

### Condition E: Bidirectional Protection

**Problem**: Some scenarios require protecting tasks from accessing resources AND protecting tasks from being accessed by unauthorized resources.

**Examples**:
- Protect proprietary libraries/programs from piracy while allowing specific programs to use them
- Ensure only the "upgrade-firmware" command can upgrade system firmware (not "dd"), and protect the integrity of the "upgrade-firmware" command itself

**HoneyBest Solution**: HoneyBest supports bidirectional protection models that restrict both task-to-resource and resource-to-task access.

---

## Architecture

HoneyBest's core design focuses on capturing kernel activities triggered by user-space programs. Tracked activities are stored in list data structures that the security module uses to detect unexpected events.

**Key Design Principles:**

1. **Activity Tracking**: Kernel activities are captured and converted into structured data
2. **Granularity Control**: The size of data structures depends on the selected granularity level—higher granularity provides more precise control but requires more storage space
3. **Freeze/Unfreeze Model**: 
   - **Unfreeze mode**: System runs normally, all activities are tracked and added to the model
   - **Freeze mode**: System restricts all activities to those previously observed in the model
4. **Interactive Refinement**: Developers can fine-tune the model using an editor or interactive mode, which prompts for permission when new activities occur

**Lifecycle Workflow:**

1. Product development is completed
2. Enable unfreeze mode / Disable interaction mode
3. Run first End-to-End System Integration Test
4. Disable unfreeze mode / Enable interaction mode
5. Run second End-to-End System Integration Test or manually edit the model
6. Disable interaction mode (system is now locked down)

---

## Building and Installation

Similar to SELinux and AppArmor, HoneyBest is integrated into the Linux Security Module framework. To build HoneyBest:

### Prerequisites

For Debian/Ubuntu systems, install the required packages:

```bash
apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev bc
```

### Build Steps

1. **Create the HoneyBest directory**:
   ```bash
   mkdir -p [KERNEL_SOURCE]/security/honeybest
   ```

2. **Clone the source code**:
   ```bash
   cd [KERNEL_SOURCE]/security/honeybest
   git clone [repository-url] .
   ```

3. **Apply patches**:
   ```bash
   cd [KERNEL_SOURCE]/security/honeybest
   patch -p1 < Kconfig.patch
   patch -p1 < Makefile.patch
   ```

4. **Copy kernel configuration**:
   ```bash
   cat /boot/config-$(uname -r) > [KERNEL_SOURCE]/.config
   ```

5. **Configure the kernel**:
   ```bash
   cd [KERNEL_SOURCE]
   make menuconfig
   ```
   Navigate to: **Security options** → **HoneyBest LSM** and enable it.

6. **Build the kernel**:
   ```bash
   cd [KERNEL_SOURCE]
   make modules bzImage
   ```

7. **Install the kernel and modules**:
   ```bash
   sudo make install
   ```

---

## Configuration

### Enablement Options

HoneyBest starts in **deactivated/non-interactive mode** by default. To activate:

**Option 1: GRUB parameter**
```bash
# Add to GRUB_CMDLINE_LINUX in /etc/default/grub
hashlock.enabled=1
sudo update-grub
```

**Option 2: Initrd/ramfs stage**
```bash
echo 1 > /proc/sys/kernel/honeybest/enabled
```

**⚠️ Security Warning**: When compiled with `CONFIG_HONEYBEST_PROD=y`, HoneyBest cannot be deactivated after activation for security reasons. GRUB/initrd image updates must be tightly integrated with secure boot verification processes.

Once activated, kernel tracking activities are recorded in files under `/proc/honeybest/`. Monitor progress using standard file reading tools:

```bash
tail -f /proc/honeybest/binprm
cat /proc/honeybest/files
```

### Feature Selection

HoneyBest provides multiple feature sets for tracking different system perspectives. Enable individual features:

```bash
# Enable binary hash tracking
echo 1 > /proc/sys/kernel/honeybest/binprm

# Enable file operation tracking
echo 1 > /proc/sys/kernel/honeybest/files

# Enable socket tracking
echo 1 > /proc/sys/kernel/honeybest/socket

# Enable IPC tracking
echo 1 > /proc/sys/kernel/honeybest/ipc

# Enable inode tracking
echo 1 > /proc/sys/kernel/honeybest/inode

# Enable path tracking
echo 1 > /proc/sys/kernel/honeybest/path

# Enable task tracking
echo 1 > /proc/sys/kernel/honeybest/tasks

# Enable superblock tracking
echo 1 > /proc/sys/kernel/honeybest/sb

# Enable kernel module tracking
echo 1 > /proc/sys/kernel/honeybest/kmod

# Enable ptrace tracking
echo 1 > /proc/sys/kernel/honeybest/ptrace
```

See the [Activity Files](#activity-files) section for details on each feature.

### Locking Mode

Locking mode only takes effect when the enablement option is turned on (default: off). When enabled, only expected activities (those in the whitelist) are allowed to operate.

**Enable locking mode**:
```bash
echo 1 > /proc/sys/kernel/honeybest/locking
```

**Disable locking mode**:
```bash
echo 0 > /proc/sys/kernel/honeybest/locking
```

**Note**: Locking mode only works when the enablement option is active.

### Interactive Mode

Interactive mode allows real-time approval or denial of new activities. It only takes effect when enablement mode is active.

**Modes**:
- **Auto mode** (default): All activities are immediately tracked after enablement
- **Manual mode**: Requires the `libhoneybest-notify` package (under development) to prompt for user approval

**Enable interactive mode**:
```bash
echo 1 > /proc/sys/kernel/honeybest/interact
```

**Disable interactive mode**:
```bash
echo 0 > /proc/sys/kernel/honeybest/interact
```

**Note**: Interactive mode only works when:
- Enablement option is active
- Locking option is disabled

### Blacklist/Whitelist Mode

HoneyBest supports both whitelist and blacklist modes:

- **Whitelist mode** (default): All activities that pass through the list are allowed by default (similar to iptables ACCEPT policy)
- **Blacklist mode**: All activities that pass through the list are denied by default (similar to iptables REJECT policy)

**Enable blacklist mode**:
```bash
echo 1 > /proc/sys/kernel/honeybest/bl
```

**Enable whitelist mode**:
```bash
echo 0 > /proc/sys/kernel/honeybest/bl
```

### Granularity Levels

Granularity controls the precision of activity matching and tracking:

- **Level 0** (default): Suitable for most use cases
- **Level 1-2**: Higher precision, but:
  - Increased comparison time
  - Reduced system flexibility
  - Higher storage requirements

**Set granularity level**:
```bash
# Set to level 1
echo 1 > /proc/sys/kernel/honeybest/level

# Set to level 2
echo 2 > /proc/sys/kernel/honeybest/level

# Reset to default (level 0)
echo 0 > /proc/sys/kernel/honeybest/level
```

---

## Activity Configuration

All files in `/proc/honeybest/` track different system behaviors. Each file shares common fields, described below.

### Common Fields

All activity files contain the following common columns:

| Field | Description |
|-------|-------------|
| **NO** | Sequence number. HoneyBest compares activities starting from lower to higher numbers. |
| **FUNCTION** | Functional identification used to identify different activities. For example, under the 'socket' category, activities are labeled as `listen`, `bind`, `accept`, `open`, `setsocketopt`, etc. |
| **USER ID** | User identification used to reference the relationship between identity and function. Supports regular expressions (digits and `*` asterisk). |
| **ACTION** | Matching action: `A` (Accept) or `R` (Reject). Default value depends on the blacklist/whitelist option: Accept actions are appended when blacklist is 0 (whitelist mode); Reject actions are appended when blacklist is 1 (blacklist mode). |

### Activity Files

| File | Description |
|------|-------------|
| **binprm** | Tracks executable file path names, process UIDs, and calculates file content hash (SHA-1) to protect integrity. |
| **files** | Tracks ordinary file operations: `open`, `read`, `write`, `delete`, `rename`. |
| **inode** | Tracks inode operations: `create`, `delete`, `read`, `update`, `setxattr`, `getxattr`. |
| **path** | Tracks behavior of all file types: device nodes, hard/soft symbolic links, directories, pipes, Unix sockets. |
| **socket** | Tracks TCP/UDP/ICMP socket activities, including port numbers. |
| **task** | Tracks inter-process activities, such as signal exchange. |
| **sb** | Tracks superblock information. Activities such as `mount`, `umount`, `df` are recorded here. Highly related to `file` and `path` categories due to system registration in `/proc`. |
| **kmod** | Tracks Linux kernel module activities. Kernel `modprobe` operations are recorded here. |
| **ptrace** | Tracks ptrace activities for process debugging and monitoring. |
| **ipc** | Tracks Linux inter-process communication activities: shared memory, message queues, and semaphores. |
| **notify** | Notification channel between the security module and user-space applications. In interactive mode, unexpected events are saved here for user-space programs to notify users. Dialog pop-ups acquire security expert approval or denial of such activities. **Important**: When interactive mode is enabled, all events passing through this file can cause memory exhaustion. Therefore, designing a READ scheduler in the user-space program is vital. Content in the notify file is cleared after each READ operation. |

### Tuning Example

This example demonstrates how to configure HoneyBest for path tracking, which is highly relevant to symbolic link creation activities.

**Basic Workflow**:

1. **Enable HoneyBest LSM**:
   ```bash
   echo 1 > /proc/sys/kernel/honeybest/enabled
   ```

2. **Run system tests**: 
   ```bash
   # Example: Create a symbolic link
   ln -s /etc/services /tmp/services
   ```

3. **Disable HoneyBest before tuning whitelist**:
   ```bash
   echo 0 > /proc/sys/kernel/honeybest/enabled
   ```

4. **Review tracked activities**:
   ```bash
   cat /proc/honeybest/path | grep services
   ```

5. **Verify whitelist entry**: If the result shows:
   ```
   23 0 0 0 0 0 /etc/services /tmp/services
   ```
   This indicates the whitelist was automatically tracked.

**Advanced Case: Pattern Matching**

If your system test involves the udev daemon constantly creating new symbolic files with a pattern (e.g., `/dev/usb0`, `/dev/usb1`, ... `/dev/usbn` linking to `/dev/ttyUSB0`, `/dev/ttyUSB1`, etc.), you'll notice multiple lines related to `/dev/ttyUSB` in the path file. Use regular expressions to consolidate these entries:

1. **Disable HoneyBest LSM**:
   ```bash
   echo 0 > /proc/sys/kernel/honeybest/enabled
   ```

2. **Dump context to a file**:
   ```bash
   cat /proc/honeybest/path > /etc/hb/path
   ```

3. **Review the context** (see Figure 1 below)

4. **Process the file**:
   - Remove the first row (header) and first column (sequence numbers)
   - Eliminate all duplicate lines
   - Use regular expressions to consolidate patterns (see Figure 2 below)
   - Example: Replace `/dev/ttyUSB0`, `/dev/ttyUSB1`, `/dev/ttyUSB2` with `/dev/ttyUSB*`

5. **Re-apply the processed activities**:
   ```bash
   cat /etc/hb/path > /proc/honeybest/path
   ```

6. **Enable HoneyBest LSM**:
   ```bash
   echo 1 > /proc/sys/kernel/honeybest/enabled
   ```

**Figure 1: Example path file content**

| NO | FUNC | UID | MODE | SUID | GUID | DEV | SOURCE PATH | TARGET PATH |
|----|------|-----|------|------|------|-----|-------------|-------------|
| 0 | 23 | 0 | 0 | 0 | 0 | 0 | /dev/usb0 | /dev/ttyUSB0 |
| 1 | 23 | 0 | 0 | 0 | 0 | 0 | /dev/usb0 | /dev/ttyUSB1 |
| 2 | 23 | 0 | 0 | 0 | 0 | 0 | /dev/usb0 | /dev/ttyUSB2 |
| 3 | 20 | 0 | 420 | 0 | 0 | 0 | /etc/resolv.conf.dhclient-new.1115 | /etc/resolv.conf |

**Figure 2: Processed path file with regular expressions**

| FUNC | UID | MODE | SUID | GUID | DEV | SOURCE PATH | TARGET PATH |
|------|-----|------|------|------|-----|-------------|-------------|
| 23 | 0 | 0 | 0 | 0 | 0 | /dev/usb0 | /dev/ttyUSB* |
| 20 | 0 | 420 | 0 | 0 | 0 | /etc/resolv.conf.dhclient-new.* | /etc/resolv.conf |

**Verification**: Enable locking mode during system tests to verify the outcome. If system tests fail, disable locking mode and re-run the activities. Comparing file contexts will reveal which missing activities need to be added.

### Save and Restore

Saving and restoring HoneyBest LSM configuration is straightforward:

**Save configuration**:
```bash
# Save binary hash configuration
cat /proc/honeybest/binprm > /etc/hb/binprm

# Save file operations configuration
cat /proc/honeybest/files > /etc/hb/files

# Save path configuration
cat /proc/honeybest/path > /etc/hb/path
# ... repeat for other feature sets
```

**⚠️ Important**: After saving, you must process the files (remove headers, eliminate duplicates, apply regular expressions) as described in step 6.4 of the [Tuning Example](#tuning-example). HoneyBest LSM will not restore correctly if this step is not completed.

**Restore configuration**:
```bash
# Restore binary hash configuration
cat /etc/hb/binprm > /proc/honeybest/binprm

# Restore file operations configuration
cat /etc/hb/files > /proc/honeybest/files

# ... repeat for other feature sets
```

**Complete setup workflow**:
```bash
# 1. Restore configurations
cat /etc/hb/binprm > /proc/honeybest/binprm
cat /etc/hb/files > /proc/honeybest/files
# ... restore other feature sets

# 2. Enable feature sets
echo 1 > /proc/sys/kernel/honeybest/binprm
echo 1 > /proc/sys/kernel/honeybest/files
# ... enable other feature sets

# 3. Lock down HoneyBest (prevents further tracking)
echo 1 > /proc/sys/kernel/honeybest/locking

# 4. Enable HoneyBest
echo 1 > /proc/sys/kernel/honeybest/enabled
```

**Automation**: Add restore commands to `initrd` scripts or `/etc/rc.local` to automatically restore configuration on system boot.

---

## Use Cases

### Proprietary Shared Library Protection

This example demonstrates how to protect proprietary shared libraries from being copied or extracted from the system, even by root users.

**Protected Libraries**:
- `/usr/lib/arm-linux-gnueabihf/libtss2-sys.so.0.0.0`
- `/usr/lib/arm-linux-gnueabihf/libtss2-mu.so.0.0.0`
- `/usr/lib/arm-linux-gnueabihf/libcrypto.so.1.1`
- `/usr/lib/arm-linux-gnueabihf/libtss2-tcti-device.so.0.0.0`

**Prerequisites**:

1. **Secure Boot**: Enable and configure secure boot to prevent kernel and initramfs replacement
2. **Hardware Security Module (HSM)**: Use TPM or Arm TrustZone integrated into the secure boot process
3. **LUKS Encryption**: Reformat partitions with LUKS and bind LUKS keys to the HSM

**Configuration Steps**:

1. **Recompile kernel with production option**:
   ```bash
   # In kernel configuration
   CONFIG_HONEYBEST_PROD=y
   ```

2. **Add 'files' feature set configuration** to initramfs:
   Save configuration to `/etc/honeybest/files` in initramfs:
   
<img src="images/honeybest blacklist files shared libraries protection.JPG" width="1000" height="150" />

3. **Add 'binprm' feature set configuration** to initramfs:
   Save configuration to `/etc/honeybest/binprm` in initramfs:
   
<img src="images/honeybest blacklist binprm shared libraries protection.JPG" width="1000" height="150" />

4. **Add 'sb' feature set configuration** to initramfs:
   Save configuration to `/etc/honeybest/sb` in initramfs:
   
<img src="images/honeybest blacklist sb shared libraries protection.JPG" width="700" height="20" />

5. **Add initramfs script** (`init-top`) to run before chroot into LUKS filesystem:
   
<img src="images/honeybest blacklist setup shared libraries protection.JPG" width="700" height="500" />

This configuration ensures that:
- The libraries cannot be copied via `scp`, `cp`, or other file operations
- Only authorized processes can load and use the libraries
- Superblock operations are restricted to prevent filesystem-level access
- All protections are active before the root filesystem is mounted

---

## License

This software is licensed under the terms of the GNU General Public License version 2, as published by the Free Software Foundation. See the [LICENSE](LICENSE) file for details.

---

## Contributing

Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details on our code of conduct.

---

## Support

For issues, questions, or contributions, please refer to the project repository or contact the maintainers.

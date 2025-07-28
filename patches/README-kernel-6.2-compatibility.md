# HoneyBest Kernel 6.2 Compatibility Patch

This patch makes HoneyBest compatible with Linux kernel 6.2 by addressing several compatibility issues.

## Changes Made

### 1. Sysctl API Compatibility
- **Issue**: `register_sysctl_paths()` was deprecated and removed in kernel 6.1
- **Fix**: Added version-specific code to use the new `register_sysctl()` API for kernel 6.1+
- **Backward Compatibility**: Maintains support for older kernels (4.4+)

### 2. LSM Hook Function Signatures
- **Issue**: Some LSM hook function signatures changed in kernel 6.2
- **Fix**: Added version-specific function declarations for kernel 6.2+
- **Affected Functions**:
  - `honeybest_quotactl()`
  - `honeybest_sb_pivotroot()`
  - `honeybest_mount()`
  - `honeybest_umount()`
  - `honeybest_path_*()` functions
  - `honeybest_inode_getattr()`

### 3. Version-Specific Code Organization
- **Issue**: Mixed version checks made code hard to maintain
- **Fix**: Organized version-specific code with clear `#if LINUX_VERSION_CODE` blocks
- **Benefits**: Easier to maintain and understand compatibility requirements

## How to Apply the Patch

### Method 1: Using git apply
```bash
cd /path/to/linux/kernel/source
git apply /path/to/honeybest/patches/honeybest-kernel-6.2-compatibility.patch
```

### Method 2: Using patch command
```bash
cd /path/to/linux/kernel/source
patch -p1 < /path/to/honeybest/patches/honeybest-kernel-6.2-compatibility.patch
```

### Method 3: Manual Application
If the patch doesn't apply cleanly, you can manually apply the changes:

1. **Add version guards around sysctl structures** (lines ~192-200):
   ```c
   #if LINUX_VERSION_CODE < KERNEL_VERSION(6,1,0)
   static struct ctl_path honeybest_sysctl_path[] = {
       { .procname = "kernel", },
       { .procname = "honeybest", },
       { }
   };
   #endif
   ```

2. **Update sysctl registration** (lines ~703-720):
   ```c
   #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
   /* Use new sysctl API for kernel 6.1+ */
   struct ctl_table_header *hdr;
   
   hdr = register_sysctl("kernel/honeybest", honeybest_sysctl_table);
   if (!hdr) {
       pr_err("HoneyBest: Failed to register sysctl\n");
       return;
   }
   #else
   #ifdef CONFIG_SYSCTL
   if (!register_sysctl_paths(honeybest_sysctl_path, honeybest_sysctl_table))
       panic("HoneyBest: sysctl registration failed.\n");
   #endif
   #endif
   ```

3. **Add version-specific function declarations** for all affected LSM hooks

## Testing the Patch

After applying the patch:

1. **Compile the kernel**:
   ```bash
   make menuconfig  # Enable HoneyBest LSM
   make -j$(nproc)
   ```

2. **Test basic functionality**:
   ```bash
   # Check if HoneyBest is loaded
   cat /proc/lsm | grep honeybest
   
   # Test sysctl interface
   echo 1 > /proc/sys/kernel/honeybest/enabled
   cat /proc/sys/kernel/honeybest/enabled
   ```

3. **Verify proc interface**:
   ```bash
   ls /proc/honeybest/
   cat /proc/honeybest/files
   ```

## Supported Kernel Versions

- **Minimum**: Linux kernel 4.4.0
- **Primary Target**: Linux kernel 4.9.0 - 6.2.x
- **New Support**: Linux kernel 6.1.0 - 6.2.x

## Troubleshooting

### Compilation Errors
If you encounter compilation errors:

1. **Check kernel version**: Ensure you're using a supported kernel version
2. **Verify patch application**: Make sure the patch was applied correctly
3. **Check dependencies**: Ensure all required kernel headers are available

### Runtime Issues
If HoneyBest doesn't work at runtime:

1. **Check kernel logs**: `dmesg | grep -i honeybest`
2. **Verify LSM loading**: `cat /proc/lsm`
3. **Test sysctl interface**: Check if `/proc/sys/kernel/honeybest/` exists

## Contributing

If you encounter issues with this patch:

1. Check the kernel version you're using
2. Verify the patch was applied correctly
3. Check kernel compilation logs for specific errors
4. Report issues with detailed information about your environment

## License

This patch is provided under the same license as the original HoneyBest code (GPL v2). 
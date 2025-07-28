#!/bin/bash

# HoneyBest Kernel 6.2 Compatibility Patch Application Script
# This script helps apply the compatibility patch for Linux kernel 6.2

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check kernel version
check_kernel_version() {
    local kernel_version=$(uname -r)
    print_status "Detected kernel version: $kernel_version"
    
    # Extract major.minor version
    local major_minor=$(echo $kernel_version | cut -d. -f1,2)
    local major=$(echo $major_minor | cut -d. -f1)
    local minor=$(echo $major_minor | cut -d. -f2)
    
    if [ "$major" -eq 6 ] && [ "$minor" -ge 1 ]; then
        print_success "Kernel version is compatible with this patch"
        return 0
    elif [ "$major" -eq 6 ] && [ "$minor" -eq 0 ]; then
        print_warning "Kernel version 6.0 detected - patch may not be necessary but should work"
        return 0
    else
        print_warning "Kernel version $major_minor detected - this patch is designed for kernel 6.1+"
        print_warning "The patch will still work but may not be necessary"
        return 0
    fi
}

# Function to find kernel source
find_kernel_source() {
    local kernel_version=$(uname -r)
    local possible_paths=(
        "/usr/src/linux-headers-$kernel_version"
        "/usr/src/linux-source-$kernel_version"
        "/usr/src/linux"
        "/lib/modules/$kernel_version/build"
        "/lib/modules/$kernel_version/source"
    )
    
    for path in "${possible_paths[@]}"; do
        if [ -d "$path" ] && [ -f "$path/Makefile" ]; then
            print_success "Found kernel source at: $path"
            echo "$path"
            return 0
        fi
    done
    
    print_error "Could not find kernel source directory"
    print_status "Please specify the kernel source path manually"
    return 1
}

# Function to backup original file
backup_file() {
    local file="$1"
    local backup="${file}.backup.$(date +%Y%m%d_%H%M%S)"
    
    if [ -f "$file" ]; then
        cp "$file" "$backup"
        print_success "Backed up original file to: $backup"
    fi
}

# Function to apply patch
apply_patch() {
    local kernel_source="$1"
    local patch_file="$2"
    
    print_status "Applying patch to kernel source: $kernel_source"
    
    # Check if patch file exists
    if [ ! -f "$patch_file" ]; then
        print_error "Patch file not found: $patch_file"
        return 1
    fi
    
    # Change to kernel source directory
    cd "$kernel_source"
    
    # Try to apply patch
    if command_exists git && [ -d ".git" ]; then
        print_status "Using git apply..."
        if git apply "$patch_file"; then
            print_success "Patch applied successfully using git"
            return 0
        else
            print_warning "git apply failed, trying patch command..."
        fi
    fi
    
    if command_exists patch; then
        print_status "Using patch command..."
        if patch -p1 < "$patch_file"; then
            print_success "Patch applied successfully using patch command"
            return 0
        else
            print_error "patch command failed"
            return 1
        fi
    else
        print_error "Neither git nor patch command found"
        return 1
    fi
}

# Function to verify patch application
verify_patch() {
    local kernel_source="$1"
    local honeybest_file="$kernel_source/security/honeybest/honeybest.c"
    
    if [ -f "$honeybest_file" ]; then
        if grep -q "LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)" "$honeybest_file"; then
            print_success "Patch verification successful - version-specific code found"
            return 0
        else
            print_warning "Patch verification failed - version-specific code not found"
            return 1
        fi
    else
        print_error "HoneyBest source file not found at expected location"
        return 1
    fi
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -k, --kernel-source PATH    Specify kernel source directory"
    echo "  -p, --patch-file PATH       Specify patch file path"
    echo "  -h, --help                  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Auto-detect kernel source"
    echo "  $0 -k /usr/src/linux-6.2.0           # Specify kernel source"
    echo "  $0 -p /path/to/custom-patch.patch    # Specify custom patch file"
}

# Main script
main() {
    local kernel_source=""
    local patch_file=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -k|--kernel-source)
                kernel_source="$2"
                shift 2
                ;;
            -p|--patch-file)
                patch_file="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    print_status "HoneyBest Kernel 6.2 Compatibility Patch Application Script"
    echo ""
    
    # Check kernel version
    check_kernel_version
    echo ""
    
    # Find kernel source if not specified
    if [ -z "$kernel_source" ]; then
        print_status "Auto-detecting kernel source..."
        kernel_source=$(find_kernel_source)
        if [ $? -ne 0 ]; then
            print_error "Please specify kernel source directory with -k option"
            exit 1
        fi
    fi
    
    # Verify kernel source exists
    if [ ! -d "$kernel_source" ] || [ ! -f "$kernel_source/Makefile" ]; then
        print_error "Invalid kernel source directory: $kernel_source"
        exit 1
    fi
    
    # Set default patch file if not specified
    if [ -z "$patch_file" ]; then
        patch_file="$(dirname "$0")/honeybest-kernel-6.2-compatibility.patch"
    fi
    
    # Check if HoneyBest is already in kernel source
    local honeybest_dir="$kernel_source/security/honeybest"
    if [ ! -d "$honeybest_dir" ]; then
        print_error "HoneyBest directory not found in kernel source"
        print_status "Please ensure HoneyBest is properly integrated into the kernel source first"
        exit 1
    fi
    
    # Backup original file
    local honeybest_file="$honeybest_dir/honeybest.c"
    if [ -f "$honeybest_file" ]; then
        backup_file "$honeybest_file"
    fi
    
    # Apply patch
    if apply_patch "$kernel_source" "$patch_file"; then
        echo ""
        print_success "Patch applied successfully!"
        
        # Verify patch
        if verify_patch "$kernel_source"; then
            echo ""
            print_success "Patch verification successful!"
            print_status "You can now compile the kernel with HoneyBest support"
            print_status "Run: make menuconfig (enable HoneyBest LSM)"
            print_status "Then: make -j$(nproc)"
        else
            echo ""
            print_warning "Patch verification failed - please check manually"
        fi
    else
        echo ""
        print_error "Failed to apply patch"
        print_status "You may need to apply the changes manually"
        print_status "See README-kernel-6.2-compatibility.md for manual instructions"
        exit 1
    fi
}

# Run main function
main "$@" 
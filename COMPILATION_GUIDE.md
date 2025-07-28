# HoneyBest Compilation Guide for macOS

## Overview
HoneyBest is a Linux Security Module (LSM) that needs to be compiled within a Linux kernel source tree. Since you're on macOS, here are several approaches to compile it.

## Prerequisites

### Option 1: Docker (Recommended)
```bash
# Install Docker Desktop for Mac
# Download from: https://www.docker.com/products/docker-desktop

# Or install via Homebrew
brew install --cask docker
```

### Option 2: Virtual Machine
- **Parallels Desktop** (Commercial)
- **VMware Fusion** (Commercial)
- **VirtualBox** (Free)

### Option 3: Cross-compilation
- **Homebrew** for package management
- **Linux kernel headers** for target architecture

## Method 1: Docker Compilation (Recommended)

### Step 1: Create Dockerfile
```bash
# Create a Dockerfile in the honeybest directory
cat > Dockerfile << 'EOF'
FROM ubuntu:20.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install required packages
RUN apt-get update && apt-get install -y \
    build-essential \
    libncurses-dev \
    bison \
    flex \
    libssl-dev \
    libelf-dev \
    bc \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /honeybest

# Copy source code
COPY . .

# Create compilation script
RUN echo '#!/bin/bash\n\
set -e\n\
echo "Setting up kernel source..."\n\
KERNEL_VERSION=${1:-5.15}\n\
KERNEL_SRC="/usr/src/linux-headers-${KERNEL_VERSION}-generic"\n\
\n\
if [ ! -d "$KERNEL_SRC" ]; then\n\
    echo "Installing kernel headers for version ${KERNEL_VERSION}..."\n\
    apt-get update\n\
    apt-get install -y linux-headers-${KERNEL_VERSION}-generic\n\
fi\n\
\n\
echo "Copying HoneyBest to kernel source..."\n\
cp -r /honeybest ${KERNEL_SRC}/security/\n\
cd ${KERNEL_SRC}/security/honeybest\n\
\n\
echo "Applying kernel configuration patch..."\n\
if [ -f "patches/honeybest-kernel-option.patch" ]; then\n\
    patch -p1 < patches/honeybest-kernel-option.patch\n\
fi\n\
\n\
echo "Applying kernel 6.2 compatibility patch..."\n\
if [ -f "patches/honeybest-kernel-6.2-compatibility.patch" ]; then\n\
    patch -p1 < patches/honeybest-kernel-6.2-compatibility.patch\n\
fi\n\
\n\
echo "Building HoneyBest module..."\n\
cd ${KERNEL_SRC}\n\
make M=security/honeybest modules\n\
\n\
echo "Compilation completed successfully!"\n\
echo "Module location: ${KERNEL_SRC}/security/honeybest/honeybest.ko"\n\
' > /compile.sh && chmod +x /compile.sh

# Default command
CMD ["/bin/bash"]
EOF
```

### Step 2: Build and Run Docker Container
```bash
# Build the Docker image
docker build -t honeybest-compiler .

# Run the container with kernel source mounted
docker run -it --rm \
    -v $(pwd):/honeybest \
    -v /usr/src:/usr/src \
    honeybest-compiler

# Inside the container, run:
./compile.sh 5.15  # or your target kernel version
```

## Method 2: Virtual Machine Compilation

### Step 1: Set up Ubuntu VM
1. Download Ubuntu 20.04 LTS ISO
2. Create VM with at least 4GB RAM and 20GB disk
3. Install required packages:
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    libncurses-dev \
    bison \
    flex \
    libssl-dev \
    libelf-dev \
    bc \
    git \
    linux-headers-$(uname -r)
```

### Step 2: Compile HoneyBest
```bash
# Clone or copy HoneyBest source to VM
cd /usr/src/linux-headers-$(uname -r)
sudo mkdir -p security/honeybest
sudo cp -r /path/to/honeybest/* security/honeybest/

# Apply patches
cd security/honeybest
sudo patch -p1 < patches/honeybest-kernel-option.patch
sudo patch -p1 < patches/honeybest-kernel-6.2-compatibility.patch

# Compile
cd /usr/src/linux-headers-$(uname -r)
sudo make M=security/honeybest modules
```

## Method 3: Cross-compilation (Advanced)

### Step 1: Install Cross-compilation Tools
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install cross-compilation tools
brew install gcc
brew install binutils
brew install linux-headers

# For ARM64 targets
brew install aarch64-linux-gnu-binutils
```

### Step 2: Set up Cross-compilation Environment
```bash
# Create cross-compilation script
cat > cross-compile.sh << 'EOF'
#!/bin/bash

# Set cross-compilation variables
export ARCH=x86_64  # or arm64
export CROSS_COMPILE=x86_64-linux-gnu-  # or aarch64-linux-gnu-
export KERNEL_SRC=/path/to/linux-kernel-source

# Compile HoneyBest
cd $KERNEL_SRC
make M=security/honeybest modules
EOF

chmod +x cross-compile.sh
```

## Testing the Compiled Module

### Load the Module (on Linux system)
```bash
# Copy the compiled module to target system
sudo insmod honeybest.ko

# Check if module is loaded
lsmod | grep honeybest

# Check module parameters
cat /proc/sys/kernel/honeybest/enabled

# Enable HoneyBest
echo 1 > /proc/sys/kernel/honeybest/enabled
```

### Verify Installation
```bash
# Check if proc entries are created
ls -la /proc/honeybest/

# Check if sysctl entries are available
sysctl kernel.honeybest.enabled

# Test basic functionality
echo 1 > /proc/sys/kernel/honeybest/enabled
cat /proc/honeybest/files
```

## Troubleshooting

### Common Issues

1. **Kernel headers not found**
   ```bash
   sudo apt-get install linux-headers-$(uname -r)
   ```

2. **Missing dependencies**
   ```bash
   sudo apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev bc
   ```

3. **Patch application fails**
   ```bash
   # Check patch compatibility
   patch --dry-run -p1 < patches/honeybest-kernel-6.2-compatibility.patch
   ```

4. **Module compilation errors**
   ```bash
   # Check kernel version compatibility
   uname -r
   # Ensure patches match your kernel version
   ```

### Debug Mode Compilation
```bash
# Enable debug output
export DEBUG=y
make M=security/honeybest modules
```

## Next Steps

1. **Test on target system**: Load and test the module on your target Linux system
2. **Configure HoneyBest**: Set up whitelist/blacklist policies
3. **Integration testing**: Test with your specific use cases
4. **Performance tuning**: Adjust granularity levels as needed

## Support

- Check the main README.md for detailed usage instructions
- Review the kernel 6.2 compatibility patch documentation
- Test thoroughly before deploying to production systems 
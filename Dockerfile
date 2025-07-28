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
    curl \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /honeybest

# Copy source code
COPY . .

# Create compilation script
RUN echo '#!/bin/bash\n\
set -e\n\
echo "=== HoneyBest Compilation Script ==="\n\
echo "Setting up kernel source..."\n\
KERNEL_VERSION=${1:-5.15}\n\
KERNEL_SRC="/usr/src/linux-headers-${KERNEL_VERSION}-generic"\n\
\n\
echo "Target kernel version: ${KERNEL_VERSION}"\n\
echo "Kernel source path: ${KERNEL_SRC}"\n\
\n\
if [ ! -d "$KERNEL_SRC" ]; then\n\
    echo "Installing kernel headers for version ${KERNEL_VERSION}..."\n\
    apt-get update\n\
    apt-get install -y linux-headers-${KERNEL_VERSION}-generic\n\
fi\n\
\n\
if [ ! -d "$KERNEL_SRC" ]; then\n\
    echo "ERROR: Kernel headers not found for version ${KERNEL_VERSION}"\n\
    echo "Available kernel headers:"\n\
    ls -la /usr/src/linux-headers-*\n\
    exit 1\n\
fi\n\
\n\
echo "Copying HoneyBest to kernel source..."\n\
cp -r /honeybest ${KERNEL_SRC}/security/\n\
cd ${KERNEL_SRC}/security/honeybest\n\
\n\
echo "Applying kernel configuration patch..."\n\
if [ -f "patches/honeybest-kernel-option.patch" ]; then\n\
    echo "Applying honeybest-kernel-option.patch..."\n\
    patch -p1 < patches/honeybest-kernel-option.patch\n\
else\n\
    echo "Warning: honeybest-kernel-option.patch not found"\n\
fi\n\
\n\
echo "Applying kernel 6.2 compatibility patch..."\n\
if [ -f "patches/honeybest-kernel-6.2-compatibility.patch" ]; then\n\
    echo "Applying honeybest-kernel-6.2-compatibility.patch..."\n\
    patch -p1 < patches/honeybest-kernel-6.2-compatibility.patch\n\
else\n\
    echo "Warning: honeybest-kernel-6.2-compatibility.patch not found"\n\
fi\n\
\n\
echo "Building HoneyBest module..."\n\
cd ${KERNEL_SRC}\n\
make M=security/honeybest modules\n\
\n\
if [ $? -eq 0 ]; then\n\
    echo "=== Compilation completed successfully! ==="\n\
    echo "Module location: ${KERNEL_SRC}/security/honeybest/honeybest.ko"\n\
    echo "Module size: $(ls -lh ${KERNEL_SRC}/security/honeybest/honeybest.ko | awk '\''{print $5}'\'')"\n\
    echo ""\n\
    echo "To copy the module to your host system:"\n\
    echo "docker cp <container_id>:/usr/src/linux-headers-${KERNEL_VERSION}-generic/security/honeybest/honeybest.ko ./"\n\
else\n\
    echo "=== Compilation failed! ==="\n\
    exit 1\n\
fi\n\
' > /compile.sh && chmod +x /compile.sh

# Create a helper script for different kernel versions
RUN echo '#!/bin/bash\n\
echo "Available kernel versions:"\n\
ls -1 /usr/src/linux-headers-* 2>/dev/null | sed "s|/usr/src/linux-headers-||" | sed "s|-generic||" || echo "No kernel headers found"\n\
echo ""\n\
echo "Usage: ./compile.sh <kernel_version>"\n\
echo "Example: ./compile.sh 5.15"\n\
' > /list-kernels.sh && chmod +x /list-kernels.sh

# Default command
CMD ["/bin/bash"] 
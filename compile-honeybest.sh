#!/bin/bash

# HoneyBest Compilation Script for macOS
# This script automates the compilation process using Docker

set -e

echo "🐝 HoneyBest Compilation Script for macOS"
echo "=========================================="

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed or not in PATH"
    echo ""
    echo "Please install Docker Desktop for Mac:"
    echo "https://www.docker.com/products/docker-desktop"
    echo ""
    echo "Or install via Homebrew:"
    echo "brew install --cask docker"
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "❌ Docker is not running"
    echo "Please start Docker Desktop and try again"
    exit 1
fi

echo "✅ Docker is available and running"

# Get kernel version from user
echo ""
echo "Which Linux kernel version do you want to compile for?"
echo "Common versions: 5.15, 6.1, 6.2, 6.3"
read -p "Enter kernel version (default: 5.15): " KERNEL_VERSION
KERNEL_VERSION=${KERNEL_VERSION:-5.15}

echo ""
echo "🔨 Building Docker image..."
docker build -t honeybest-compiler .

if [ $? -ne 0 ]; then
    echo "❌ Docker build failed"
    exit 1
fi

echo "✅ Docker image built successfully"

# Create output directory
mkdir -p compiled_modules

echo ""
echo "🚀 Starting compilation for kernel ${KERNEL_VERSION}..."
echo "This may take several minutes..."

# Run the compilation
CONTAINER_ID=$(docker run -d honeybest-compiler /compile.sh ${KERNEL_VERSION})

# Show compilation progress
echo "📊 Compilation in progress..."
docker logs -f ${CONTAINER_ID} &
LOGS_PID=$!

# Wait for container to finish
docker wait ${CONTAINER_ID}
EXIT_CODE=$(docker inspect ${CONTAINER_ID} --format='{{.State.ExitCode}}')

# Stop log following
kill $LOGS_PID 2>/dev/null || true

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "✅ Compilation completed successfully!"
    
    # Copy the compiled module
    echo "📁 Copying compiled module..."
    docker cp ${CONTAINER_ID}:/usr/src/linux-headers-${KERNEL_VERSION}-generic/security/honeybest/honeybest.ko ./compiled_modules/
    
    if [ -f "./compiled_modules/honeybest.ko" ]; then
        echo "✅ Module copied to: ./compiled_modules/honeybest.ko"
        echo ""
        echo "📊 Module information:"
        ls -lh ./compiled_modules/honeybest.ko
        echo ""
        echo "🎉 Ready to use! Copy the module to your Linux system and load it with:"
        echo "   sudo insmod honeybest.ko"
    else
        echo "❌ Failed to copy module from container"
    fi
else
    echo ""
    echo "❌ Compilation failed with exit code: $EXIT_CODE"
    echo ""
    echo "📋 Full compilation log:"
    docker logs ${CONTAINER_ID}
fi

# Clean up container
docker rm ${CONTAINER_ID} >/dev/null 2>&1 || true

echo ""
echo "🏁 Compilation process completed" 
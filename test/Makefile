
PWD:=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
TEST_ROOT:=$(PWD)
SRC_ROOT:=$(abspath $(PWD)/../)
BUILD_ROOT:=$(abspath $(PWD)/build/)
BIN_ROOT:=$(abspath $(PWD)/bin/)
COMPILE_FLAGS:=-iquote $(SRC_ROOT)

UNITTEST_ROOT:=$(abspath $(TEST_ROOT)/unittest/)
UNITTEST_MOCK_ROOT:=$(abspath $(UNITTEST_ROOT)/mocks/)
UNITTEST_TEST_ROOT:=$(abspath $(UNITTEST_ROOT)/tests/)
UNITTEST_INCLUDE_ROOT:=$(abspath $(UNITTEST_ROOT)/includes/)
UNITTEST_KERNEL_ARCH:=x86
UNITTEST_KERNEL_CONFIG:=x86_64_defconfig
UNITTEST_INCLUDE_KERNEL_ROOT?=$(abspath $(UNITTEST_INCLUDE_ROOT)/linux)
UNITTEST_BUILD_ROOT:=$(abspath $(BUILD_ROOT)/unittest/)
UNITTEST_BIN_ROOT:=$(abspath $(BIN_ROOT)/unittest/)
UNITTEST_COMPILE_FLAGS:=-I $(UNITTEST_ROOT)/ \
			-I $(UNITTEST_INCLUDE_KERNEL_ROOT)/include/ \
			-I $(UNITTEST_INCLUDE_KERNEL_ROOT)/include/uapi/ \
			-I $(UNITTEST_INCLUDE_KERNEL_ROOT)/arch/$(UNITTEST_KERNEL_ARCH)/include/ \
			-I $(UNITTEST_INCLUDE_KERNEL_ROOT)/arch/$(UNITTEST_KERNEL_ARCH)/include/generated/ \
			-I $(UNITTEST_INCLUDE_KERNEL_ROOT)/arch/$(UNITTEST_KERNEL_ARCH)/include/uapi/ \
			-include generated/autoconf.h \
			-include linux/kconfig.h \
			-include linux/types.h \
			-D _SYS_TYPES_H \
			-D _SYS_WAIT_H \
			-D _STRINGS_H \
			-D __KERNEL__

.SILENT:
.PHONY: unittest unittest-clean

unittest:
	echo "#######################################################"
	echo "# Executing Unittest on ${UNITTEST_KERNEL_ARCH} architecture #"
	echo "#######################################################"
# Prepare Kernel Header
	if [ ! -d $(UNITTEST_INCLUDE_KERNEL_ROOT) ]; then \
		echo "Please provide kernel header files in ${UNITTEST_INCLUDE_KERNEL_ROOT}, or"; \
		echo "provide path to kernel header files by UNITTEST_INCLUDE_KERNEL_ROOT variable"; \
		exit 255; \
	elif [ ! -d $(UNITTEST_INCLUDE_KERNEL_ROOT)/include/generated ]; then \
		make -C $(UNITTEST_INCLUDE_KERNEL_ROOT) olddefconfig \
			-o $(UNITTEST_INCLUDE_KERNEL_ROOT)/arch/$(UNITTEST_KERNEL_ARCH)/configs/$(UNITTEST_KERNEL_CONFIG); \
		make -C $(UNITTEST_INCLUDE_KERNEL_ROOT) prepare; \
	fi
# Build Test Code
	echo "##########################"
	echo "# Building Unittest Code #"
	echo "##########################"
	mkdir -p $(UNITTEST_BUILD_ROOT) $(UNITTEST_BIN_ROOT)
	for test in $$(find ${UNITTEST_TEST_ROOT} -name test_* -type d); do \
		make -C $$test SRC_ROOT="$(SRC_ROOT)" \
			MOCK_ROOT="$(UNITTEST_MOCK_ROOT)" \
			TEST_ROOT="$(UNITTEST_TEST_ROOT)" \
			BUILD_ROOT="$(UNITTEST_BUILD_ROOT)" \
			TEST_BIN_ROOT="$(UNITTEST_BIN_ROOT)" \
			CFLAGS="$(CFLAGS) $(UNITTEST_COMPILE_FLAGS) $(COMPILE_FLAGS)" \
			CXXFLAGS="$(CXXFLAGS) $(UNITTEST_COMPILE_FLAGS) $(COMPILE_FLAGS)"; \
	done
# Run Unittest
	for test in $$(find $(UNITTEST_BIN_ROOT) -type f -executable); do\
		echo "### $${test}"; \
		$${test}; \
	done

unittest-clean:
	rm -rf $(UNITTEST_BUILD_ROOT) $(UNITTEST_BIN_ROOT)


PWD:=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))

SRC_SRC:=$(SRC_ROOT)/regex.c
TEST_SRC:=$(wildcard $(PWD)/*.cpp) $(wildcard $(PWD)/*.c) $(TEST_ROOT)/common/unittest_common.c
MOCK_SRC:=$(MOCK_ROOT)/linux/kernel/printk/mock_printk.c \
	$(MOCK_ROOT)/linux/mock_global_variables.c

SRC_CFLAGS:=-D"main(...)=__main__(__VA_ARGS__)"
TEST_CFLAGS:=

.SILENT:
.PHONY: all

BUILD_PATH:=$(subst $(TEST_ROOT),$(BUILD_ROOT),$(PWD))
ALL_SRC:=$(SRC_SRC) $(TEST_SRC) $(MOCK_SRC)
ALL_OBJ:=$(addprefix $(BUILD_PATH)/, $(notdir $(patsubst %.cpp,%.o,$(patsubst %.c,%.o,$(ALL_SRC)))))

all:
	mkdir -p $(BUILD_PATH)
	for src_file in $(filter %.c,$(SRC_SRC)); do \
		gcc -c $(CFLAGS) $(TEST_CFLAGS) $(SRC_CFLAGS) $(CPPUTEST_CFLAGS) \
			-o $(BUILD_PATH)/$$(basename $$src_file .c).o $$src_file; \
	done
	for src_file in $(filter %.cpp,$(SRC_SRC)); do \
		g++ -c $(CXXFLAGS) $(TEST_CFLAGS) $(SRC_CXXFLAGS) $(CPPUTEST_CXXFLAGS) \
			-o $(BUILD_PATH)/$$(basename $$src_file .cpp).o $$src_file; \
	done
	for src_file in $(filter %.c,$(TEST_SRC) $(MOCK_SRC)); do \
		gcc -c $(CFLAGS) $(TEST_CFLAGS) $(CPPUTEST_CFLAGS) \
		-o $(BUILD_PATH)/$$(basename $$src_file .c).o $$src_file; \
	done
	for src_file in $(filter %.cpp,$(TEST_SRC) $(MOCK_SRC)); do \
		g++ -c $(CXXFLAGS) $(TEST_CFLAGS) $(CPPUTEST_CXXFLAGS) \
			-o $(BUILD_PATH)/$$(basename $$src_file .cpp).o $$src_file; \
	done
	g++ -o $(TEST_BIN_ROOT)/$(shell basename $(PWD)) $(ALL_OBJ) \
		$$(objdump -t $(ALL_OBJ) | grep ".text.*__wrap_" | sed -e "s/.*.text.*__wrap_\(.*\)/-Wl,--wrap=\1/")

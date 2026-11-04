# Compile only. Package preparation and target execution are separate commands.
EXAMPLE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
STATEAFL_ROOT := $(abspath $(EXAMPLE_DIR)/../../..)
STATEAFL_CC ?= $(STATEAFL_ROOT)/afl-clang-fast
BUILD_DIR ?= /tmp/stateafl-minimal-modbus-build
CFLAGS ?= -O1 -g -Wall -Wextra -Werror

.PHONY: build-only
build-only: $(BUILD_DIR)/fixture_server

$(BUILD_DIR)/fixture_server: $(EXAMPLE_DIR)/fixture_server.c $(STATEAFL_ROOT)/afl-clang-fast \
  $(STATEAFL_ROOT)/afl-llvm-pass.so $(STATEAFL_ROOT)/afl-llvm-rt.o \
  $(STATEAFL_ROOT)/afl-llvm-rt-state-tracer.o $(STATEAFL_ROOT)/llvm_mode/state-tracer.h
	mkdir -p "$(@D)"
	"$(STATEAFL_CC)" $(CFLAGS) "$<" -o "$@"

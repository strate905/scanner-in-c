CC      := $(shell command -v clang 2>/dev/null)
ifeq ($(CC),)
CC      := cc
endif
CFLAGS  ?= -std=c11 -Wall -Wextra -pedantic -pthread
LDFLAGS ?=
LDLIBS  ?= -pthread

SRC_DIR := src
BUILD_DIR := build
BUILD_STAMP := $(BUILD_DIR)/.dir
TARGET := $(BUILD_DIR)/scanner

SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))
TEST_BUILD_DIR := $(BUILD_DIR)/tests
TEST_SOURCES := $(wildcard tests/*.c)
TEST_OBJECTS := $(patsubst tests/%.c,$(TEST_BUILD_DIR)/%.o,$(TEST_SOURCES))
TEST_BIN := $(TEST_BUILD_DIR)/test_cli

.PHONY: all build clean run test

all: build

build: $(TARGET)

$(TARGET): $(OBJECTS) | $(BUILD_STAMP)
	CCACHE_DISABLE=1 $(CC) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILD_STAMP):
	mkdir -p $(BUILD_DIR)
	touch $(BUILD_STAMP)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_STAMP)
	CCACHE_DISABLE=1 $(CC) $(CFLAGS) -Iinclude -c $< -o $@

run: build
	$(TARGET) $(ARGS)

$(TEST_BUILD_DIR)/%.o: tests/%.c | $(BUILD_STAMP)
	mkdir -p $(TEST_BUILD_DIR)
	CCACHE_DISABLE=1 $(CC) $(CFLAGS) -Iinclude -c $< -o $@

$(TEST_BIN): $(TEST_BUILD_DIR)/test_cli.o $(BUILD_DIR)/cli.o | $(BUILD_STAMP)
	mkdir -p $(TEST_BUILD_DIR)
	CCACHE_DISABLE=1 $(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

test: $(TEST_BIN)
	$(TEST_BIN)

clean:
	rm -rf $(BUILD_DIR)

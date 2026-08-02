CC ?= gcc
PKG_CONFIG ?= pkg-config
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

TARGET := wcat
SRC := $(wildcard src/*.c)
OBJ := $(SRC:.c=.o)
DEP := $(OBJ:.o=.d)
TEST_STUBS := tests/stubs/socks5_stub tests/stubs/http_connect_stub
UNIT_TESTS := tests/unit_cli
FUZZ_TARGETS := tests/fuzz_cli
FUZZ_CORPUS ?= tests/corpus/cli
FUZZ_TIME ?= 3600

OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null || printf '%s' '-lssl -lcrypto')

CPPFLAGS ?=
CFLAGS ?= -O2 -g
WARNFLAGS := -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -Wmissing-prototypes
CPPFLAGS += -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -Iinclude $(OPENSSL_CFLAGS)
LDFLAGS ?=
LDLIBS += $(OPENSSL_LIBS)

.PHONY: all debug asan analyze fuzz-harness fuzz-cli test unit integration clean install uninstall

all: $(TARGET)

debug: CFLAGS := -O0 -g3
debug: CPPFLAGS += -DWCAT_DEBUG=1
debug: $(TARGET)

asan: CFLAGS := -O1 -g3 -fsanitize=address,undefined -fno-omit-frame-pointer
asan: LDFLAGS += -fsanitize=address,undefined
asan: clean $(TARGET)

analyze: CC := clang
analyze:
	$(CC) --analyze -Xanalyzer -analyzer-output=text $(CPPFLAGS) $(WARNFLAGS) src/*.c

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNFLAGS) -MMD -MP -c -o $@ $<

tests/stubs/%: tests/stubs/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNFLAGS) -o $@ $<

tests/unit_cli: tests/unit_cli.c src/cli.c src/util.c src/access.c src/log.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNFLAGS) -o $@ $^

tests/fuzz_cli: tests/fuzz_cli.c src/cli.c src/util.c src/access.c src/log.c
	clang $(CPPFLAGS) -g -O1 -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer $(WARNFLAGS) -o $@ $^

fuzz-harness: $(FUZZ_TARGETS)

fuzz-cli: tests/fuzz_cli
	mkdir -p $(FUZZ_CORPUS)
	./tests/fuzz_cli $(FUZZ_CORPUS) -max_total_time=$(FUZZ_TIME) -print_final_stats=1

unit: $(UNIT_TESTS)
	./tests/unit_cli

integration: $(TARGET) $(TEST_STUBS)
	./tests/integration.sh

test: unit integration

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -d $(DESTDIR)$(MANDIR)/man1
	install -m 0644 docs/wcat.1 $(DESTDIR)$(MANDIR)/man1/wcat.1

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(MANDIR)/man1/wcat.1

clean:
	rm -f $(TARGET) $(OBJ) $(DEP) $(TEST_STUBS) $(UNIT_TESTS) $(FUZZ_TARGETS) *.plist

-include $(DEP)

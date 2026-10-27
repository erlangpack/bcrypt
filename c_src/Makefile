# Based on c_src.mk from erlang.mk by Loic Hoguin <essen@ninenines.eu>

CURDIR := .
BASEDIR := ..

PROJECT ?= $(notdir $(BASEDIR))
PROJECT := $(strip $(PROJECT))

ERTS_INCLUDE_DIR ?= $(shell erl -noshell -eval 'io:format("~s/erts-~s/include/", [code:root_dir(), erlang:system_info(version)]).' -s erlang halt)
ERL_INTERFACE_INCLUDE_DIR ?= $(shell erl -noshell -eval 'io:format("~s", [code:lib_dir(erl_interface, include)]).' -s erlang halt)
ERL_INTERFACE_LIB_DIR ?= $(shell erl -noshell -eval 'io:format("~s", [code:lib_dir(erl_interface, lib)]).' -s erlang halt)

C_SRC_DIR = $(CURDIR)
C_SRC_NIF = $(CURDIR)/../priv/bcrypt_nif.so
C_SRC_PORT = $(CURDIR)/../priv/bcrypt

# DRV_LDFLAGS = -shared $(ERL_LDFLAGS) -lpthread
DRV_CFLAGS = -Ic_src -Wall -O3 -fPIC $(ERL_CFLAGS)

# System type and C compiler/flags.

UNAME_SYS := $(shell uname -s)
ifeq ($(UNAME_SYS), Darwin)
	CC ?= cc
	CFLAGS ?= -O3 -std=c99 -Wall -Wmissing-prototypes
	LDFLAGS += -flat_namespace -undefined suppress
	DRV_LDFLAGS = -flat_namespace -undefined suppress $(ERL_LDFLAGS)
else ifeq ($(UNAME_SYS), Linux)
	CC ?= gcc
	CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes -D_DEFAULT_SOURCE
	DRV_LDFLAGS = $(ERL_LDFLAGS)
else # FreeBSD
	CC ?= cc
	CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes
	DRV_LDFLAGS = $(ERL_LDFLAGS)
endif

#   {"DRV_LDFLAGS","-shared $ERL_LDFLAGS -lpthread"},
#   {"darwin", "DRV_LDFLAGS", "-bundle -flat_namespace -undefined suppress $ERL_LDFLAGS -lpthread"},
#   {"solaris", "ERL_LDFLAGS", "-lxnet -lssp -lnsl $ERL_LDFLAGS"},
#   {"DRV_CFLAGS","-Ic_src -Wall -O3 -fPIC $ERL_CFLAGS"},
#   {"CFLAGS", "$CFLAGS -Ic_src -Wall -O3"},
#   {"LDFLAGS", "$LDFLAGS -lpthread"}

CFLAGS += -fPIC -I $(ERTS_INCLUDE_DIR) -I $(ERL_INTERFACE_INCLUDE_DIR)

LDLIBS += -L $(ERL_INTERFACE_LIB_DIR) -lei -lpthread

# Verbosity.

c_verbose_0 = @echo " C     " $(?F);
c_verbose = $(c_verbose_$(V))

cpp_verbose_0 = @echo " CPP   " $(?F);
cpp_verbose = $(cpp_verbose_$(V))

link_verbose_0 = @echo " LD    " $(@F);
link_verbose = $(link_verbose_$(V))

SOURCES := $(shell find $(C_SRC_DIR) -type f \( -name "*.c" -o -name "*.C" -o -name "*.cc" -o -name "*.cpp" \))
OBJECTS = $(addsuffix .o, $(basename $(SOURCES)))

COMPILE_C = $(c_verbose) $(CC) $(CFLAGS) $(CPPFLAGS) -c
COMPILE_CPP = $(cpp_verbose) $(CXX) $(CXXFLAGS) $(CPPFLAGS) -c

all: $(C_SRC_NIF) $(C_SRC_PORT)

$(C_SRC_PORT): bcrypt_port.o bcrypt.o blowfish.o
	@mkdir -p $(BASEDIR)/priv/
	$(CC) $(CFLAGS) bcrypt_port.o bcrypt.o blowfish.o $(DRV_LDFLAGS) $(LDLIBS) -o ../priv/bcrypt

$(C_SRC_NIF): bcrypt_nif.o bcrypt.o blowfish.o
	@mkdir -p $(BASEDIR)/priv/
	$(link_verbose) $(CC) bcrypt_nif.o bcrypt.o blowfish.o $(LDFLAGS) -shared $(LDLIBS) -o $(C_SRC_NIF)

$(OBJECTS): bcrypt.h erl_blf.h

%.o: %.c
	$(COMPILE_C) $(OUTPUT_OPTION) $<

%.o: %.cc
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.C
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.cpp
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

clean:
	@rm -f $(C_SRC_NIF) $(C_SRC_PORT) $(OBJECTS)

.PHONY: security-test
security-test:
	@tmpdir=$$(mktemp -d) || exit 1; trap 'rm -rf "$$tmpdir"' EXIT; \
	$(CC) -std=c99 -D_DEFAULT_SOURCE -g -O1 -fsanitize=address,undefined \
	    -fno-omit-frame-pointer -fno-sanitize-recover=all -I. ../test/bcrypt_native_tests.c bcrypt.c blowfish.c \
	    -o "$$tmpdir/bcrypt_native_tests" && "$$tmpdir/bcrypt_native_tests"

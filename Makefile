ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc
include $(RTE_SDK)/mk/rte.vars.mk

LDLIBS = -lpcap -lpthread #-lm

# binary name
APP = tx_test

# all source are stored in SRCS-y
SRCS-y := main.c
CFLAGS += -O3 
CFLAGS += -DPORT_MASK=0x01

include $(RTE_SDK)/mk/rte.extapp.mk


cleandiy:
	rm -rf ./build *~

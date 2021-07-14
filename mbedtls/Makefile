
//TOOL_PREFIX?=arm-buildroot-linux-uclibcgnueabihf-

CC = $(TOOL_PREFIX)gcc
CXX = $(TOOL_PREFIX)g++
AR = $(TOOL_PREFIX)ar
RANLIB = $(TOOL_PREFIX)ranlib


TARGET = mbedtls_test tuya_test

LOCAL_SRC = crypto.c 

MBEDTLS_SRC = test_crypt.c

TUYA_SRC = test_tuya.c

INCLUDE += -I./ -I./include

OBJS += $(LOCAL_SRC:%.c=%.o)


CFLAGS = -O2 -Wall
LD_FLAGS += -lpthread
LD_FLAGS += -lrt -lmbedcrypto -lmbedtls -lmbedx509
LIBS_DIR += -L./lib

FLAGS += $(CFLAFS) $(LD_FLAGS) $(LIBS_DIR)

all:$(TARGET)
	@rm -f $(OBJS)

$(TARGET): $(OBJS)

mbedtls_test:test_crypt.o
	$(CC) -o $@ test_crypt.o $(OBJS) $(FLAGS)
	

tuya_test:test_tuya.o
	$(CC) -o $@ test_tuya.o $(OBJS) $(FLAGS) -lcjson -lcjson_utils

%.o:%.c
	$(CC) $(CFLAFS) -c $^ -o $@ $(INCLUDE)

clean:
	rm -f *.o $(TARGET)


.PHONY:all clean
.PHONY:$(TARGET)

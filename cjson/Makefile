
//TOOL_PREFIX?=arm-buildroot-linux-uclibcgnueabihf-

CC = $(TOOL_PREFIX)gcc
CXX = $(TOOL_PREFIX)g++
AR = $(TOOL_PREFIX)ar
RANLIB = $(TOOL_PREFIX)ranlib


TARGET = cjson_test

LOCAL_SRC = test_cjson.c 

INCLUDE += -I./ -I./include

OBJS += $(LOCAL_SRC:%.c=%.o)


CFLAGS = -O2 -Wall
LD_FLAGS = -lrt -lcjson -lcjson_utils
LIBS_DIR += -L./lib

FLAGS += $(CFLAFS) $(LD_FLAGS) $(LIBS_DIR)

all:$(TARGET)

$(TARGET):$(OBJS)
	$(CC) -o $@ $(OBJS) $(FLAGS)
	@rm -f $(OBJS)

%.o:%.c
	$(CC) $(CFLAFS) -c $^ -o $@ $(INCLUDE)

clean:
	rm -f *.o $(TARGET)


.PHONY:all clean
.PHONY:$(TARGET)

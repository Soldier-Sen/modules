TOOL_PREFIX?=

CC = $(TOOL_PREFIX)gcc
CXX = $(TOOL_PREFIX)g++
AR = $(TOOL_PREFIX)ar
RANLIB = $(TOOL_PREFIX)ranlib


TARGET = test_inifile

SOURCES += $(wildcard *.c)

INCLUDE = -I./

OBJS = $(SOURCES:%.c=%.o)

CFLAGS += -O2 -Wall

FLAGS += $(CFLAGS)

all: $(TARGET)


$(TARGET):$(OBJS)
	$(CC) -o $@ $(OBJS) $(FLAGS)
	@rm -f $(OBJS)

%.o:%.c
	$(CC) $(FLAGS) -c $^ -o $@ $(INCLUDE)

clean:
	rm -rf $(TARGET) $(OBJS)


.PHONY: all clean
.PHONY: $(TARGET)

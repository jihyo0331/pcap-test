# Makefile for packet_capture_structs

# 컴파일러 및 플래그
CC      := gcc
CFLAGS  := -Wall -Wextra -O2

# 링커 플래그
LIBS    := -lpcap

# 타겟 이름 및 소스 파일
TARGET  := pcap-test
SRCS    := pcap-test.c
OBJS    := $(SRCS:.c=.o)

# 기본 타겟: all
all: $(TARGET)

# 실행 파일 빌드
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# 오브젝트 파일 컴파일
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 청소
clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean

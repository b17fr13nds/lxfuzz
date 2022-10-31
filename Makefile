CFLAGS = -O3 -Wall -g -lpthread -static -lrt
CXX = g++ -std=c++2a
TARGET_CXX = g++ -std=c++2a

fuzzer: ./src/fuzzer.cpp
	$(TARGET_CXX) ./src/fuzzer.cpp ./src/syscall_generator.cpp ./src/syscall_executor.cpp ./src/sysdevproc_generator.cpp ./src/sysdevproc_executor.cpp ./src/socket_generator.cpp ./src/socket_executor.cpp ./src/hypercall.c $(CFLAGS)

manager: ./src/manager.cpp
	$(CXX) ./src/manager.cpp $(CFLAGS) -o manager -Wno-write-strings

qemu-setup:
	cd tools/ && \
	wget https://download.qemu.org/qemu-7.1.0.tar.xz && \
	tar xvJf qemu-7.1.0.tar.xz && \
	patch -s -p0 qemu-7.1.0/qemu-options.hx < qemu-options.diff && \
	patch -s -p0 qemu-7.1.0/softmmu/vl.c < vl.diff && \
	patch -s -p0 qemu-7.1.0/target/i386/helper.h < helper.diff && \
	patch -s -p0 qemu-7.1.0/target/i386/tcg/misc_helper.c < misc_helper.diff && \
	patch -s -p0 qemu-7.1.0/target/i386/tcg/translate.c < translate.diff && \
	cp instance.h qemu-7.1.0/include && \
	cd qemu-7.1.0/ && ./configure --target-list=x86_64-softmmu --extra-cflags="-lrt" --extra-ldflags="-lrt"

qemu: qemu-setup
	cd ./tools/qemu-7.1.0 && make

all: qemu fuzzer manager

clean: all
	rm fuzzer
	rm manager
	rm -r ./tools/qemu*

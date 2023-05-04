CFLAGS = -O3 -Wall -lpthread -static -lrt -Wno-unused-result -g -lstdc++_libbacktrace -Wdelete-incomplete
CXX = g++ -std=c++23
TARGET_CXX = g++ -std=c++23

fuzzer: ./src/fuzzer.cpp
	$(TARGET_CXX) ./src/fuzzer.cpp ./src/mutator.cpp ./src/syscall_generator.cpp ./src/syscall_executor.cpp ./src/sysdevproc_generator.cpp ./src/sysdevproc_executor.cpp ./src/socket_generator.cpp ./src/socket_executor.cpp ./src/hypercall.c -o ./fuzzer $(CFLAGS) -Wno-pointer-arith

fuzz_manager: ./src/fuzz_manager.cpp
	$(CXX) ./src/fuzz_manager.cpp $(CFLAGS) -o fuzz_manager -Wno-write-strings

reproducer:
	$(TARGET_CXX) ./src/reproducer.cpp ./src/syscall_executor.cpp ./src/sysdevproc_executor.cpp ./src/socket_executor.cpp -o ./reproducer $(CFLAGS)

repro_manager: ./src/repro_manager.cpp
	$(CXX) ./src/repro_manager.cpp $(CFLAGS) -o repro_manager -Wno-write-strings

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

all: qemu fuzzer fuzz_manager reproducer repro_manager
	mkdir kernel && mkdir kernel/data

clean: fuzzer fuzz_manager reproducer repro_manager
	rm fuzzer
	rm fuzz_manager
	rm reproducer
	rm repro_manager
	rm -r ./kernel/data
	rm -r ./tools/qemu-7.1.0*

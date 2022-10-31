# uxfuzz
uxfuzz is a black-box fuzzer used as a base for more os specific (unix based and mostly posix compatible) fuzzers. it is scalable because of qemu being used to emulate in a way to be able to freely choose the number of instances and their memory.

## setup and run

to build the whole project simply run 
```
make all
```
this will build a custom qemu emulator (x86-64) plus the fuzzer and manager

before running the manager, you have to configure how your kernel should be started. you can do that by editing the `cmdline.cfg` file (which already contains an example configuration)
you're completely free in how the kernel is to be running. make sure to have qemu exit on a kernel panic or similar. be careful to use the modified qemu emulator (located in `./tools/qemu-7.1.0/build/`)

if everything is set up you can start the manager
```
./manager <no of instances>
```
you can choose as much instances as your hardware can take

# uxfuzz
lxfuzz is a grey-box fuzzer used for linux. it is scalable because of qemu being used to emulate in a way to be able to freely choose the number of instances and their memory.

## setup and run

to build the whole project simply run 
```
make all
```
this will build a custom qemu emulator (x86-64) plus the fuzzer and manager.

before running the manager, you have to configure how your kernel should be started. you can do that by editing the `cmdline.cfg` file (which already contains an example configuration)

you're completely free in choosing how the kernel should be running. however make sure to have qemu exit on a kernel panic or similar. be careful to use the modified qemu emulator. (located in `./tools/qemu-7.1.0/build/`)

if everything is set up you can start the manager
```
./manager <no of instances>
```
you can choose as many instances as your hardware can take.

## logs and crashes

all fuzzing logs are saved in `./kernel/data/`. each instance got an own directory in which each core/thread got an own log file. the log format is readable by humans and programs can be recreated manually. there will be an automatic program recreator in the future. 

WARNING: the log folders and files grow extremely large after some time. make sure to keep track of them and keep removing old log data (i.e. by a shell script)

if the manager encounters a crash, the whole log directory of the corresponding instance is copied and saved.

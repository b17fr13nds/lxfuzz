# lxfuzz
lxfuzz is a grey-box kernel fuzzer used for linux. it is scalable because of qemu being used to emulate in a way to be able to freely choose the number of instances and their memory.

## setup and run

first, install build dependencies (example debian-based):
```
wget git make gcc g++ flex bc bison pkg-config ninja-build libssl-dev libglib2.0-dev bzip2 libpixman-1-dev libelf-dev libncurses5-dev
```

of course, you will need a properly built linux kernel. following options should be enabled
```
CONFIG_USER_NS=y
CONFIG_NET_DEV_REFCNT_TRACKER=y
CONFIG_NET_NS_REFCNT_TRACKER=y
CONFIG_KASAN=y
CONFIG_PANIC_ON_OOPS=y
CONFIG_BUG_ON_DATA_CORRUPTION=y
CONFIG_KCOV=y # make sure /sys/kernel/debug/kcov is rw for user
CONFIG_KCOV_INSTRUMENT_ALL=y

# CONFIG_RANDOMIZE_BASE is not set
```
enabling extra options that add more code to be fuzzed is always a good idea

now, to build the fuzzer simply run
```
make all
```
this will build a custom qemu emulator (x86-64) plus the fuzzer, a reproducer and manager programs for both of those.

before running the manager, you have to configure how QEMU should run your kernel. you can do that by editing the `cmdline.cfg` file (which already contains an example configuration)

you're completely free in choosing how the kernel should be running. however make sure to have qemu exit on a kernel panic or similar. be careful to use the modified qemu emulator. (located in `./tools/qemu-7.1.0/build/`)

if everything is set up you can start the fuzzing manager
```
./fuzz_manager -n <instances> [--timeout <inactive log timeout>] [--daemon] [--userns]
```
###### required arguments:
with `-n`, you can choose as many instances as your hardware can take.

###### optional arguments:
`--timeout` specifies in seconds, how long no log activity should be ignored, until the `fuzz_manager` checks for hangs or crashes.

use `--daemon` to run the fuzzer as a daemon in the background.

`--userns` tells the fuzzer to make use of user namespaces.

## logs and crashes

all fuzzing logs are saved in `./kernel/data/`. each instance got an own directory in which each core/thread got an own log file. 

*WARNING: the log folders and files grow extremely large after some time. make sure to keep track of them and keep removing old log data (i.e. by a shell script)*

if the manager encounters a crash, the whole log directory of the corresponding instance is copied and saved. the active logfiles get cleared whenever a crash or hang occurs

to reproduce crashes, copy the folder containing the crashes to the default startup working directory of the machine alongside with the `reproducer` binary. make sure the folder is named `crash/`. running `repro_manager` will try to reproduce the crash and will notify if successful. you can try to reduce the log data in `crash/` while still reproducing successfully, until you get to a point where you're able to understand the crash and create a POC.

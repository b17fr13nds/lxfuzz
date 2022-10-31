# uxfuzz
uxfuzz is a black-box fuzzer used as a base for more os specific (unix based) fuzzers. it is scalable because of qemu being used to emualte in a way to be able to freely choose the number of instances and their memory.

QEMU running parameters are set to be working with linux plus some linux specific files in `kernel/` as well as some things in `Makefile`. Highly experimental, will get cleaned up.

minimal Linux options:
```
CONFIG_USER_NS=y
CONFIG_NET_DEV_REFCNT_TRACKER=y
CONFIG_NET_NS_REFCNT_TRACKER=y
CONFIG_KASAN=y
CONFIG_PANIC_ON_OOPS=y
CONFIG_BUG_ON_DATA_CORRUPTION=y
CONFIG_KCOV=y
CONFIG_KCOV_INSTRUMENT_ALL=y

# CONFIG_RANDOMIZE_BASE is not set
```
 

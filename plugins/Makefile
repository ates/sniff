obj-m := http_plugin.o

EXTRA_CFLAGS += -I/usr/include
KBUILD_EXTRA_SYMBOLS := $(PWD)/Module.symvers

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

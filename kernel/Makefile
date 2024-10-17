# Makefile to build starter module

obj-m += fw.o
fw-objs := fw_proc_if.o fw_kernel.o fw_netfilter_if.o fw_netlink_logger_if.o 


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

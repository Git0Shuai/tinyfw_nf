KER_SRC_ROOT	=		/usr/src/linux-source-4.2

myntfw-objs := module_interface.o rule_list_manage.o filter_action.o
obj-m += myntfw.o

all : 
	make -C $(KER_SRC_ROOT) M=$(shell pwd) modules
	rm *.mod.c
	rm *.o
	rm *.symvers
	rm *.order

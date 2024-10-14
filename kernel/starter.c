#include "fw_proc_if.h"

MODULE_AUTHOR("Patsaoglou Pantelis");
MODULE_DESCRIPTION("My starter module for kernel dev");
MODULE_LICENSE("Dual MIT/GPL");

static fw_proc_if_st proc_handle;

static int __init starter_init(void)
{
	printk(KERN_INFO "%s: Starter module testing fw proc if source\n", KBUILD_MODNAME);
	
	if (init_fw_proc_if(&proc_handle) == FW_PROC_IF_SUCCESS)
	{
		printk(KERN_INFO "%s: Successfull init_fw_proc_if \n", KBUILD_MODNAME);
		return 0;
	}else
	{
		printk(KERN_INFO "%s: init_fw_proc_if failed \n", KBUILD_MODNAME);
		return -1;
	}
}

static void __exit starter_exit(void)
{
	deinit_fw_proc_if(&proc_handle);
	printk(KERN_INFO "%s: Starter module exit\n", KBUILD_MODNAME);
}

module_init(starter_init);
module_exit(starter_exit);
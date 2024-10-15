#include "fw_kernel.h"

MODULE_AUTHOR("Patsaoglou Pantelis");
MODULE_DESCRIPTION("Kernel module for netfilter hooks inmplemation and procfs pseudofile registration");
MODULE_LICENSE("Dual MIT/GPL");

static fw_proc_if_st proc_handle;
static fw_netfilter_if netfilter_handle;

// static int __init fw_kernel_init(void)
// {
// 	printk(KERN_INFO "%s: Starting Firewall kernel\n", KBUILD_MODNAME);
	
// 	if (init_fw_proc_if(&proc_handle, NULL) == FW_PROC_IF_SUCCESS)
// 	{
// 		printk(KERN_INFO "%s: Successfull init_fw_proc_if \n", KBUILD_MODNAME);
// 		return 0;
// 	}else
// 	{
// 		printk(KERN_INFO "%s: init_fw_proc_if failed \n", KBUILD_MODNAME);
// 		return -1;
// 	}
// }

// static void __exit fw_kernel_exit(void)
// {
// 	deinit_fw_proc_if(&proc_handle);
// 	printk(KERN_INFO "%s: Starter module exit\n", KBUILD_MODNAME);
// }


static int __init fw_kernel_init(void)
{
	printk(KERN_INFO "%s: Starting Firewall kernel\n", KBUILD_MODNAME);
	
	if (init_fw_netfilter_if(&netfilter_handle) == FW_NETFILTER_IF_SUCCESS)
	{
		add_ipv4_entry(0x01010101);
		printk(KERN_INFO "%s: Successfull init_fw_netfilter_if \n", KBUILD_MODNAME);
		return 0;
	}else
	{
		printk(KERN_INFO "%s: init_fw_netfilter_if failed \n", KBUILD_MODNAME);
		return -1;
	}
}

static void __exit fw_kernel_exit(void)
{
	deinit_fw_netfilter_if(&netfilter_handle);
	printk(KERN_INFO "%s: Starter module exit\n", KBUILD_MODNAME);
}

module_init(fw_kernel_init);
module_exit(fw_kernel_exit);
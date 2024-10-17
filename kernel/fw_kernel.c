#include "fw_kernel.h"

MODULE_AUTHOR("Patsaoglou Pantelis");
MODULE_DESCRIPTION("Kernel module for netfilter hooks implementation and procfs pseudofile registration");
MODULE_LICENSE("Dual MIT/GPL");

static fw_proc_if_st proc_handle;
static fw_netfilter_if netfilter_handle;
static fw_netlink_logger_if_st netlink_handle;

static int __init fw_kernel_init(void)
{
	printk(KERN_INFO "%s: Starting Firewall kernel...", KBUILD_MODNAME);
	
	if (init_fw_netlink_if(&netlink_handle) == FW_LOG_NETLINK_SUCCESS)
	{
		printk(KERN_INFO "%s: Successfull Firewall netlink init", KBUILD_MODNAME);
	}else
	{
		printk(KERN_INFO "%s: Firewall netlink init failed", KBUILD_MODNAME);
		return -1;
	}

	if (init_fw_netfilter_if(&netfilter_handle, &netlink_handle) == FW_NETFILTER_IF_SUCCESS)
	{
		add_ipv4_entry(0x01010101);
		printk(KERN_INFO "%s: Successfull Firewall netfilter init ", KBUILD_MODNAME);
	}else
	{
		printk(KERN_INFO "%s: Firewall netfilter init failed \n", KBUILD_MODNAME);
		return -1;
	}


	if (init_fw_proc_if(&proc_handle, &netfilter_handle) == FW_PROC_IF_SUCCESS)
	{
		printk(KERN_INFO "%s: Successfull Firewall proc init \n", KBUILD_MODNAME);
		
	}else
	{
		printk(KERN_INFO "%s: Firewall proc init failed \n", KBUILD_MODNAME);
		return -1;
	}

	return 0;
}

static void __exit fw_kernel_exit(void)
{
	deinit_fw_proc_if(&proc_handle);
	deinit_fw_netfilter_if(&netfilter_handle);
	deinit_fw_netlink_if(&netlink_handle);
	printk(KERN_INFO "%s: End Firewall kernel\n", KBUILD_MODNAME);
}

module_init(fw_kernel_init);
module_exit(fw_kernel_exit);
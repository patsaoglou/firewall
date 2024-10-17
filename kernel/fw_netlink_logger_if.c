#include "fw_netlink_logger_if.h"

// global pointer to netlink handle so it can be seen by the callback
static fw_netlink_logger_if_st *fw_netlink_if_handle_gb;

fw_netlink_logger_if_status init_fw_netlink_if(fw_netlink_logger_if_st *fw_netlink_if_handle)
{

     struct netlink_kernel_cfg cfg = {
        .input = receive_fw_deamon_pid,
    };

    fw_netlink_if_handle_gb = fw_netlink_if_handle;

    fw_netlink_if_handle->log_netlink = netlink_kernel_create(&init_net, FW_LOG_NETLINK, &cfg);

    // this is to indicate that netlink has not received the fw deamon pid
    fw_netlink_if_handle->fw_deamon_pid = -1;

    if (fw_netlink_if_handle->log_netlink < 0)
    {
        printk(KERN_INFO "%s: Failed to create netlink", KBUILD_MODNAME);

        return FW_LOG_NETLINK_FAIL;
    }

    return FW_LOG_NETLINK_SUCCESS;

}

void deinit_fw_netlink_if(fw_netlink_logger_if_st *fw_netlink_if_handle)
{
    if (fw_netlink_if_handle->log_netlink != NULL)
    {
        printk(KERN_INFO "%s: Deinit Firewall netlink", KBUILD_MODNAME);

        netlink_kernel_release(fw_netlink_if_handle->log_netlink);
    }
}

void receive_fw_deamon_pid(struct sk_buff *skb)
{
    struct nlmsghdr *msg_header; 
    
    if (fw_netlink_if_handle_gb->fw_deamon_pid == -1)
    {
        // mask message data to get header
        msg_header = (struct nlmsghdr*)skb->data;

        printk(KERN_INFO "%s: Firewall deamon PID: %d", KBUILD_MODNAME, msg_header->nlmsg_pid);

        fw_netlink_if_handle_gb->fw_deamon_pid = msg_header->nlmsg_pid;
    }
    else
    {
        printk(KERN_INFO "%s: Firewall deamon PID is already set", KBUILD_MODNAME);
    }
    
}

fw_netlink_logger_if_status send_log_entry_netlink(fw_netlink_logger_if_st *fw_netlink_if_handle, char *log_entry, spinlock_t *log_spinlock)
{
    unsigned long flags;
    struct sk_buff *payload_log_entry;
    struct nlmsghdr *netlink_entry;
    int log_entry_size;
    int netlink_entry_status;

    if (fw_netlink_if_handle->fw_deamon_pid == -1)
    {
        printk(KERN_INFO "%s: Deamon has not establised a netlink.", KBUILD_MODNAME);
        return FW_LOG_NETLINK_MES_FAIL;
    }

    log_entry_size = strlen(log_entry);

    payload_log_entry = nlmsg_new(log_entry_size, 0);

    if (payload_log_entry == NULL)
    {
        printk(KERN_INFO "%s: Failed to create a new netlink log entry", KBUILD_MODNAME);
        return FW_LOG_NETLINK_MES_FAIL;
    }

    netlink_entry = nlmsg_put(payload_log_entry, 0, 0, NLMSG_DONE, log_entry_size, 0);
    
    NETLINK_CB(payload_log_entry).dst_group = 0;
    strncpy(nlmsg_data(netlink_entry), log_entry, log_entry_size);

    // deep locking when netlink queue is modified
    spin_lock_irqsave(log_spinlock, flags);

    netlink_entry_status = nlmsg_unicast(fw_netlink_if_handle_gb->log_netlink, payload_log_entry, fw_netlink_if_handle_gb->fw_deamon_pid);     
    
    spin_unlock_irqrestore(log_spinlock, flags);

    if (netlink_entry_status < 0)
    {
        // propably netlink lost from the user space deamon so make pid -1 again 
        printk(KERN_INFO "%s: Failed to add netlink entry to netlink queue", KBUILD_MODNAME);
        
        fw_netlink_if_handle->fw_deamon_pid = -1;
        return FW_LOG_NETLINK_MES_FAIL;
    }

    return FW_LOG_NETLINK_MES_SUCCESS;
}
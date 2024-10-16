#include "fw_netfilter_if.h"

DEFINE_HASHTABLE(ip_entries, HASHTABLE_BUCKETS);

spinlock_t log_spinlock;
fw_netfilter_if *fw_netfilter_if_handle_gb;

fw_netfilter_if_status init_fw_netfilter_if(fw_netfilter_if *fw_netfilter_if_handle)
{
    printk(KERN_INFO "%s: Initializing init_fw_netfilter_if...", KBUILD_MODNAME);
    
    // set global handler pointer so it can be used in the hook callback
    fw_netfilter_if_handle_gb = fw_netfilter_if_handle;


    fw_netfilter_if_handle->fw_netfilter_hook = (struct nf_hook_ops *) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

    if (fw_netfilter_if_handle->fw_netfilter_hook){
        printk(KERN_INFO "%s: Registering netfilter hooks structure...", KBUILD_MODNAME);
        
        // registering fw_netfilter_hook_cb callback routine when hook is triggered
        fw_netfilter_if_handle->fw_netfilter_hook->hook = (nf_hookfn *) fw_netfilter_hook_cb;

        // hook callback just when packet arrives at netif
        fw_netfilter_if_handle->fw_netfilter_hook->hooknum = NF_INET_PRE_ROUTING;
        fw_netfilter_if_handle->fw_netfilter_hook->pf =NFPROTO_IPV4;
        fw_netfilter_if_handle->fw_netfilter_hook->priority = NF_IP_PRI_FIRST;
        
        // init_net is the main net structure used for networking interfacing within the kernel 
        if (nf_register_net_hook(&init_net, fw_netfilter_if_handle->fw_netfilter_hook) == 0)
        {
            printk(KERN_INFO "%s: Registered netfilter hook structure successfully", KBUILD_MODNAME);
            
            return FW_NETFILTER_IF_SUCCESS;
        }
        else
        {
            printk(KERN_INFO "%s: Hook registration failed", KBUILD_MODNAME);
            deinit_fw_netfilter_if(fw_netfilter_if_handle);
            
            return FW_NETFILTER_IF_FAIL;
        }        
    }
    else
    {
        printk(KERN_INFO "%s: kcalloc in init_fw_netfilter_if failed", KBUILD_MODNAME);
        return FW_NETFILTER_IF_FAIL;
    }

    return FW_NETFILTER_IF_SUCCESS;
}

void deinit_fw_netfilter_if(fw_netfilter_if *fw_netfilter_if_handle){
    
    if (fw_netfilter_if_handle->fw_netfilter_hook != NULL)
    {
        printk(KERN_INFO "%s: Unregistering netfilter hooks structure", KBUILD_MODNAME);
        
        // unregistering hook callback from netif
        nf_unregister_net_hook(&init_net, fw_netfilter_if_handle->fw_netfilter_hook);
        kfree(fw_netfilter_if_handle->fw_netfilter_hook);
    }
}


unsigned int fw_netfilter_hook_cb(void *priv,struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    long irq_flags;

    if (skb == NULL)
    {
        return NF_ACCEPT;
    }

    // to get ip header from initial packet
    ip_header = ip_hdr(skb);

    if (ip_header)
    {
        if (lookup_ipv4_entry(ip_header->saddr) == IP_TABLE_ENTRY_FOUND)
        {
            printk(KERN_INFO "%s: Packet from src: %pI4 is blocked. Dropping packet", KBUILD_MODNAME, &ip_header->saddr);
           
            //  synchronization of the logbuff is needed: hook_callback is the producer, proc read is the consumer of logbuff
            //  hook callback happened in an interrupt context so we need irq locking 
            spin_lock_irqsave(&log_spinlock, irq_flags);
            
            add_log_enty_to_log_buff(ip_header);

            spin_unlock_irqrestore(&log_spinlock, irq_flags);

            return NF_DROP;
        }
        
        printk(KERN_INFO "%s: Packet from src: %pI4 is not blocked. Accept packet", KBUILD_MODNAME, &ip_header->saddr);

        return NF_ACCEPT;
    }

    return NF_ACCEPT;
}

// these function are going to be called from proc mng callbacks and change ip entries table
fw_netfilter_if_ip_table_st lookup_ipv4_entry(__be32 ipv4_addr)
{
    ip_hashtable_entry *ip_entry;

    if (ipv4_addr == 0)
    {
        printk(KERN_INFO "%s: lookup_ipv4_entry got 0 ipv4_addr", KBUILD_MODNAME);
        
        return IP_TABLE_ENTRY_NOT_FOUND;
    }

    hash_for_each_possible_rcu(ip_entries, ip_entry, hash_node, ipv4_addr)
    {
        if (ip_entry->ipv4_entry == ipv4_addr)
        {
            return IP_TABLE_ENTRY_FOUND;
        }
    }

    return IP_TABLE_ENTRY_NOT_FOUND;
}

fw_netfilter_if_ip_table_st add_ipv4_entry(__be32 ipv4_addr)
{
    ip_hashtable_entry *ip_entry;

    hash_for_each_possible_rcu(ip_entries, ip_entry, hash_node, ipv4_addr)
    {
        if (ip_entry->ipv4_entry == ipv4_addr)
        {   
            printk(KERN_INFO "%s: add_ipv4_entry %pI4 is already added to hash", KBUILD_MODNAME, &ipv4_addr);

            return IP_TABLE_ENTRY_FOUND;
        }
    }

    // reserve kernel memory for new ip entry
    ip_entry = kcalloc(1, sizeof(ip_hashtable_entry), GFP_KERNEL);

    ip_entry->ipv4_entry = ipv4_addr;
    hash_add_rcu(ip_entries, &ip_entry->hash_node, ipv4_addr);

    printk(KERN_INFO "%s: add_ipv4_entry %pI4 added to hash", KBUILD_MODNAME, &ipv4_addr);
    
    return IP_TABLE_ENTRY_ADDED;
}

fw_netfilter_if_ip_table_st remove_ipv4_entry(__be32 ipv4_addr)
{
    ip_hashtable_entry *ip_entry;

    hash_for_each_possible_rcu(ip_entries, ip_entry, hash_node, ipv4_addr)
    {
        if (ip_entry->ipv4_entry == ipv4_addr)
        {   
            hash_del_rcu(&ip_entry->hash_node);

            // free up kernel memory of the removed hash node
            kfree(ip_entry);

            printk(KERN_INFO "%s: IP %pI4 removed from hash", KBUILD_MODNAME, &ipv4_addr);

            return IP_TABLE_ENTRY_REMOVED;
        }
    }

    printk(KERN_INFO "%s: IP %pI4 not found in hash to be removed", KBUILD_MODNAME, &ipv4_addr);

    return IP_TABLE_ENTRY_NOT_FOUND;
}

void add_log_enty_to_log_buff(struct iphdr *ip_header)
{   
    // got from: https://stackoverflow.com/questions/5077192/how-to-get-current-hour-time-of-day-in-linux-kernel-space
    struct timespec curr_tm;
    getnstimeofday(&curr_tm);


    snprintf(fw_netfilter_if_handle_gb->log_dump, FW_NETFILTER_LOG_BUFF_SIZE, "%pI4, %s, %.2lu:%.2lu:%.2lu:%.6lu, DROP\n", &ip_header->saddr,
                 get_protocal_str(ip_header->protocol),   (curr_tm.tv_sec / 3600) % (24),
                   (curr_tm.tv_sec / 60) % (60),
                   curr_tm.tv_sec % 60,
                   curr_tm.tv_nsec / 1000);
    printk("%s", fw_netfilter_if_handle_gb->log_dump);

}

char *get_protocal_str(__u8 protocol)
{
    switch (protocol)
    {
        case IPPROTO_ICMP:
            return "ICMP";
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_IPV6:  
            return "IPv6";
        default:
            return "Unknown";
    }
}



// fw_netfilter_if_ip_table_st add_ipv4_entries(__be32 ipv4_addr[]);
// fw_netfilter_if_ip_table_st remove_ipv4_entries(__be32 ipv4_addr[]);

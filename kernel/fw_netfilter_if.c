#include "fw_netfilter_if.h"

fw_netfilter_if_status init_fw_netfilter_if(fw_netfilter_if *fw_netfilter_if_handle)
{
    printk(KERN_INFO "%s: Initializing init_fw_netfilter_if...", KBUILD_MODNAME);

    fw_netfilter_if_handle->fw_netfilter_hook = (struct nf_hook_ops *) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

    if (fw_netfilter_if_handle->fw_netfilter_hook){
        printk(KERN_INFO "%s: Registering netfilter hooks structure...", KBUILD_MODNAME);
        
        // registering fw_netfilter_hook_cb callback routine when hook is triggered
        fw_netfilter_if_handle->fw_netfilter_hook->hook = (nf_hookfn *) fw_netfilter_hook_cb;
        fw_netfilter_if_handle->fw_netfilter_hook->hooknum = NF_INET_PRE_ROUTING;
        fw_netfilter_if_handle->fw_netfilter_hook->pf =NFPROTO_IPV4;
        fw_netfilter_if_handle->fw_netfilter_hook->priority = NF_IP_PRI_FIRST;
        
        // init_net is the main net structure used for networking interfacing within the kernel 
        if (nf_register_net_hook(&init_net, fw_netfilter_if_handle->fw_netfilter_hook) == 0)
        {
            printk(KERN_INFO "%s: Registered netfilter hook structure successfully\n", KBUILD_MODNAME);
            
            return FW_NETFILTER_IF_SUCCESS;
        }
        else
        {
            printk(KERN_INFO "%s: Hook registration failed\n", KBUILD_MODNAME);
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

    if (skb == NULL)
    {
        return NF_ACCEPT;
    }

    // to get ip header from initial packet
    ip_header = ip_hdr(skb);

    if (ip_header)
    {
        printk(KERN_INFO "%s: received packet from source: %pI4", KBUILD_MODNAME, &ip_header->saddr);

        return NF_ACCEPT;
    }

    return NF_ACCEPT;
}

// these function are going to be called from proc mng callbacks and change ip entries table

// fw_netfilter_if_ip_table_st lookup_ipv4_entry(__be32 *ipv4_addr);

// fw_netfilter_if_ip_table_st add_ipv4_entry(__be32 *ipv4_addr);
// fw_netfilter_if_ip_table_st remove_ipv4_entry(__be32 *ipv4_addr);
// fw_netfilter_if_ip_table_st add_ipv4_entries(__be32 ipv4_addr[]);
// fw_netfilter_if_ip_table_st remove_ipv4_entries(__be32 ipv4_addr[]);

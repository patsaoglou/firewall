#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/hashtable.h>
#include <linux/time.h>

#define FW_NETFILTER_LOG_BUFF_SIZE 128
#define HASHTABLE_BUCKETS 10 

typedef struct 
{   
    // storing ip as 32bit key
    __be32 ipv4_entry;

    struct hlist_node hash_node;
}ip_hashtable_entry;


typedef struct 
{
    // this buff is used by fw_proc_if to dump to /proc/my_fw/logv
    char log_dump[FW_NETFILTER_LOG_BUFF_SIZE];
    
    struct nf_hook_ops *fw_netfilter_hook;
}fw_netfilter_if;

typedef enum
{
    FW_NETFILTER_IF_SUCCESS,
    FW_NETFILTER_IF_FAIL
}fw_netfilter_if_status;

typedef enum
{
    IP_TABLE_ENTRY_FOUND,
    IP_TABLE_ENTRY_NOT_FOUND,
    IP_TABLE_ENTRY_ADDED,
    IP_TABLE_ENTRY_REMOVED,
    IP_TABLE_FAIL
}fw_netfilter_if_ip_table_st;

extern spinlock_t log_spinlock; 
extern fw_netfilter_if *fw_netfilter_if_handle_gb;

fw_netfilter_if_status init_fw_netfilter_if(fw_netfilter_if *fw_netfilter_if_handle);
void deinit_fw_netfilter_if(fw_netfilter_if *fw_netfilter_if_handle);

unsigned int fw_netfilter_hook_cb(void *priv,struct sk_buff *skb, const struct nf_hook_state *state);

fw_netfilter_if_ip_table_st lookup_ipv4_entry(__be32 ipv4_addr);

fw_netfilter_if_ip_table_st add_ipv4_entry(__be32 ipv4_addr);
fw_netfilter_if_ip_table_st remove_ipv4_entry(__be32 ipv4_addr);


void add_log_enty_to_log_buff(struct iphdr *ip_header);
char *get_protocal_str(__u8 protocol);

// fw_netfilter_if_ip_table_st add_ipv4_entries(__be32 ipv4_addr[]);
// fw_netfilter_if_ip_table_st remove_ipv4_entries(__be32 ipv4_addr[]);



